"""Reliability of the deciding layer (the facts-only judgement). docs/RECHECK.md.

1. The classifier sees every re-check fact; a model trained on another list is refused.
2. "benign" needs confidence; a low-probability benign becomes unsure.
3. Two judges: the model and the rule scorecard must both say benign.
4. Training on real labelled data (JSON lines) works and reports the false-benign rate.
5. Analyst decisions become labelled examples; the drift signal tracks agreement.
6. Threat-intel quorum: a link is clean only when enough sources say so.
7. Organisation-wide first-seen facts negate sender history.
8. Relationship facts (someone here replied) count as costly support.
9. ARC and BIMI come only from the trusted Authentication-Results header.
10. The re-check bench: the full T1 judgement lets no affordable attack through.
"""

from __future__ import annotations

import dataclasses
import json
import subprocess
import sys

import pytest

from conftest import requires_opa

from eval.generate_alerts import generate
from trustgate.evidence_floor import t1_evidence
from trustgate.ingest.enrich import EnrichmentReport, ThreatIntel, url_verdict
from trustgate.ingest.parsers.email import auth_from_headers
from trustgate.models import Alert, GateDecision, ProposedAction, TypedFacts
from trustgate.policy_client import load_pack
from trustgate.recheck import (FEATURE_ORDER, EnsembleRecheck, RecheckResult, XGBoostRecheck,
                               facts_only_recheck, vectorise)
from trustgate.scorecard import score
from trustgate.store import ActionRecord

FLOOR = load_pack("packs/soc.rego").floor["t1_evidence"]
KNOWN = dict(spf_pass=True, dkim_pass=True, dmarc_pass=True, url_reputation="clean", sender_prior_messages=180,
             org_replied_to_sender=True, reply_to_mismatch=False, sender_first_link=False,
             sender_first_attachment=False, sender_new_sending_ip=False, org_url_domain_first_seen=False)
OWNED = dict(spf_pass=True, dkim_pass=True, dmarc_pass=True, sender_domain_age_days=900, url_reputation="clean",
             sender_prior_messages=0)


# --- 1. every fact, and no stale models ----------------------------------------------------

def test_model_sees_every_recheck_fact():
    view = TypedFacts().recheck_view()
    assert list(FEATURE_ORDER) == list(view)
    for fact in ("sender_prior_messages", "reply_to_mismatch", "sender_new_sending_ip", "attachment_has_qr",
                 "enrichment_failed", "org_replied_to_sender", "asset_criticality"):
        assert fact in FEATURE_ORDER
    row = vectorise(TypedFacts(asset_criticality="critical", sender_prior_messages=4))
    assert len(row) == len(FEATURE_ORDER)
    assert row[FEATURE_ORDER.index("asset_criticality")] == 3.0


def test_model_trained_on_another_fact_list_is_refused(tmp_path, settings):
    xgb = pytest.importorskip("xgboost")
    old = ["spf_pass", "dkim_pass", "dmarc_pass"]
    booster = xgb.train({"objective": "multi:softprob", "num_class": 3},
                        xgb.DMatrix([[1, 1, 1], [0, 0, 0]], label=[0, 2], feature_names=old), num_boost_round=2)
    path = tmp_path / "old.json"
    booster.save_model(str(path))
    with pytest.raises(Exception, match="different fact list"):
        XGBoostRecheck(dataclasses.replace(settings, xgb_model_path=str(path)))


# --- 2. confidence ------------------------------------------------------------------------

class _Booster:
    def __init__(self, probs):
        self.probs = probs

    def predict(self, _matrix):
        return [self.probs]


class _Xgb:
    @staticmethod
    def DMatrix(rows, feature_names):  # noqa: N802 - mirrors xgboost.DMatrix
        return rows


def _xgb_recheck(probs, min_confidence=0.9):
    r = XGBoostRecheck.__new__(XGBoostRecheck)
    r._booster, r._xgb, r.min_confidence = _Booster(probs), _Xgb, min_confidence
    return r


def test_low_confidence_benign_becomes_unsure():
    result = _xgb_recheck([0.62, 0.20, 0.18])(TypedFacts())
    assert result.verdict == "unsure"
    assert result.confidence == 0.62
    assert "below 0.90" in result.reasons[0]


def test_confident_benign_and_malicious_stand():
    assert _xgb_recheck([0.95, 0.03, 0.02])(TypedFacts()).verdict == "benign"
    assert _xgb_recheck([0.10, 0.20, 0.70])(TypedFacts()).verdict == "malicious"


# --- 3. two judges ------------------------------------------------------------------------

def _model(verdict):
    fn = lambda facts: RecheckResult(verdict=verdict, backend="stub")  # noqa: E731
    fn.backend = "stub"
    return fn


def test_ensemble_needs_both_judges_for_benign():
    benign_facts = TypedFacts(**KNOWN)
    assert score(benign_facts).verdict == "benign"
    assert EnsembleRecheck(_model("benign"))(benign_facts).verdict == "benign"
    # The model is fooled, the scorecard is not: an attacker-owned domain with no history.
    owned = EnsembleRecheck(_model("benign"))(TypedFacts(**OWNED))
    assert owned.verdict == "unsure"
    assert any("no fact positively supports benign" in r for r in owned.reasons)
    # Either judge saying malicious wins.
    assert EnsembleRecheck(_model("malicious"))(benign_facts).verdict == "malicious"
    assert EnsembleRecheck(_model("benign"))(TypedFacts(**{**KNOWN, "dmarc_pass": False})).verdict == "malicious"


def test_configured_recheck_runs_with_the_scorecard(settings, tmp_path):
    pytest.importorskip("xgboost")
    path = tmp_path / "m.json"
    subprocess.run([sys.executable, "scripts/train_recheck.py", "--out", str(path), "--synthetic", "400"],
                   check=True, capture_output=True)
    on = facts_only_recheck(dataclasses.replace(settings, recheck_backend="xgboost", xgb_model_path=str(path)))
    off = facts_only_recheck(dataclasses.replace(settings, recheck_backend="xgboost", xgb_model_path=str(path),
                                                 recheck_scorecard=False))
    assert isinstance(on, EnsembleRecheck) and on.backend == "xgboost+scorecard"
    assert isinstance(off, XGBoostRecheck)
    meta = json.loads((tmp_path / "m.meta.json").read_text())
    assert meta["features"] == list(FEATURE_ORDER) and meta["synthetic_only"] is True
    assert meta["holdout"]["false_benign_rate"] is not None


def test_scorecard_treats_cheap_facts_as_cheap():
    assert score(TypedFacts(**OWNED)).verdict == "unsure"                       # DMARC pass alone is not enough
    assert score(TypedFacts(**{**KNOWN, "dmarc_pass": None})).verdict == "unsure"  # email with unknown DMARC
    assert score(TypedFacts(sandbox_verdict="not_run", process_signed=True)).verdict == "unsure"
    assert score(TypedFacts(sandbox_verdict="clean", process_signed=True)).verdict == "benign"
    assert score(TypedFacts(**{**KNOWN, "sender_first_link": True})).verdict == "unsure"


@requires_opa
def test_judges_reasons_reach_the_analyst_not_the_agent(settings, store, opa_engine):
    from trustgate.gate import Gate
    from trustgate.ratelimit import MemoryRateLimiter

    def recheck(_facts):
        return RecheckResult(verdict="unsure", reasons=("scorecard: Reply-To is on another domain",))

    gate = Gate("packs/soc.rego", recheck=recheck, settings=settings, store=store, policy_engine=opa_engine,
                limiter=MemoryRateLimiter())
    store.put_alert(Alert(alert_id="R-1", source="email", severity="low", facts=TypedFacts(**KNOWN), evidence=[]))
    d = gate.decide(ProposedAction(alert_id="R-1", verdict="benign", tool="close_alert", args={"reason": "x"},
                                   cited_evidence=["facts.dmarc_pass"]))
    assert d.decision == "escalate"
    assert "re-check: scorecard: Reply-To is on another domain" in d.reasons


# --- 4. training on real data -------------------------------------------------------------

def test_training_on_labelled_data_file(tmp_path):
    pytest.importorskip("xgboost")
    rows = []
    for i in range(60):
        rows.append({"facts": {**KNOWN, "sender_prior_messages": 10 + i}, "label": "benign"})
        rows.append({"facts": {**OWNED, "org_url_domain_first_seen": True}, "label": "malicious"})
    rows.append({"facts": {"dmarc_pass": None}, "label": "unsure"})
    data = tmp_path / "tickets.jsonl"
    data.write_text("\n".join(json.dumps(r) for r in rows))
    out = tmp_path / "real.json"
    proc = subprocess.run([sys.executable, "scripts/train_recheck.py", "--data", str(data), "--out", str(out)],
                          capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    meta = json.loads((tmp_path / "real.meta.json").read_text())
    assert meta["synthetic_only"] is False and "synthetic" not in meta["sources"]
    assert meta["holdout"]["false_benign"] == 0


def test_training_rejects_bad_labels(tmp_path):
    data = tmp_path / "bad.jsonl"
    data.write_text(json.dumps({"facts": {}, "label": "probably fine"}))
    proc = subprocess.run([sys.executable, "scripts/train_recheck.py", "--data", str(data),
                           "--out", str(tmp_path / "x.json")], capture_output=True, text=True)
    assert proc.returncode != 0 and "label must be" in (proc.stdout + proc.stderr)


def test_training_mode_adds_hard_negatives_and_leaves_eval_data_alone():
    assert generate(8) == generate(8)
    assert not any(a["alert_id"].startswith("H-") for a in generate(200))
    training = generate(400, training=True)
    scenarios = {a["ground_truth"]["scenario"] for a in training}
    assert {"owned_domain", "compromised_account"} <= scenarios
    assert any(a["ground_truth"]["label"] == "unsure" for a in training)


# --- 5. analyst feedback and drift --------------------------------------------------------

def test_feedback_examples_and_agreement(store):
    def alert(aid):
        a = Alert(alert_id=aid, source="email", severity="low", facts=TypedFacts(**KNOWN), evidence=[])
        store.put_alert(a)
        return a

    def escalation(aid, status, recheck, canary=False):
        esc = store.open_escalation(ProposedAction(alert_id=aid, verdict="benign", tool="close_alert",
                                                   args={"reason": aid}),
                                    GateDecision(decision="escalate", tier=1, reasons=["x"], recheck_verdict=recheck),
                                    canary=canary)
        store.close_escalation(esc.id, status=status, analyst="ana", reason="r")

    for aid in ("F-1", "F-2", "F-3", "F-4"):
        alert(aid)
    escalation("F-1", "approved", "benign")      # agreed: benign
    escalation("F-2", "rejected", "malicious")   # agreed: not benign
    escalation("F-3", "approved", "unsure")      # disagreed
    escalation("F-4", "approved", "benign", canary=True)  # planted: ignored
    store.record_action(ActionRecord(alert_id="F-1", tool="close_alert", tier=1, status="reverted"))

    labels = {a.alert_id: label for a, label in store.feedback_examples()}
    assert labels == {"F-2": "malicious", "F-3": "benign", "F-1": "malicious"}  # the revert overrides the approval
    drift = store.recheck_agreement()
    assert drift == {"resolved": 3, "agreement_rate": round(2 / 3, 4)}


# --- 6. threat-intel quorum ---------------------------------------------------------------

def test_url_verdict_quorum_and_disagreement():
    assert url_verdict(["clean", "unknown"], quorum=1) == "clean"
    assert url_verdict(["clean", "unknown"], quorum=2) == "unknown"
    assert url_verdict(["clean", "clean"], quorum=2) == "clean"
    assert url_verdict(["clean", "suspicious"], quorum=1) == "suspicious"  # sources disagree: worst wins
    assert url_verdict(["unknown", "unknown"], quorum=1) == "unknown"


def test_a_link_nobody_could_vouch_for_outweighs_a_clean_one(settings):
    class FakeCache(dict):
        def set(self, key, value, expire=None):
            self[key] = value

    ti = ThreatIntel(dataclasses.replace(settings, virustotal_api_key="k", urlhaus_auth_key="k"), cache=FakeCache())
    ti.virustotal_url = lambda url: "clean" if "good" in url else "unknown"
    ti.urlhaus = lambda url: "unknown"
    report: EnrichmentReport = ti.enrich(ips=[], urls=["http://good.example/a", "http://other.example/b"],
                                         file_hashes=[], sender_domain="")
    assert report.url_reputation == "unknown"


# --- 7/8. organisation history in the evidence floor --------------------------------------

def test_someone_replying_counts_as_costly_support():
    facts = TypedFacts(**{**KNOWN, "sender_prior_messages": 0})  # no sender history, but staff replied
    ev = t1_evidence(facts, "email", FLOOR, ["facts.dmarc_pass"])
    assert ev.costly_ok and not ev.reasons()


def test_an_unseen_link_domain_cancels_all_history():
    facts = TypedFacts(**{**KNOWN, "org_url_domain_first_seen": True})
    ev = t1_evidence(facts, "email", FLOOR, ["facts.dmarc_pass"])
    assert not ev.costly_ok
    assert any("behaving unusually" in r and "org_url_domain_first_seen" in r for r in ev.reasons())


# --- 9. ARC and BIMI only from the trusted header -----------------------------------------

def test_arc_and_bimi_come_only_from_the_trusted_header():
    trusted = "mx.corp.example; spf=pass; dkim=pass; dmarc=pass; arc=pass; bimi=pass"
    facts, _ = auth_from_headers([trusted], "mx.corp.example")
    assert facts.arc_pass is True and facts.bimi_pass is True
    spoofed = "mx.corp.example; arc=pass; bimi=pass"
    facts, flagged = auth_from_headers(["mx.other.example; arc=fail", spoofed], "mx.corp.example")
    assert facts.arc_pass is None and facts.bimi_pass is None and flagged == [spoofed]


# --- 10. the bench --------------------------------------------------------------------------

def test_full_t1_judgement_lets_no_affordable_attack_through(settings, tmp_path):
    pytest.importorskip("xgboost")
    from eval import recheck_bench

    path = tmp_path / "m.json"
    subprocess.run([sys.executable, "scripts/train_recheck.py", "--out", str(path)], check=True, capture_output=True)
    result = recheck_bench.run(dataclasses.replace(settings, xgb_model_path=str(path)))
    assert result["judges"]["t1"]["attacks_let_through"] == []
    assert result["judges"]["ensemble"]["false_benign_rate"] == 0.0
    assert result["judges"]["t1"]["benign_pass_rate"] > 0
