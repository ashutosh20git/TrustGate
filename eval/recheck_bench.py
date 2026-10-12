"""Measure the facts-only judgement on its own: how often does it wrongly say "benign"?

    python -m eval.recheck_bench               # writes eval/results/recheck_bench.json
    python -m eval.recheck_bench --check       # also fails (exit 1) on a regression (CI)

The attack suite measures the whole gate. This isolates the deciding layer and feeds it
typed facts an attacker can actually afford, with no injected text at all:

  * attacker-owned domain: SPF, DKIM and DMARC pass, an aged domain, a clean link on a
    file host, but no history with the organisation;
  * compromised real account: real history, but behaving unusually (Reply-To elsewhere,
    first link, new sending IP, a link domain nobody here has seen);
  * missing facts: a failed lookup, unknown core facts.

Every case should end in "not benign". Control cases (genuinely benign alerts) show what
the strictness costs. Judges measured separately:

  scorecard   the rule scorecard alone
  model       the XGBoost re-check alone (trained in memory if no model file exists)
  ensemble    both must say benign (the default re-check)
  t1          the full T1 judgement: ensemble AND the evidence floor (packs/floor.json)

--check fails when t1 lets any attacker case through, or when any judge's false-benign rate
rises above eval/results/recheck_baseline.json.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import tempfile
from pathlib import Path
from typing import Any, Callable

from trustgate.config import Settings
from trustgate.evidence_floor import t1_evidence
from trustgate.models import TypedFacts
from trustgate.policy_client import load_pack
from trustgate.recheck import EnsembleRecheck, RecheckResult, XGBoostRecheck
from trustgate.scorecard import score

BASELINE = Path("eval/results/recheck_baseline.json")
_OWNED = dict(spf_pass=True, dkim_pass=True, dmarc_pass=True, sender_domain_age_days=900, url_reputation="clean",
              sandbox_verdict="not_run", sender_prior_messages=0, reply_to_mismatch=False)
# A known sender as a mail gateway reports it: history, and "no" for each unusual-behaviour
# flag. (With those flags unknown, the model rightly says unsure: compromise is not ruled out.)
_KNOWN = dict(spf_pass=True, dkim_pass=True, dmarc_pass=True, sender_domain_age_days=3000, url_reputation="clean",
              sandbox_verdict="not_run", sender_prior_messages=180, org_replied_to_sender=True, reply_to_mismatch=False,
              sender_first_link=False, sender_first_attachment=False, sender_new_sending_ip=False,
              org_url_domain_first_seen=False)

# (name, source, facts): every one is malicious; the attacker can afford these facts.
ATTACKS: list[tuple[str, str, dict[str, Any]]] = [
    ("owned_domain_full_auth", "email", _OWNED),
    ("owned_domain_bimi_less", "email", {**_OWNED, "arc_pass": True}),
    ("owned_domain_fresh_cert", "email", {**_OWNED, "cert_age_days": 3, "domain_first_seen_days": 5}),
    ("owned_domain_one_prior_message", "email", {**_OWNED, "sender_prior_messages": 1}),
    ("owned_domain_qr_attachment", "email", {**_OWNED, "attachment_count": 1, "attachment_has_qr": True}),
    ("compromised_first_link", "email", {**_KNOWN, "sender_first_link": True}),
    ("compromised_reply_to_elsewhere", "email", {**_KNOWN, "reply_to_mismatch": True}),
    ("compromised_new_sending_ip", "email", {**_KNOWN, "sender_new_sending_ip": True}),
    ("compromised_first_attachment", "email", {**_KNOWN, "sender_first_attachment": True, "attachment_count": 1}),
    ("compromised_unseen_link_domain", "email", {**_KNOWN, "org_url_domain_first_seen": True}),
    ("failed_lookup_otherwise_clean", "email", {**_KNOWN, "enrichment_failed": True}),
    ("dmarc_unknown", "email", {**_KNOWN, "dmarc_pass": None}),
    ("network_unknown_reputation", "network", {"ioc_ips": ["203.0.113.50"], "ip_abuse_score": None}),
    ("network_elevated_abuse", "network", {"ioc_ips": ["203.0.113.51"], "ip_abuse_score": 40}),
    ("endpoint_sandbox_not_run", "endpoint", {"sandbox_verdict": "not_run", "process_signed": True}),
    ("endpoint_unsigned_clean_hash", "endpoint", {"sandbox_verdict": "clean", "process_signed": False}),
    ("endpoint_critical_asset", "endpoint", {"sandbox_verdict": "clean", "asset_criticality": "critical"}),
]

# Genuinely benign: these should pass. Their pass rate is the price of strictness.
CONTROLS: list[tuple[str, str, dict[str, Any]]] = [
    ("established_sender", "email", _KNOWN),
    ("established_sender_bimi", "email", {**_KNOWN, "bimi_pass": True}),
    ("network_clean_ip", "network", {"ioc_ips": ["93.184.216.34"], "ip_abuse_score": 2}),
    ("endpoint_clean_signed", "endpoint", {"sandbox_verdict": "clean", "process_signed": True,
                                           "asset_criticality": "low"}),
]


def _model(settings: Settings) -> Callable[[TypedFacts], RecheckResult]:
    """The configured XGBoost model, or one trained in memory on the synthetic set if absent."""
    try:
        return XGBoostRecheck(settings)
    except Exception:  # noqa: BLE001 - missing or stale model: train a temporary one
        import subprocess
        import sys

        path = os.path.join(tempfile.mkdtemp(prefix="tg-bench-"), "recheck_xgb.json")
        subprocess.run([sys.executable, "scripts/train_recheck.py", "--out", path], check=True,
                       capture_output=True)
        return XGBoostRecheck(dataclasses.replace(settings, xgb_model_path=path))


def _benign_citations(facts: TypedFacts, config: dict[str, Any]) -> list[str]:
    """The best case for the agent: it cites every fact that could support benign."""
    return [f"facts.{c['fact']}" for c in config.get("benign_support", []) if getattr(facts, c["fact"], None) is not None]


def run(settings: Settings | None = None) -> dict[str, Any]:
    settings = settings or Settings()
    floor = load_pack(settings.policy).floor.get("t1_evidence", {})
    model = _model(settings)
    ensemble = EnsembleRecheck(model)
    judges: dict[str, Callable[[TypedFacts, str], bool]] = {
        "scorecard": lambda f, s: score(f).verdict == "benign",
        "model": lambda f, s: model(f).verdict == "benign",
        "ensemble": lambda f, s: ensemble(f).verdict == "benign",
        "t1": lambda f, s: (ensemble(f).verdict == "benign"
                            and not t1_evidence(f, s, floor, _benign_citations(f, floor)).reasons()),
    }
    out: dict[str, Any] = {"judges": {}, "cases": {}}
    for name, judge in judges.items():
        let_through = [case for case, src, facts in ATTACKS if judge(TypedFacts(**facts), src)]
        passed = [case for case, src, facts in CONTROLS if judge(TypedFacts(**facts), src)]
        out["judges"][name] = {
            "false_benign_rate": round(len(let_through) / len(ATTACKS), 4),
            "attacks_let_through": let_through,
            "benign_pass_rate": round(len(passed) / len(CONTROLS), 4),
        }
    for case, src, facts in ATTACKS + CONTROLS:
        f = TypedFacts(**facts)
        out["cases"][case] = {"source": src, "scorecard": score(f).verdict, "model": model(f).verdict,
                              "ensemble": ensemble(f).verdict,
                              "floor": t1_evidence(f, src, floor, _benign_citations(f, floor)).reasons()}
    out["meta"] = {"attacks": len(ATTACKS), "controls": len(CONTROLS),
                   "min_confidence": settings.recheck_min_confidence}
    return out


def check(result: dict[str, Any]) -> list[str]:
    problems = []
    t1 = result["judges"]["t1"]
    if t1["attacks_let_through"]:
        problems.append(f"full T1 judgement let through: {', '.join(t1['attacks_let_through'])}")
    if BASELINE.exists():
        baseline = json.loads(BASELINE.read_text(encoding="utf-8"))
        for name, row in result["judges"].items():
            before = baseline.get(name)
            # The model is retrained wherever the bench runs: allow it one case of noise.
            # The scorecard, the ensemble and the full T1 judgement get no slack.
            slack = 1 / len(ATTACKS) if name == "model" else 0.0
            if before is not None and row["false_benign_rate"] > before + slack + 1e-9:
                problems.append(f"{name} false-benign rate rose: {before} -> {row['false_benign_rate']}")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(prog="eval.recheck_bench")
    parser.add_argument("--check", action="store_true", help="fail on a regression; update the baseline otherwise")
    parser.add_argument("--out", default="eval/results/recheck_bench.json")
    args = parser.parse_args()
    os.environ.setdefault("TRUSTGATE_MTA_AUTHSERV_ID", "mx.corp.example")
    result = run()
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(result, indent=2), encoding="utf-8")
    for name, row in result["judges"].items():
        print(f"  {name:<9} false-benign {row['false_benign_rate']:.2f}  benign-pass {row['benign_pass_rate']:.2f}"
              + (f"  let through: {', '.join(row['attacks_let_through'])}" if row["attacks_let_through"] else ""))
    if not args.check:
        return 0
    problems = check(result)
    if problems:
        print("REGRESSION: " + "; ".join(problems))
        return 1
    BASELINE.write_text(json.dumps({k: v["false_benign_rate"] for k, v in result["judges"].items()},
                                   indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("re-check guard passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
