"""v2.2 silent-failure fixes.

1. Approvals and MCP re-pins need an analyst bearer token; the identity comes from
   the token, so two made-up names in a request body approve nothing.
2. A T1 action must cite a typed fact that actually supports "benign".
3. An approved action whose executor raises is closed as failed and audited,
   never left open with no trace.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from conftest import requires_opa

from services.proxy.main import create_app as create_proxy
from trustgate.analysts import AnalystDirectory, token_hash
from trustgate.gate import ApprovalExecutionFailed
from trustgate.models import Alert, Evidence, ProposedAction, TypedFacts

KNOWN_SENDER = dict(dmarc_pass=True, url_reputation="clean", sender_prior_messages=12)
TOKENS = {"ana": "tok-ana", "bo": "tok-bo"}


def _directory() -> AnalystDirectory:
    return AnalystDirectory.parse("\n".join(f"{name}:{token_hash(tok)}" for name, tok in TOKENS.items()))


def _put(store, alert_id="A-1", **facts):
    store.put_alert(Alert(alert_id=alert_id, source="email", severity="low", facts=TypedFacts(**facts),
                          evidence=[Evidence(id="ev-1", field="email.body", content="hello")]))


def _escalated_block(gate, store, fn=None):
    executed = []
    gate.register("block_ip", 2, fn or (lambda alert_id, ip: executed.append(ip) or {"ok": True}))
    _put(store, ioc_ips=["10.0.0.10"], **KNOWN_SENDER)  # critical asset: a human must approve
    d = gate.decide(ProposedAction(alert_id="A-1", verdict="malicious", tool="block_ip",
                                   args={"ip": "10.0.0.10"}, cited_evidence=["facts.ioc_ips"]))
    assert d.escalation_id
    return d.escalation_id, executed


def _bearer(name):
    return {"Authorization": f"Bearer {TOKENS[name]}"}


# --- 1. authenticated approvals ---------------------------------------------------------------

def test_directory_identifies_by_token_only():
    directory = _directory()
    assert directory.identify("tok-ana") == "ana"
    assert directory.identify("ana") is None
    assert directory.identify("") is None
    assert AnalystDirectory.parse("").configured is False


@requires_opa
def test_approval_without_token_is_rejected(gate, store, settings):
    esc_id, executed = _escalated_block(gate, store)
    proxy = TestClient(create_proxy(gate=gate, settings=settings, analysts=_directory()))
    # The old request shape: two made-up names in the body, no token (what a hijacked agent could send).
    resp = proxy.post(f"/v1/escalations/{esc_id}/approve",
                      json={"analyst": "ana", "second_analyst": "bo", "reason": "ok"})
    assert resp.status_code == 401
    resp = proxy.post(f"/v1/escalations/{esc_id}/approve", json={"reason": "ok"},
                      headers={"Authorization": "Bearer guessed"})
    assert resp.status_code == 401
    assert executed == [] and store.get_escalation(esc_id).status == "open"


@requires_opa
def test_approvals_refused_when_no_analysts_configured(gate, store, settings):
    esc_id, executed = _escalated_block(gate, store)
    proxy = TestClient(create_proxy(gate=gate, settings=settings, analysts=AnalystDirectory()))
    resp = proxy.post(f"/v1/escalations/{esc_id}/approve", json={"reason": "ok"}, headers=_bearer("ana"))
    assert resp.status_code == 503
    assert executed == []


@requires_opa
def test_t2_approval_needs_two_distinct_tokens(gate, store, settings):
    esc_id, executed = _escalated_block(gate, store)
    proxy = TestClient(create_proxy(gate=gate, settings=settings, analysts=_directory()))
    one = proxy.post(f"/v1/escalations/{esc_id}/approve", json={"reason": "ok"}, headers=_bearer("ana"))
    assert one.status_code == 409 and "second, different analyst" in one.json()["detail"]
    same = proxy.post(f"/v1/escalations/{esc_id}/approve", json={"reason": "ok"},
                      headers={**_bearer("ana"), "X-Second-Analyst-Token": TOKENS["ana"]})
    assert same.status_code == 409
    bad = proxy.post(f"/v1/escalations/{esc_id}/approve", json={"reason": "ok"},
                     headers={**_bearer("ana"), "X-Second-Analyst-Token": "nope"})
    assert bad.status_code == 401
    assert executed == []
    ok = proxy.post(f"/v1/escalations/{esc_id}/approve", json={"reason": "ok"},
                    headers={**_bearer("ana"), "X-Second-Analyst-Token": TOKENS["bo"]})
    assert ok.status_code == 200 and executed == ["10.0.0.10"]
    esc = store.get_escalation(esc_id)
    assert esc.status == "approved" and esc.analyst == "ana"
    assert any((r.details or {}).get("second_analyst") == "bo" for r in store.audit_trail() if r.kind == "analyst")


@requires_opa
def test_repin_needs_a_token(gate, store, settings):
    proxy = TestClient(create_proxy(gate=gate, settings=settings, analysts=_directory()))
    assert proxy.post("/v1/mcp/pins/mock-soc/exfil/approve",
                      json={"approver": "ana", "reason": "x"}).status_code == 401
    # With a token the request is authorised (404: no such pin).
    assert proxy.post("/v1/mcp/pins/mock-soc/exfil/approve", json={"reason": "x"},
                      headers=_bearer("ana")).status_code == 404


# --- 2. the cited fact must support benign ---------------------------------------------------------

@requires_opa
def test_t1_citing_unrelated_fact_escalates(gate, store):
    _put(store, ioc_ips=["203.0.113.9"], **KNOWN_SENDER)
    d = gate.decide(ProposedAction(alert_id="A-1", verdict="benign", tool="close_alert",
                                   args={"reason": "fine"}, cited_evidence=["facts.ioc_ips"]))
    assert d.decision == "escalate"
    assert any("no cited typed fact supports benign" in r for r in d.reasons)
    d = gate.decide(ProposedAction(alert_id="A-1", verdict="benign", tool="close_alert",
                                   args={"reason": "fine"}, cited_evidence=["facts.ioc_ips", "facts.dmarc_pass"]))
    assert d.decision == "allow"


@requires_opa
def test_floor_denies_t1_without_cited_support(opa_engine):
    result = opa_engine.decide({
        "pack": "soc", "tool": "close_alert", "tier": 1, "agent_verdict": "benign", "recheck_verdict": "benign",
        "cited": ["facts.ioc_ips"], "alert_severity": "low", "ai_evasion_attempt": False,
        "contains_raw_evidence": False, "output_entities": [], "scope": {"required": False, "ok": True},
        "t1_evidence": {"unknown_core": [], "costly_support": ["x"], "costly_ok": True,
                        "enrichment_failed": False, "cited_support": [], "cited_support_ok": False}})
    assert result.allow is False
    assert result.deny == ["T1: no cited typed fact supports benign"]


# --- 3. a failed approved execution is closed and audited -------------------------------------------

@requires_opa
def test_failed_approved_execution_is_closed_and_audited(gate, store, settings):
    def broken(alert_id, ip):
        raise ConnectionError("firewall API down")

    esc_id, _ = _escalated_block(gate, store, fn=broken)
    with pytest.raises(ApprovalExecutionFailed):
        gate.resolve_escalation(esc_id, approve=True, analyst="ana", reason="ok", second_analyst="bo")
    esc = store.get_escalation(esc_id)
    assert esc.status == "failed" and esc.result == {"error": "ConnectionError"}
    failed = [r for r in store.audit_trail() if r.kind == "execution_failed"]
    assert failed and failed[-1].details["escalation_id"] == esc_id


@requires_opa
def test_failed_approved_execution_returns_502(gate, store, settings):
    def broken(alert_id, ip):
        raise ConnectionError("firewall API down")

    esc_id, _ = _escalated_block(gate, store, fn=broken)
    proxy = TestClient(create_proxy(gate=gate, settings=settings, analysts=_directory()))
    resp = proxy.post(f"/v1/escalations/{esc_id}/approve", json={"reason": "ok"},
                      headers={**_bearer("ana"), "X-Second-Analyst-Token": TOKENS["bo"]})
    assert resp.status_code == 502
    assert "firewall" not in resp.text  # fixed message: the error type only
