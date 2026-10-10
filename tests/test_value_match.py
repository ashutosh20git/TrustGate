"""T2 targets must be in typed facts; T3 recipients must be allowlisted (blueprint test_value_match).

Covers silent failure 16 (laundered arguments invisible to a proxy).
"""

from __future__ import annotations

from conftest import requires_opa

from trustgate.models import Alert, ProposedAction, TypedFacts


def _alert(store, **facts):
    alert = Alert(alert_id="A-1", source="network", severity="high", facts=TypedFacts(**facts), evidence=[])
    store.put_alert(alert)
    return alert


@requires_opa
def test_t2_target_in_facts_allowed(gate, store):
    _alert(store, ioc_ips=["203.0.113.9"], ip_abuse_score=90)
    d = gate.decide(ProposedAction(alert_id="A-1", verdict="malicious", tool="block_ip",
                                   args={"ip": "203.0.113.9"}, cited_evidence=["facts.ioc_ips"]))
    assert d.decision == "allow"


@requires_opa
def test_t2_target_not_in_facts_escalates(gate, store):
    _alert(store, ioc_ips=["203.0.113.9"])
    d = gate.decide(ProposedAction(alert_id="A-1", verdict="malicious", tool="block_ip",
                                   args={"ip": "8.8.8.8"}, cited_evidence=["facts.ioc_ips"]))
    assert d.decision == "escalate"
    assert "target not in typed facts" in d.reasons


@requires_opa
def test_t2_critical_asset_needs_human(gate, store):
    _alert(store, ioc_ips=["10.0.0.10"], ip_abuse_score=90)
    d = gate.decide(ProposedAction(alert_id="A-1", verdict="malicious", tool="block_ip",
                                   args={"ip": "10.0.0.10"}, cited_evidence=["facts.ioc_ips"]))
    assert d.decision == "escalate"


@requires_opa
def test_t3_allowlisted_recipient_allowed(gate, store):
    _alert(store, dmarc_pass=True)
    d = gate.decide(ProposedAction(alert_id="A-1", verdict="malicious", tool="send_email",
                                   args={"to": "soc-team@corp.example", "subject": "update",
                                         "body": "Blocked an IP for alert A-1."},
                                   cited_evidence=["facts.dmarc_pass"]))
    assert d.decision == "allow"


@requires_opa
def test_t3_recipient_off_allowlist_escalates(gate, store):
    _alert(store, dmarc_pass=True)
    d = gate.decide(ProposedAction(alert_id="A-1", verdict="malicious", tool="send_email",
                                   args={"to": "attacker@evil.example", "subject": "x", "body": "hi"},
                                   cited_evidence=["facts.dmarc_pass"]))
    assert d.decision == "escalate"
    assert any("allowlist" in r for r in d.reasons)
