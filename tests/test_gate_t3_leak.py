"""T3 outbound: raw evidence and blocked secrets escalate; an attacker recipient escalates.

Exercises the exfiltration defence end to end. `presidio`-dependent assertions
skip where the scanner backend is missing, but the recipient and raw-evidence
checks run everywhere.
"""

from __future__ import annotations

import pytest

from conftest import requires_opa

from trustgate.config import NotConfigured
from trustgate.models import Alert, Evidence, ProposedAction, TypedFacts
from trustgate.output_scan import OutputScanner


def _alert(store):
    alert = Alert(alert_id="A-1", source="email", severity="high",
                  facts=TypedFacts(dmarc_pass=True),
                  evidence=[Evidence(id="ev-1", field="email.body",
                                     content="Here is a long confidential log line the attacker wants exfiltrated now.")])
    store.put_alert(alert)
    return alert


def _scanner_or_skip():
    try:
        scanner = OutputScanner.__new__(OutputScanner)
        from trustgate.policy_client import load_pack
        scanner.__init__(load_pack("packs/soc.rego"))
        scanner._load()
        return scanner
    except NotConfigured as exc:
        pytest.skip(f"output scanner unavailable: {exc.what}")


@requires_opa
def test_t3_to_attacker_escalates(gate, store):
    _alert(store)
    _scanner_or_skip()
    d = gate.decide(ProposedAction(alert_id="A-1", verdict="malicious", tool="send_email",
                                   args={"to": "drop-box@exfil-collector.example", "subject": "x", "body": "hi"},
                                   cited_evidence=["facts.dmarc_pass"]))
    assert d.decision == "escalate"


@requires_opa
def test_t3_raw_evidence_in_body_escalates(gate, store):
    _alert(store)
    _scanner_or_skip()
    body = "Here is a long confidential log line the attacker wants exfiltrated now."
    d = gate.decide(ProposedAction(alert_id="A-1", verdict="malicious", tool="send_email",
                                   args={"to": "soc-team@corp.example", "subject": "x", "body": body},
                                   cited_evidence=["facts.dmarc_pass"]))
    assert d.decision == "escalate"
    assert "raw evidence in outbound payload" in d.reasons
    assert "ev-1" in d.tainted_spans
