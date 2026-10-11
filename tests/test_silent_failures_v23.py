"""v2.3 silent-failure fixes: what leaves the system.

14. Outbound checks run on decoded text: zero-width characters, base64 and
    inserted punctuation no longer hide a quote of the evidence or a secret.
15. Every quote of 40+ letters and digits is caught, not only quotes that line
    up with a sampled window; oversize payloads escalate instead of being
    partly scanned.
16. The proxy tells tool callers only whether an action ran; reasons and the
    analyst views need an analyst token.
17. The LLM Guard fallback names secrets and floor-blocked identifiers, so the
    floor can still block them instead of only redacting.
"""

from __future__ import annotations

import base64
import re

import pytest
from fastapi.testclient import TestClient

from conftest import facts_recheck, requires_opa

from services.proxy.main import create_app as create_proxy
from trustgate.analysts import AnalystDirectory, token_hash
from trustgate.gate import ApprovalRefused, Gate
from trustgate.ingest.decode import SCAN_TEXT_LIMIT
from trustgate.models import Alert, Evidence, ProposedAction, TypedFacts
from trustgate.output_scan import LLMGuardBackend, OutputScanner, regex_findings
from trustgate.policy_client import load_pack
from trustgate.ratelimit import MemoryRateLimiter
from trustgate.value_match import raw_evidence_in

EVIDENCE = "Here is a long confidential log line the attacker wants exfiltrated right now, all of it."
KEY = "AKIAIOSFODNN7EXAMPLE"
ZW = "​"


class _Hit:
    def __init__(self, entity, start, end, score):
        self.entity_type, self.start, self.end, self.score = entity, start, end, score


class RegexBackend:
    """Deterministic stand-in for Presidio: the regex recognizers only, no spaCy model."""

    name = "regex-test"

    def analyze(self, text):
        return [_Hit(*h) for h in regex_findings(text)]

    def redact(self, text, hits):
        for h in sorted(hits, key=lambda h: -h.start):
            text = text[:h.start] + f"<{h.entity_type}>" + text[h.end:]
        return text


def _alert():
    return Alert(alert_id="A-1", source="email", severity="high", facts=TypedFacts(dmarc_pass=False),
                 evidence=[Evidence(id="ev-1", field="email.body", content=EVIDENCE)])


@pytest.fixture
def tgate(settings, store, opa_engine):
    pack = load_pack("packs/soc.rego")
    gate = Gate("packs/soc.rego", recheck=facts_recheck, mode="enforce", settings=settings, store=store,
                policy_engine=opa_engine, limiter=MemoryRateLimiter(),
                output_scanner=OutputScanner(pack, settings, backend=RegexBackend()))
    store.put_alert(_alert())
    return gate


def _send(gate, body):
    return gate.decide(ProposedAction(alert_id="A-1", verdict="malicious", tool="send_email",
                                      args={"to": "soc-team@corp.example", "subject": "update", "body": body},
                                      cited_evidence=["facts.dmarc_pass"]))


# --- 14 and 15: evidence quotes ---------------------------------------------------------------

@pytest.mark.parametrize("disguise", [
    lambda t: t,
    lambda t: ZW.join(t),                                     # zero-width characters between letters
    lambda t: base64.b64encode(t.encode()).decode(),          # base64
    lambda t: ".".join(t.split()),                            # punctuation instead of spaces
    lambda t: t.upper(),
])
def test_evidence_quote_caught_however_disguised(disguise):
    assert raw_evidence_in("Summary: " + disguise(EVIDENCE), _alert()) == ["ev-1"]


def test_unaligned_short_quote_is_caught():
    # 54 characters starting at offset 25: no 40-char window sampled every 20 characters fits inside.
    quote = EVIDENCE[25:79]
    assert len(re.sub(r"[\W_]", "", quote)) >= 40
    assert raw_evidence_in(f"FYI {quote} thanks", _alert()) == ["ev-1"]


def test_unrelated_text_not_flagged():
    assert raw_evidence_in("Blocked 203.0.113.9 at the firewall; ticket closed as malicious phishing.", _alert()) == []


@requires_opa
def test_t3_encoded_quote_escalates(tgate):
    d = _send(tgate, "Status: " + base64.b64encode(EVIDENCE.encode()).decode())
    assert d.decision == "escalate"
    assert "raw evidence in outbound payload" in d.reasons


# --- 14: secrets hidden by encoding ------------------------------------------------------------

@requires_opa
@pytest.mark.parametrize("hide", [lambda k: ZW.join(k), lambda k: base64.b64encode(k.encode()).decode()])
def test_t3_hidden_secret_escalates(tgate, hide):
    d = _send(tgate, f"Rotated credentials: {hide(KEY)}")
    assert d.decision == "escalate"
    assert any("hidden by encoding" in r and "API_KEY" in r for r in d.reasons)


@requires_opa
def test_t3_plain_secret_still_blocked_and_clean_body_allowed(tgate):
    d = _send(tgate, f"key {KEY}")
    assert d.decision == "escalate" and any("API_KEY" in r for r in d.reasons)
    assert _send(tgate, "Blocked the sender; no further action needed.").decision == "allow"


@requires_opa
def test_t3_oversize_payload_escalates(tgate):
    d = _send(tgate, "x " * (SCAN_TEXT_LIMIT // 2 + 1))
    assert d.decision == "escalate"
    assert any("cannot be fully scanned" in r for r in d.reasons)


@requires_opa
def test_approval_refuses_encoded_floor_blocked_secret(tgate, store):
    executed = []
    tgate.register("send_email", 3, lambda alert_id, to, subject, body: executed.append(body))
    hidden = base64.b64encode(f"card 4111 1111 1111 1111".encode()).decode()
    d = _send(tgate, f"Billing ref {hidden}")
    assert d.decision == "escalate" and d.escalation_id
    with pytest.raises(ApprovalRefused, match="CREDIT_CARD"):
        tgate.resolve_escalation(d.escalation_id, approve=True, analyst="ana", reason="ok", second_analyst="bo")
    assert executed == []


# --- 17: LLM Guard fallback can block ----------------------------------------------------------

def test_llm_guard_fallback_blocks_floor_entities(settings):
    class FakeLLMGuard(LLMGuardBackend):
        def __init__(self):  # no llm-guard install needed
            pass

        def analyze_and_redact(self, text):
            return "[REDACTED]", False, 0.9

    scanner = OutputScanner(load_pack("packs/soc.rego"), settings, backend=FakeLLMGuard())
    result = scanner.scan({"body": "card 4111 1111 1111 1111"})
    assert "CREDIT_CARD" in result.blocked_entities
    assert result.redacted["body"] == "[REDACTED]"


def test_regex_findings_use_checksums():
    entities = {e for e, *_ in regex_findings("4111 1111 1111 1112 and 234123412345")}
    assert "CREDIT_CARD" not in entities and "IN_AADHAAR" not in entities  # checksums fail
    entities = {e for e, *_ in regex_findings("4111 1111 1111 1111 and 2341 2341 2346")}
    assert {"CREDIT_CARD", "IN_AADHAAR"} <= entities


# --- 16: the proxy does not tell the agent why ------------------------------------------------------

@requires_opa
def test_tool_response_hides_reasons_and_views_need_token(tgate, settings):
    analysts = AnalystDirectory.parse(f"ana:{token_hash('tok-ana')}")
    proxy = TestClient(create_proxy(gate=tgate, settings=settings, analysts=analysts))
    body = proxy.post("/v1/tools/send_email", json={
        "alert_id": "A-1", "verdict": "malicious", "tool": "send_email",
        "args": {"to": "drop@exfil.example", "subject": "x", "body": "hi"},
        "cited_evidence": ["facts.dmarc_pass"]}).json()
    assert body["executed"] is False
    assert set(body["decision"]) == {"decision", "tier", "mode", "escalation_id"}
    assert body["decision"]["decision"] == "escalate"
    for path in ("/v1/escalations", "/v1/audit", "/v1/alerts/A-1", "/v1/metrics", "/v1/rollout", "/v1/mcp/pins"):
        assert proxy.get(path).status_code == 401, path
        assert proxy.get(path, headers={"Authorization": "Bearer tok-ana"}).status_code == 200, path
    # The reasons are still there for analysts.
    queue = proxy.get("/v1/escalations", headers={"Authorization": "Bearer tok-ana"}).json()
    assert any("policy: T3: recipient not on the SOC allowlist" in r for e in queue for r in e["reasons"])
