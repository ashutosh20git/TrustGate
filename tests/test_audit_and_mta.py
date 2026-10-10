"""Audit chain integrity, SIEM export, and trusted-vs-spoofed email auth headers."""

from __future__ import annotations

from trustgate.ingest.parsers.email import auth_from_headers
from trustgate.models import Alert, GateDecision, TypedFacts


def test_audit_chain_detects_tampering(store):
    alert = Alert(alert_id="A-1", source="email", severity="low", facts=TypedFacts(), evidence=[])
    store.put_alert(alert)
    for i in range(3):
        store.audit("decision", alert_id="A-1", tool="close_alert",
                    decision=GateDecision(decision="escalate", tier=1, reasons=[f"r{i}"]))
    assert store.verify_audit_chain() is True
    with store.session() as s:
        from trustgate.store import AuditRecord
        from sqlmodel import select
        rec = s.exec(select(AuditRecord)).first()
        rec.reasons = ["tampered"]
        s.add(rec)
        s.commit()
    assert store.verify_audit_chain() is False


def test_trusted_authserv_header_is_a_fact():
    headers = ["mx.corp.example; spf=pass smtp.mailfrom=a@b.example; dkim=pass; dmarc=pass header.from=b.example"]
    facts, spoofed = auth_from_headers(headers, "mx.corp.example")
    assert facts.spf_pass is True and facts.dmarc_pass is True
    assert facts.source == "mta_header"
    assert spoofed == []


def test_attacker_authserv_header_is_spoofed_not_a_fact():
    headers = [
        "mx.corp.example; spf=fail; dkim=none; dmarc=fail header.from=evil.example",  # trusted, topmost
        "mx.corp.example; spf=pass; dkim=pass; dmarc=pass",                           # attacker-written copy
    ]
    facts, spoofed = auth_from_headers(headers, "mx.corp.example")
    assert facts.spf_pass is False and facts.dmarc_pass is False  # the real result
    assert len(spoofed) == 1


def test_no_trusted_authserv_means_unknown():
    headers = ["attacker-mta.evil; spf=pass; dkim=pass; dmarc=pass"]
    facts, spoofed = auth_from_headers(headers, "mx.corp.example")
    assert facts.spf_pass is None and facts.source == "none"


def test_siem_jsonl_export(tmp_path, monkeypatch):
    path = tmp_path / "siem.jsonl"
    monkeypatch.setenv("TRUSTGATE_SIEM_JSONL", str(path))
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/s.db")
    from trustgate.config import Settings
    from trustgate.store import Store

    store = Store(settings=Settings())
    store.audit("decision", alert_id="A-1", tool="block_ip",
                decision=GateDecision(decision="allow", tier=2, reasons=["ok"]))
    assert path.exists()
    assert "block_ip" in path.read_text(encoding="utf-8")
