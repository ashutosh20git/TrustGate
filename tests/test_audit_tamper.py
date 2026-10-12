"""Tampering with the audit trail, every way someone with database access could (docs/BENCHMARKS.md).

NIST SP 800-53 AU-9 (protection of audit information) and AU-10 (non-repudiation), ISO/IEC
27001:2022 A.8.15 (logging). The hash chain catches edits, deletions in the middle, reordering and
forged inserts on its own. Deleting the newest records, or rewriting every record and recomputing
every hash, leaves a valid chain: those are caught by comparing with the copy already exported to
the SIEM (Store.verify_audit_export).
"""

from __future__ import annotations

import hashlib

import pytest
from sqlmodel import select

from trustgate.models import Alert, GateDecision, TypedFacts
from trustgate.store import AuditRecord, Store, _canonical


@pytest.fixture
def exported(tmp_path, monkeypatch):
    path = tmp_path / "siem.jsonl"
    monkeypatch.setenv("TRUSTGATE_SIEM_JSONL", str(path))
    monkeypatch.setenv("TRUSTGATE_RATELIMIT_BACKEND", "memory")
    from trustgate.config import Settings

    store = Store(f"sqlite:///{tmp_path}/a.db", settings=Settings())
    store.put_alert(Alert(alert_id="A-1", source="email", severity="low", facts=TypedFacts(), evidence=[]))
    for i in range(6):
        store.audit("decision", alert_id="A-1", tool="close_alert",
                    decision=GateDecision(decision="escalate" if i % 2 else "allow", tier=1, reasons=[f"r{i}"]))
    assert store.verify_audit_chain() and store.verify_audit_export(str(path)) == []
    return store, str(path)


def _edit(store, fn):
    with store.session() as s:
        fn(s, list(s.exec(select(AuditRecord).order_by(AuditRecord.seq)).all()))
        s.commit()


def test_edit_is_caught(exported):
    store, path = exported

    def edit(s, recs):
        recs[1].decision = "allow"  # an escalation rewritten as allowed
        s.add(recs[1])
    _edit(store, edit)
    assert not store.verify_audit_chain() and store.verify_audit_export(path)


def test_deleting_a_middle_record_is_caught(exported):
    store, path = exported
    _edit(store, lambda s, recs: s.delete(recs[3]))
    assert not store.verify_audit_chain()
    assert any("missing" in p for p in store.verify_audit_export(path))


def test_reordering_is_caught(exported):
    store, _ = exported

    def swap(s, recs):
        recs[1].reasons, recs[4].reasons = recs[4].reasons, recs[1].reasons
        s.add(recs[1])
        s.add(recs[4])
    _edit(store, swap)
    assert not store.verify_audit_chain()


def test_forged_insert_is_caught(exported):
    store, _ = exported

    def forge(s, recs):
        fake = AuditRecord(kind="decision", alert_id="A-1", tool="close_alert", decision="allow",
                           prev_hash=recs[2].record_hash)
        fake.record_hash = hashlib.sha256((fake.prev_hash + _canonical(fake)).encode()).hexdigest()
        s.add(fake)
    _edit(store, forge)
    assert not store.verify_audit_chain()


def test_deleting_the_newest_records_needs_the_export(exported):
    store, path = exported

    def truncate(s, recs):
        for rec in recs[-2:]:
            s.delete(rec)
    _edit(store, truncate)
    assert store.verify_audit_chain()  # what is left is still a valid chain
    assert any("missing" in p for p in store.verify_audit_export(path))


def test_rewriting_the_whole_chain_needs_the_export(exported):
    store, path = exported

    def rewrite(s, recs):
        prev = ""
        for rec in recs:
            if rec.decision == "escalate":
                rec.decision = "allow"  # hide every escalation
            rec.prev_hash = prev
            rec.record_hash = hashlib.sha256((rec.prev_hash + _canonical(rec)).encode()).hexdigest()
            prev = rec.record_hash
            s.add(rec)
    _edit(store, rewrite)
    assert store.verify_audit_chain()  # recomputed hashes: the chain alone cannot tell
    assert any("differs" in p for p in store.verify_audit_export(path))


def test_nist_au9_reports_a_rewritten_chain(exported):
    from trustgate.compliance import report

    store, _ = exported
    controls = {c["id"]: c for c in report(store, "nist-800-53")["controls"]}
    assert controls["AU-9"]["status"] == "met"

    def rewrite(s, recs):
        prev = ""
        for rec in recs:
            rec.decision = "allow"
            rec.prev_hash = prev
            rec.record_hash = hashlib.sha256((rec.prev_hash + _canonical(rec)).encode()).hexdigest()
            prev = rec.record_hash
            s.add(rec)
    _edit(store, rewrite)
    controls = {c["id"]: c for c in report(store, "nist-800-53")["controls"]}
    assert controls["AU-9"]["status"] == "gap" and "DIFFERS" in controls["AU-9"]["evidence"]
