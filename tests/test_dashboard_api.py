"""The proxy reads behind the redesigned dashboard: the alert list and the newest audit records.

Both need an analyst token like every other analyst view. The audit trail used to return only
the oldest records, so on a busy system the dashboard could never show what just happened.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from services.proxy.main import create_app as create_proxy
from trustgate.analysts import AnalystDirectory, token_hash
from trustgate.models import Alert, Evidence, ProposedAction, TypedFacts

TOKEN = "alice-token"
AUTH = {"Authorization": f"Bearer {TOKEN}"}


def _proxy(gate, settings) -> TestClient:
    return TestClient(create_proxy(gate=gate, settings=settings,
                                   analysts=AnalystDirectory.parse(f"alice:{token_hash(TOKEN)}")))


def test_alert_list_needs_an_analyst_and_summarises_each_alert(gate, store, settings):
    store.put_alert(Alert(alert_id="A-1", source="email", severity="high", facts=TypedFacts(), tags=["hidden content"],
                          evidence=[Evidence(id="ev-1", field="email.body", content="hi", flags=["hidden_text"]),
                                    Evidence(id="ev-2", field="email.subject", content="x")]))
    proxy = _proxy(gate, settings)
    assert proxy.get("/v1/alerts").status_code == 401
    rows = proxy.get("/v1/alerts", headers=AUTH).json()
    assert [r["alert_id"] for r in rows] == ["A-1"]
    assert rows[0]["flagged_evidence"] == 1
    assert rows[0]["tags"] == ["hidden content"]
    assert rows[0]["received_at"]


def test_audit_newest_returns_the_latest_records_in_chain_order(gate, store, settings):
    store.put_alert(Alert(alert_id="A-1", source="email", severity="high", facts=TypedFacts(), evidence=[]))
    for _ in range(5):
        gate.decide(ProposedAction(alert_id="A-1", verdict="unsure", tool="no_such_tool", args={}))
    proxy = _proxy(gate, settings)
    every = proxy.get("/v1/audit", headers=AUTH).json()
    oldest = proxy.get("/v1/audit?limit=2", headers=AUTH).json()
    newest = proxy.get("/v1/audit?limit=2&newest=true", headers=AUTH).json()
    assert [r["seq"] for r in oldest] == [r["seq"] for r in every[:2]]
    assert [r["seq"] for r in newest] == [r["seq"] for r in every[-2:]]
