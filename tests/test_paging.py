"""Cursor pagination on the analyst lists: alerts, the queue, decided items, actions and the audit trail.

Pages are keyed on the last row's sort key, so rows arriving while an analyst pages
through never cause a duplicate or a skip, which offsets would. The next cursor comes
in the X-Next-Cursor header and is absent on the last page; a tampered cursor is a 400.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from services.proxy.main import create_app as create_proxy
from trustgate.analysts import AnalystDirectory, token_hash
from trustgate.models import Alert, GateDecision, ProposedAction, TypedFacts
from trustgate.store import ActionRecord

AUTH = {"Authorization": "Bearer ana-token"}


def _proxy(gate, settings) -> TestClient:
    return TestClient(create_proxy(gate=gate, settings=settings,
                                   analysts=AnalystDirectory.parse(f"ana:{token_hash('ana-token')}")))


def _alert(store, alert_id: str) -> None:
    store.put_alert(Alert(alert_id=alert_id, source="email", severity="low", facts=TypedFacts(), evidence=[]))


def _held(store, alert_id: str, tool: str = "close_alert"):
    action = ProposedAction(alert_id=alert_id, verdict="benign", tool=tool, args={"n": tool})
    return store.open_escalation(action, GateDecision(decision="escalate", tier=1, reasons=["held"]))


def _walk(proxy, path: str) -> tuple[list[dict], int]:
    """Every row of a paged list, and how many pages it took."""
    rows, cursor, pages = [], None, 0
    while True:
        sep = "&" if "?" in path else "?"
        resp = proxy.get(f"{path}{sep}cursor={cursor}" if cursor else path, headers=AUTH)
        assert resp.status_code == 200, resp.text
        rows += resp.json()
        pages += 1
        cursor = resp.headers.get("x-next-cursor")
        if not cursor:
            return rows, pages


def test_alerts_page_newest_first_without_repeats(gate, store, settings):
    for i in range(5):
        _alert(store, f"A-{i}")
    proxy = _proxy(gate, settings)
    rows, pages = _walk(proxy, "/v1/alerts?limit=2")
    assert [r["alert_id"] for r in rows] == ["A-4", "A-3", "A-2", "A-1", "A-0"]
    assert pages == 3


def test_an_alert_arriving_mid_scroll_neither_repeats_nor_skips_a_row(gate, store, settings):
    for i in range(4):
        _alert(store, f"A-{i}")
    proxy = _proxy(gate, settings)
    first = proxy.get("/v1/alerts?limit=2", headers=AUTH)
    _alert(store, "A-new")  # offsets would now shift A-2 onto page two again
    second = proxy.get(f"/v1/alerts?limit=2&cursor={first.headers['x-next-cursor']}", headers=AUTH)
    assert [r["alert_id"] for r in first.json() + second.json()] == ["A-3", "A-2", "A-1", "A-0"]
    assert "x-next-cursor" not in second.headers


def test_alert_status_filter_search_and_counts(gate, store, settings):
    for alert_id in ("WAIT-1", "DONE-1", "NEW-1"):
        _alert(store, alert_id)
    _held(store, "WAIT-1")
    store.audit("decision", alert_id="DONE-1", tool="close_alert",
                decision=GateDecision(decision="allow", tier=0, reasons=[]))
    proxy = _proxy(gate, settings)
    statuses = {r["alert_id"]: r["status"] for r in proxy.get("/v1/alerts", headers=AUTH).json()}
    assert statuses == {"WAIT-1": "waiting", "DONE-1": "handled", "NEW-1": "new"}
    for status, expected in (("waiting", "WAIT-1"), ("handled", "DONE-1"), ("new", "NEW-1")):
        assert [r["alert_id"] for r in proxy.get(f"/v1/alerts?status={status}", headers=AUTH).json()] == [expected]
    assert [r["alert_id"] for r in proxy.get("/v1/alerts?q=done", headers=AUTH).json()] == ["DONE-1"]
    assert proxy.get("/v1/alerts?q=%25", headers=AUTH).json() == []  # LIKE wildcards are escaped
    assert proxy.get("/v1/alerts?status=bogus", headers=AUTH).status_code == 422
    assert proxy.get("/v1/alert-counts", headers=AUTH).json() == {"all": 3, "waiting": 1, "handled": 1, "new": 1}


def test_open_queue_pages_cover_everything_and_report_the_total(gate, store, settings):
    for i in range(7):
        _alert(store, f"A-{i}")
        _held(store, f"A-{i}")
    proxy = _proxy(gate, settings)
    first = proxy.get("/v1/escalations?status=open&limit=3", headers=AUTH)
    total = int(first.headers["x-total-count"])  # includes any canary planted on this read
    rows, pages = _walk(proxy, "/v1/escalations?status=open&limit=3")
    assert len(rows) == len({r["id"] for r in rows}) == total >= 7
    assert pages == -(-total // 3)
    again, _ = _walk(proxy, "/v1/escalations?status=open&limit=3")
    assert [r["id"] for r in again] == [r["id"] for r in rows]  # stable order across reads


def test_queue_filters_to_one_alert_and_lists_decided_items(gate, store, settings):
    _alert(store, "A-1")
    _alert(store, "A-2")
    keep = _held(store, "A-1")
    done = _held(store, "A-2")
    store.close_escalation(done.id, status="rejected", analyst="ana", reason="no")
    proxy = _proxy(gate, settings)
    only = proxy.get("/v1/escalations?status=open&alert_id=A-2", headers=AUTH).json()
    assert only == []
    assert keep.id in [e["id"] for e in proxy.get("/v1/escalations?status=open&alert_id=A-1", headers=AUTH).json()]
    decided = proxy.get("/v1/escalations?status=decided", headers=AUTH).json()
    assert [(e["id"], e["status"], e["analyst_reason"]) for e in decided] == [(done.id, "rejected", "no")]


def test_canaries_carry_their_templates_age(gate, store, settings):
    _alert(store, "A-1")
    real = _held(store, "A-1")
    _proxy(gate, settings).get("/v1/escalations?status=open", headers=AUTH)
    canaries = [e for e in store.escalations("open") if e.canary]
    assert canaries and all(c.created_at == real.created_at for c in canaries)


def test_audit_pages_walk_back_from_the_newest(gate, store, settings):
    for i in range(5):
        store.audit("decision", alert_id="A-1", tool=f"t{i}", decision=GateDecision(decision="allow", tier=0, reasons=[]))
    store.audit("execution", alert_id="A-1", tool="t-exec")
    proxy = _proxy(gate, settings)
    first = proxy.get("/v1/audit?newest=true&limit=2", headers=AUTH)
    assert [r["tool"] for r in first.json()] == ["t4", "t-exec"]  # the latest two, in chain order
    rows, pages = _walk(proxy, "/v1/audit?newest=true&limit=2")
    assert pages == 3 and len({r["seq"] for r in rows}) == 6
    kinds = proxy.get("/v1/audit?kind=execution", headers=AUTH).json()
    assert [r["tool"] for r in kinds] == ["t-exec"]


def test_actions_page_newest_first(gate, store, settings):
    for i in range(3):
        store.record_action(ActionRecord(alert_id="A-1", tool=f"t{i}", tier=1))
    rows, pages = _walk(_proxy(gate, settings), "/v1/actions?limit=2")
    assert [r["tool"] for r in rows] == ["t2", "t1", "t0"] and pages == 2


def test_a_tampered_cursor_is_refused(gate, settings):
    proxy = _proxy(gate, settings)
    for path in ("/v1/alerts", "/v1/audit", "/v1/actions", "/v1/escalations?status=decided",
                 "/v1/escalations?status=open"):
        sep = "&" if "?" in path else "?"
        for bad in ("not-base64!", "eyJhIjoxfQ", "W3RydWVd"):
            assert proxy.get(f"{path}{sep}cursor={bad}", headers=AUTH).status_code == 400, (path, bad)
