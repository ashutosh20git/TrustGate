"""TrustGate proxy (FastAPI + Uvicorn): the only bridge between the agent and its tools.

    uvicorn services.proxy.main:create_app --factory --port 8080

Endpoints follow the blueprint (page 8) plus v2 additions for MCP pins.
Tool credentials live only here (MOCK_SOC_TOKEN, a Docker secret).

Approving or rejecting an escalation and re-pinning an MCP tool need an analyst
bearer token (Authorization: Bearer ...); T2/T3 approvals also need a second
analyst's token (X-Second-Analyst-Token). Identities come from the tokens, never
from the request body, so the agent, which shares agent-net with the proxy and
holds no analyst token, cannot approve its own escalations.

Tool callers (the agent) learn only whether an action ran: never the gate's
reasons, the re-check verdict or the tainted spans, which would tell anything on
agent-net which check to get around. The analyst views (escalations, audit,
alerts, metrics, rollout, pins) need an analyst token too.

The team endpoints (/v1/team) need an admin token: the people in the setup secret
file, or a member an admin added as admin. A new or reset token is returned once,
in that response only; the store and the audit trail never see it in clear.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import hashlib
import hmac
import importlib
import random
import secrets
from collections import Counter
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ValidationError

from services.soc_tools import register_soc_tools, soc_tool_functions, soc_undo_functions
from trustgate.analysts import NAME, ROLES, AnalystDirectory, Member, Team, new_token, token_hash
from trustgate.config import NotConfigured, Settings
from trustgate.compliance import report as compliance_report
from trustgate.counterfactual import explain
from trustgate.gate import ApprovalExecutionFailed, ApprovalRefused, Gate, ToolConfigError, refusal_message
from trustgate.ingest.enrich import ThreatIntel
from trustgate.mcp.pinning import ToolPinRegistry
from trustgate.models import GateDecision, ProposedAction
from trustgate.paging import NEXT_CURSOR, TOTAL_COUNT, BadCursor, decode, encode
from trustgate.store import Escalation, Store, TeamMember, _now

CANARY_RATE = 0.1  # share of the queue that is planted known-bad items (silent failure 21)


class AnalystDecision(BaseModel):
    reason: str


class RepinRequest(BaseModel):
    reason: str


class RevertRequest(BaseModel):
    reason: str


class NewMember(BaseModel):
    name: str
    role: str = "analyst"


def _public(esc: Escalation) -> dict[str, Any]:
    """Escalation as the analyst sees it: canaries look like any other item."""
    data = esc.model_dump(mode="json")
    data.pop("canary", None)
    data.pop("dedupe_key", None)
    return data


def _ensure_canaries(store: Store, gate: Gate, rng: random.Random) -> None:
    open_items = store.escalations("open")
    real = [e for e in open_items if not e.canary]
    canaries = [e for e in open_items if e.canary]
    if not real or len(canaries) >= max(1, int(len(real) * CANARY_RATE)):
        return
    template = rng.choice(real)
    try:
        action = ProposedAction.model_validate(template.action)
    except ValidationError:
        return  # a malformed stored action never takes the queue down
    decision = GateDecision(decision="escalate", tier=1, reasons=[
        "facts and text disagree: agent=benign, facts-only=malicious"], recheck_verdict="malicious",
        tainted_spans=template.tainted_spans)
    # Its template's age, so "just now" on a card does not give the canary away.
    store.open_escalation(action.model_copy(update={"tool": "close_alert", "verdict": "benign"}), decision,
                          canary=True, created_at=template.created_at)


def load_soc_client(settings: Settings) -> Any:
    """Build the SOC connector named by TRUSTGATE_SOC_CLIENT ("module:Class").

    It is called as Class(base_url, token) with MOCK_SOC_URL and the mock_soc_token
    secret, and must provide the methods of services.mock_soc.client.MockSOCClient
    (the tools, their reverse actions, and query_logs). A connector that cannot start
    raises NotConfigured: decisions still work and every allowed action fails closed.
    """
    module, _, name = settings.soc_client.partition(":")
    cls = getattr(importlib.import_module(module), name)
    return cls(settings.mock_soc_url, settings.mock_soc_token)


def create_app(gate: Gate | None = None, settings: Settings | None = None,
               analysts: AnalystDirectory | None = None) -> FastAPI:
    settings = settings or Settings()
    analysts = analysts if analysts is not None else AnalystDirectory.parse(settings.analyst_tokens)
    store = gate.store if gate is not None else Store(settings=settings)
    if gate is None:
        gate = Gate(settings.policy, settings=settings, store=store)
        try:
            client = load_soc_client(settings)
        except NotConfigured:
            client = None  # placeholder: tools fail at execution, decisions still work
        if client is not None:
            register_soc_tools(gate, soc_tool_functions(client, store, ThreatIntel(settings)),
                               undo=soc_undo_functions(client))
    pins = ToolPinRegistry(store)
    team = Team(analysts, store)
    rng = random.Random()
    # The open queue's order: a keyed hash of each id. Stable, so it can be paged, and
    # unpredictable, so a canary's position says nothing (it was planted most recently).
    queue_key = secrets.token_bytes(16)

    def queue_order(esc_id: str) -> str:
        return hmac.new(queue_key, esc_id.encode(), hashlib.sha256).hexdigest()

    def cursor(value: str | None, types: tuple[type, ...]):
        try:
            return decode(value, types)
        except BadCursor:
            raise HTTPException(400, "invalid cursor") from None

    def paged(response: Response, nxt: tuple | int | None) -> None:
        if nxt is not None:
            response.headers[NEXT_CURSOR] = encode(*(nxt if isinstance(nxt, tuple) else (nxt,)))
    app = FastAPI(title="TrustGate proxy", version="2.0.0")
    app.state.gate = gate

    def member_from(authorization: str | None) -> Member:
        if not team.configured:
            raise HTTPException(503, "analyst authentication not configured; run scripts/init_secrets.py")
        scheme, _, token = (authorization or "").partition(" ")
        member = team.identify(token) if scheme == "Bearer" else None
        if member is None:
            raise HTTPException(401, "a valid analyst token is required")
        return member

    def analyst_from(authorization: str | None) -> str:
        return member_from(authorization).name

    def require_analyst(authorization: str | None = Header(default=None)) -> str:
        return analyst_from(authorization)

    def require_admin(authorization: str | None = Header(default=None)) -> Member:
        member = member_from(authorization)
        if not member.admin:
            raise HTTPException(403, "only an admin can manage the team")
        return member

    @app.post("/v1/tools/{tool}")
    async def call_tool(tool: str, action: ProposedAction) -> dict[str, Any]:
        # Validate, not model_copy: a copy skips the tool-name check, and an invalid name stored
        # with an escalation broke every later read of the analyst queue (API fuzzing).
        try:
            action = ProposedAction.model_validate({**action.model_dump(), "tool": tool})
        except ValidationError:
            raise HTTPException(422, "invalid tool name") from None
        decision = await asyncio.to_thread(gate.decide, action)
        executed, result, error = False, None, None
        if decision.permits_execution:
            try:
                result = await asyncio.to_thread(gate.execute, action, decision)
                executed = True
            except (ToolConfigError, NotConfigured) as exc:
                error = f"tool unavailable: {type(exc).__name__}"
            except Exception as exc:  # fixed message, no evidence content
                error = f"tool error: {type(exc).__name__}"
                store.audit("execution_failed", alert_id=action.alert_id, tool=tool, details={"error": error})
        return {
            # Outcome only. Reasons stay in the audit trail and the analyst queue.
            "decision": {"decision": decision.decision, "tier": decision.tier, "mode": decision.mode,
                         "escalation_id": decision.escalation_id},
            "executed": executed,
            "result": result,
            "error": error,
            "message": None if executed else (refusal_message(decision) if not decision.permits_execution else error),
        }

    @app.get("/v1/escalations", dependencies=[Depends(require_analyst)])
    def escalations(response: Response, status: str = "open", alert_id: str | None = None,
                    limit: int = Query(200, ge=1, le=1_000), cursor_: str | None = Query(None, alias="cursor")
                    ) -> list[dict[str, Any]]:
        """The queue (status=open), or decided/all/one status, a page at a time (X-Next-Cursor).

        The open queue comes in a keyed-hash order and reports its size in X-Total-Count;
        the others come newest first.
        """
        if status == "open":
            _ensure_canaries(store, gate, rng)
            ranked = sorted(((queue_order(e.id), e) for e in store.escalations("open", 100_000, alert_id=alert_id)),
                            key=lambda pair: pair[0])
            response.headers[TOTAL_COUNT] = str(len(ranked))
            after = cursor(cursor_, (str,))
            if after is not None:
                ranked = [pair for pair in ranked if pair[0] > after[0]]
            page = ranked[:limit]
            paged(response, (page[-1][0],) if len(ranked) > limit else None)
            return [_public(e) for _, e in page]
        items, nxt = store.escalation_page(status=None if status == "all" else status, alert_id=alert_id,
                                           limit=limit, after=cursor(cursor_, (dt.datetime, str)))
        paged(response, nxt)
        return [_public(e) for e in items]

    @app.post("/v1/escalations/{esc_id}/{verdict}")
    def resolve(esc_id: str, verdict: str, body: AnalystDecision,
                authorization: str | None = Header(default=None),
                x_second_analyst_token: str | None = Header(default=None)) -> dict[str, Any]:
        if verdict not in ("approve", "reject"):
            raise HTTPException(404)
        analyst = analyst_from(authorization)
        second = None
        if x_second_analyst_token:
            second_member = team.identify(x_second_analyst_token)
            second = second_member.name if second_member else None
            if second is None:
                raise HTTPException(401, "the second analyst token is not valid")
        try:
            return gate.resolve_escalation(esc_id, approve=verdict == "approve", analyst=analyst,
                                           reason=body.reason, second_analyst=second)
        except KeyError:
            raise HTTPException(404, "no open escalation with that id") from None
        except ApprovalRefused as exc:
            raise HTTPException(409, f"approval refused: {exc}") from None
        except ApprovalExecutionFailed as exc:
            raise HTTPException(502, str(exc)) from None
        except (ToolConfigError, NotConfigured) as exc:
            raise HTTPException(503, f"executor unavailable: {type(exc).__name__}") from None

    @app.get("/v1/actions", dependencies=[Depends(require_analyst)])
    def actions(response: Response, alert_id: str | None = None, status: str | None = None,
                limit: int = Query(500, ge=1, le=1_000), cursor_: str | None = Query(None, alias="cursor")
                ) -> list[dict[str, Any]]:
        """The ledger of executed T1/T2 actions and how each is undone, newest first, paged."""
        items, nxt = store.action_page(alert_id=alert_id, status=status, limit=limit,
                                       after=cursor(cursor_, (dt.datetime, str)))
        paged(response, nxt)
        return [a.model_dump(mode="json") for a in items]

    @app.post("/v1/actions/{action_id}/revert")
    def revert(action_id: str, body: RevertRequest, analyst: str = Depends(require_analyst)) -> dict[str, Any]:
        try:
            return gate.revert(action_id, by=analyst, reason=body.reason).model_dump(mode="json")
        except KeyError:
            raise HTTPException(404, "no executed action with that id") from None
        except ToolConfigError as exc:
            raise HTTPException(409, str(exc)) from None

    @app.get("/v1/analysts", dependencies=[Depends(require_analyst)])
    def analyst_scores() -> dict[str, Any]:
        """Rubber-stamp detection: approval rate, canaries approved and decision speed per analyst."""
        return store.analyst_scores()

    @app.get("/v1/escalations/{esc_id}/explain", dependencies=[Depends(require_analyst)])
    def explain_escalation(esc_id: str) -> dict[str, Any]:
        """What would have let this action through, and what never will automatically."""
        esc = store.get_escalation(esc_id)
        if esc is None:  # canaries are explained like any item, so the queue does not reveal them
            raise HTTPException(404)
        return explain(gate, esc)

    @app.get("/v1/compliance/{framework}", dependencies=[Depends(require_analyst)])
    def compliance(framework: str) -> dict[str, Any]:
        """Evidence pack for cert-in, dpdp, iso27001 or nist-800-53 (evidence for a review, not a determination)."""
        try:
            return compliance_report(store, framework)
        except ValueError as exc:
            raise HTTPException(404, str(exc)) from None

    @app.get("/v1/audit", dependencies=[Depends(require_analyst)])
    def audit(response: Response, alert_id: str | None = None, kind: str | None = None,
              limit: int = Query(500, ge=1, le=10_000), newest: bool = False,
              cursor_: str | None = Query(None, alias="cursor")) -> list[dict[str, Any]]:
        """The trail in chain order, paged: oldest first, or with newest=true walking back
        from the latest record (each page still in chain order)."""
        after = cursor(cursor_, (int,))
        rows, nxt = store.audit_page(alert_id=alert_id, kind=kind, limit=limit, newest=newest,
                                     after=after[0] if after else None)
        paged(response, nxt)
        return [r.model_dump(mode="json") for r in rows]

    @app.get("/v1/alerts", dependencies=[Depends(require_analyst)])
    def list_alerts(response: Response, limit: int = Query(200, ge=1, le=5_000),
                    status: str | None = Query(None, pattern="^(waiting|handled|new)$"),
                    q: str | None = Query(None, max_length=128),
                    cursor_: str | None = Query(None, alias="cursor")) -> list[dict[str, Any]]:
        """Every alert received, newest first and paged, with its review status
        (waiting, handled or new); q matches part of the alert id."""
        rows, nxt = store.alert_page(limit=limit, status=status, query=q,
                                     after=cursor(cursor_, (dt.datetime, str)))
        paged(response, nxt)
        return [{"alert_id": a.alert_id, "source": a.source, "severity": a.severity,
                 "original_severity": a.original_severity, "tags": a.tags,
                 "received_at": received.isoformat(), "label_coverage": a.label_coverage.ratio,
                 "flagged_evidence": sum(1 for e in a.evidence if e.flags), "status": state}
                for a, received, state in rows]

    @app.get("/v1/alert-counts", dependencies=[Depends(require_analyst)])
    def alert_counts() -> dict[str, int]:
        """How many alerts are waiting, handled or new: the alert list's filter counts."""
        return store.alert_counts()

    @app.get("/v1/alerts/{alert_id}", dependencies=[Depends(require_analyst)])
    def get_alert(alert_id: str) -> dict[str, Any]:
        alert = store.get_alert(alert_id)
        if alert is None:
            raise HTTPException(404)
        received = store.alert_received(alert_id)
        return {**alert.model_dump(mode="json"), "received_at": received.isoformat() if received else None,
                "status": store.alert_states([alert_id])[alert_id]}

    @app.get("/v1/metrics", dependencies=[Depends(require_analyst)])
    def metrics() -> dict[str, Any]:
        records = store.audit_trail(limit=1_000_000)
        decisions = [r for r in records if r.kind == "decision"]
        by = Counter(f"T{r.tier if r.tier is not None else '?'}:{r.decision}" for r in decisions)
        latencies = sorted(r.latency_ms for r in decisions if r.latency_ms is not None)
        all_esc = store.escalations(None, limit=100_000)
        canary = Counter((e.result or {}).get("canary") for e in all_esc if e.canary and e.status != "open")
        alerts = store.list_alerts(limit=10_000)
        coverage = [a.label_coverage.ratio for a in alerts]
        return {
            "decisions": len(decisions),
            "by_tier_decision": dict(by),
            "would_block_monitor": sum(1 for r in decisions if not r.enforced and r.decision != "allow"),
            "fail_closed": sum(1 for r in decisions if (r.details or {}).get("fail_closed")),
            "latency_ms_p50": latencies[len(latencies) // 2] if latencies else None,
            "latency_ms_p95": latencies[int(len(latencies) * 0.95)] if latencies else None,
            "recheck_tokens": sum(r.recheck_tokens or 0 for r in decisions),
            "escalations": dict(Counter(e.status for e in all_esc if not e.canary)),
            "canary_caught": canary.get("canary_caught", 0),
            "canary_missed": canary.get("canary_missed", 0),
            "label_coverage_min": min(coverage) if coverage else None,
            "alerts": len(alerts),
            "ai_evasion_alerts": sum(1 for a in alerts if a.ai_evasion_attempt),
            "mcp_pins": dict(Counter(p.status for p in store.pins())),
            "audit_chain_ok": store.verify_audit_chain(),
            # Drift: how often the facts-only verdict matched analysts on resolved T1 escalations.
            "recheck_analyst_agreement": store.recheck_agreement(),
            "mode": gate.mode,
            "pack": gate.pack.name,
        }

    @app.get("/v1/rollout", dependencies=[Depends(require_analyst)])
    def rollout(min_samples: int = 50) -> dict[str, Any]:
        """Monitor-mode readiness: what enforcing would have blocked, per tool."""
        return store.rollout_report(min_samples=min_samples)

    @app.get("/v1/mcp/pins", dependencies=[Depends(require_analyst)])
    def list_pins() -> list[dict[str, Any]]:
        return [p.model_dump(mode="json") for p in store.pins()]

    @app.post("/v1/mcp/pins/{server}/{tool}/approve")
    def repin(server: str, tool: str, body: RepinRequest,
              authorization: str | None = Header(default=None)) -> dict[str, Any]:
        approver = analyst_from(authorization)
        try:
            return pins.approve(server, tool, approver=approver, reason=body.reason).model_dump(mode="json")
        except KeyError:
            raise HTTPException(404) from None

    # --- team -------------------------------------------------------------------

    def _member_view(name: str, role: str, source: str, row: TeamMember | None = None) -> dict[str, Any]:
        view: dict[str, Any] = {"name": name, "role": role, "source": source, "active": True}
        if row is not None:
            view.update(active=row.removed_at is None, added_at=row.added_at, added_by=row.added_by,
                        token_reset_at=row.token_reset_at, removed_at=row.removed_at, removed_by=row.removed_by)
        return view

    def _team_member(name: str, admin: Member) -> TeamMember:
        if name in analysts.names:
            raise HTTPException(409, f"{name} is in the setup file; change them there")
        row = store.get_member(name)
        if row is None or row.removed_at is not None:
            raise HTTPException(404, f"no active team member called {name}")
        if name == admin.name:
            raise HTTPException(409, "ask another admin to change your own access")
        return row

    @app.get("/v1/me")
    def me(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        member = member_from(authorization)
        return {"name": member.name, "role": member.role, "source": member.source}

    @app.get("/v1/team", dependencies=[Depends(require_admin)])
    def list_team() -> list[dict[str, Any]]:
        setup = [_member_view(n, "admin", "setup") for n in sorted(analysts.names)]
        return setup + [_member_view(r.name, r.role, "team", r) for r in store.members()
                        if r.name not in analysts.names]

    @app.post("/v1/team")
    def add_member(body: NewMember, admin: Member = Depends(require_admin)) -> dict[str, Any]:
        name = body.name.strip().lower()
        if not NAME.match(name):
            raise HTTPException(422, "a name is 1-64 letters, digits or . _ @ -")
        if body.role not in ROLES:
            raise HTTPException(422, f"role must be one of {', '.join(ROLES)}")
        existing = store.get_member(name)
        if name in analysts.names or (existing is not None and existing.removed_at is None):
            raise HTTPException(409, f"{name} is already on the team")
        token = new_token()
        # A removed name can come back; it gets a fresh token and its old one stays dead.
        row = store.put_member(TeamMember(name=name, token_sha256=token_hash(token), role=body.role,
                                          added_by=admin.name))
        store.audit("team", details={"event": "added", "member": name, "role": body.role, "by": admin.name})
        return {"member": _member_view(name, row.role, "team", row), "token": token}

    @app.post("/v1/team/{name}/token")
    def reset_token(name: str, admin: Member = Depends(require_admin)) -> dict[str, Any]:
        row = _team_member(name, admin)
        token = new_token()
        row.token_sha256 = token_hash(token)
        row.token_reset_at = _now()
        store.put_member(row)
        store.audit("team", details={"event": "token_reset", "member": name, "by": admin.name})
        return {"member": _member_view(name, row.role, "team", row), "token": token}

    @app.post("/v1/team/{name}/remove")
    def remove_member(name: str, admin: Member = Depends(require_admin)) -> dict[str, Any]:
        row = _team_member(name, admin)
        row.removed_at = _now()
        row.removed_by = admin.name
        store.put_member(row)
        store.audit("team", details={"event": "removed", "member": name, "by": admin.name})
        return _member_view(name, row.role, "team", row)

    @app.get("/healthz")
    def healthz():
        checks = gate.health()
        healthy = (checks.get("policy") is True and checks.get("rate_limiter") is True
                   and not checks.get("saturated"))
        checks["t1_t3"] = "ok" if healthy else "fail closed: dependencies down or gate saturated"
        return JSONResponse(checks, status_code=200 if healthy else 503)

    return app
