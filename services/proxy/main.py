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
"""

from __future__ import annotations

import asyncio
import random
from collections import Counter
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from services.mock_soc.client import MockSOCClient
from services.soc_tools import register_soc_tools, soc_tool_functions, soc_undo_functions
from trustgate.analysts import AnalystDirectory
from trustgate.config import NotConfigured, Settings
from trustgate.compliance import report as compliance_report
from trustgate.counterfactual import explain
from trustgate.gate import ESCALATED_MESSAGE, ApprovalExecutionFailed, ApprovalRefused, Gate, ToolConfigError
from trustgate.ingest.enrich import ThreatIntel
from trustgate.mcp.pinning import ToolPinRegistry
from trustgate.models import GateDecision, ProposedAction
from trustgate.store import Escalation, Store

CANARY_RATE = 0.1  # share of the queue that is planted known-bad items (silent failure 21)


class AnalystDecision(BaseModel):
    reason: str


class RepinRequest(BaseModel):
    reason: str


class RevertRequest(BaseModel):
    reason: str


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
    action = ProposedAction.model_validate(template.action)
    decision = GateDecision(decision="escalate", tier=1, reasons=[
        "facts and text disagree: agent=benign, facts-only=malicious"], recheck_verdict="malicious",
        tainted_spans=template.tainted_spans)
    store.open_escalation(action.model_copy(update={"tool": "close_alert", "verdict": "benign"}), decision, canary=True)


def create_app(gate: Gate | None = None, settings: Settings | None = None,
               analysts: AnalystDirectory | None = None) -> FastAPI:
    settings = settings or Settings()
    analysts = analysts if analysts is not None else AnalystDirectory.parse(settings.analyst_tokens)
    store = gate.store if gate is not None else Store(settings=settings)
    if gate is None:
        gate = Gate(settings.policy, settings=settings, store=store)
        try:
            client = MockSOCClient(settings.mock_soc_url, settings.mock_soc_token)
        except NotConfigured:
            client = None  # placeholder: tools fail at execution, decisions still work
        if client is not None:
            register_soc_tools(gate, soc_tool_functions(client, store, ThreatIntel(settings)),
                               undo=soc_undo_functions(client))
    pins = ToolPinRegistry(store)
    rng = random.Random()
    app = FastAPI(title="TrustGate proxy", version="2.0.0")
    app.state.gate = gate

    def analyst_from(authorization: str | None) -> str:
        if not analysts.configured:
            raise HTTPException(503, "analyst authentication not configured; run scripts/init_secrets.py")
        scheme, _, token = (authorization or "").partition(" ")
        name = analysts.identify(token) if scheme == "Bearer" else None
        if name is None:
            raise HTTPException(401, "a valid analyst token is required")
        return name

    def require_analyst(authorization: str | None = Header(default=None)) -> str:
        return analyst_from(authorization)

    @app.post("/v1/tools/{tool}")
    async def call_tool(tool: str, action: ProposedAction) -> dict[str, Any]:
        action = action.model_copy(update={"tool": tool})
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
            "message": None if executed else (ESCALATED_MESSAGE if not decision.permits_execution else error),
        }

    @app.get("/v1/escalations", dependencies=[Depends(require_analyst)])
    def escalations(status: str = "open") -> list[dict[str, Any]]:
        if status == "open":
            _ensure_canaries(store, gate, rng)
        items = store.escalations(status if status != "all" else None)
        rng.shuffle(items)
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
            second = analysts.identify(x_second_analyst_token.strip())
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
    def actions(alert_id: str | None = None, status: str | None = None) -> list[dict[str, Any]]:
        """The ledger of executed T1/T2 actions and how each is undone."""
        return [a.model_dump(mode="json") for a in store.actions(alert_id, status=status)]

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
        """Evidence pack for cert-in, dpdp or iso27001 (evidence for a review, not a determination)."""
        try:
            return compliance_report(store, framework)
        except ValueError as exc:
            raise HTTPException(404, str(exc)) from None

    @app.get("/v1/audit", dependencies=[Depends(require_analyst)])
    def audit(alert_id: str | None = None, limit: int = 500) -> list[dict[str, Any]]:
        return [r.model_dump(mode="json") for r in store.audit_trail(alert_id, limit=limit)]

    @app.get("/v1/alerts/{alert_id}", dependencies=[Depends(require_analyst)])
    def get_alert(alert_id: str) -> dict[str, Any]:
        alert = store.get_alert(alert_id)
        if alert is None:
            raise HTTPException(404)
        return alert.model_dump(mode="json")

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

    @app.get("/healthz")
    def healthz():
        checks = gate.health()
        healthy = (checks.get("policy") is True and checks.get("rate_limiter") is True
                   and not checks.get("saturated"))
        checks["t1_t3"] = "ok" if healthy else "fail closed: dependencies down or gate saturated"
        return JSONResponse(checks, status_code=200 if healthy else 503)

    return app
