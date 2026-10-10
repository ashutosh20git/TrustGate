"""The TrustGate decision (blueprint flowchart B), with v2 monitor-only mode.

    gate = Gate(policy="packs/soc.rego", recheck=facts_only_recheck, mode="enforce")  # or "monitor"

    @gate.tool(tier=Tier.SECURITY_REDUCING)        # T1
    def close_alert(alert_id: str, reason: str): ...

    @gate.tool(tier=Tier.DISRUPTIVE, target="ip")  # T2
    def block_ip(ip: str): ...

Every path either executes and logs, or escalates with a reason. Any error or
timeout in a check fails closed. Monitor mode computes the same decision and
logs it as "would block", but lets the action run.
"""

from __future__ import annotations

import asyncio
import contextvars
import functools
import inspect
import time
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Callable

import structlog
from opentelemetry import trace
from pydantic import ValidationError

from trustgate import value_match
from trustgate.config import NotConfigured, Settings
from trustgate.models import Alert, GateDecision, ProposedAction, Trust, TypedFacts, Verdict
from trustgate.output_scan import OutputScanner
from trustgate.policy_client import PolicyPack, load_pack, policy_client
from trustgate.ratelimit import rate_limiter
from trustgate.recheck import RecheckResult, as_recheck, facts_only_recheck
from trustgate.store import Store
from trustgate.tiers import Tier, UnknownTool

log = structlog.get_logger("trustgate.gate")
tracer = trace.get_tracer("trustgate")

# Fixed text returned to the agent: no evidence content can leak through errors (silent failure 17).
ESCALATED_MESSAGE = "Action not executed: TrustGate escalated it to a human analyst."
RESERVED_ARGS = ("verdict", "cited_evidence", "rationale")
_FACT_FIELDS = set(TypedFacts.model_fields)


class ActionEscalated(Exception):
    def __init__(self, decision: GateDecision):
        super().__init__(ESCALATED_MESSAGE)
        self.decision = decision


class ToolConfigError(ValueError):
    pass


@dataclass
class RegisteredTool:
    name: str
    tier: Tier
    fn: Callable[..., Any] | None
    target_arg: str | None = None
    is_async: bool = False
    description: str = ""
    parameters: dict[str, Any] = field(default_factory=dict)


@dataclass
class _State:
    tier: int | None = None
    recheck_verdict: Verdict | None = None
    recheck_tokens: int = 0


class _Escalate(Exception):
    def __init__(self, reasons: list[str], tainted: list[str] | None = None):
        self.reasons = reasons
        self.tainted = tainted or []


class Gate:
    def __init__(
        self,
        policy: str = "packs/soc.rego",
        recheck: Callable[[TypedFacts], Verdict | RecheckResult] | None = None,
        mode: str | None = None,
        *,
        settings: Settings | None = None,
        store: Store | None = None,
        policy_engine=None,
        limiter=None,
        output_scanner: OutputScanner | None = None,
        timeout_s: float | None = None,
    ):
        self.settings = settings or Settings()
        self.pack: PolicyPack = load_pack(policy)
        self.mode = (mode or self.settings.mode).lower()
        if self.mode not in ("enforce", "monitor"):
            raise ValueError("mode must be 'enforce' or 'monitor'")
        self.recheck = as_recheck(recheck) if recheck is not None else facts_only_recheck(self.settings)
        self.policy = policy_engine or policy_client(self.pack, self.settings)
        self.limiter = limiter or rate_limiter(self.settings)
        self.store = store or Store(settings=self.settings)
        self.output_scanner = output_scanner or OutputScanner(self.pack, self.settings)
        self.timeout_s = timeout_s or self.settings.check_timeout_s
        self.tools: dict[str, RegisteredTool] = {}
        self._pool = ThreadPoolExecutor(max_workers=16, thread_name_prefix="trustgate-check")
        self._alert_ctx: contextvars.ContextVar[Alert | None] = contextvars.ContextVar("trustgate_alert", default=None)

    # --- registration ---------------------------------------------------------

    def tier_of(self, tool: str) -> Tier:
        registered = self.tools.get(tool)
        if registered is not None:
            return registered.tier
        tier = self.pack.tier_of(tool)
        if tier is None:
            raise UnknownTool(tool)
        return tier

    def register(self, name: str, tier: Tier | int, fn: Callable[..., Any] | None = None, *,
                 target: str | None = None, description: str = "", parameters: dict[str, Any] | None = None) -> RegisteredTool:
        tier = Tier.parse(tier)
        pack_tier = self.pack.tier_of(name)
        if pack_tier is not None and pack_tier != tier:
            raise ToolConfigError(f"{name}: code says T{int(tier)} but pack '{self.pack.name}' says T{int(pack_tier)}")
        tool = RegisteredTool(name=name, tier=tier, fn=fn, target_arg=target,
                              is_async=bool(fn) and inspect.iscoroutinefunction(fn),
                              description=description or (inspect.getdoc(fn) or "" if fn else ""),
                              parameters=parameters or {})
        self.tools[name] = tool
        return tool

    def tool(self, tier: Tier | int | None = None, *, name: str | None = None, target: str | None = None):
        """Decorator. Tier comes from code or the pack; if both are given they must agree."""

        def decorate(fn: Callable[..., Any]):
            tool_name = name or fn.__name__
            tool_tier = tier if tier is not None else self.pack.tier_of(tool_name)
            if tool_tier is None:
                raise ToolConfigError(f"{tool_name}: no tier in code or in pack '{self.pack.name}'")
            self.register(tool_name, tool_tier, fn, target=target)
            signature = inspect.signature(fn)

            def build(args: tuple, kwargs: dict) -> ProposedAction:
                reserved = {k: kwargs.pop(k) for k in RESERVED_ARGS if k in kwargs}
                call_args = signature.bind_partial(*args, **kwargs).arguments
                alert = self._alert_ctx.get()
                alert_id = call_args.get("alert_id") or (alert.alert_id if alert else "")
                return ProposedAction(alert_id=str(alert_id), tool=tool_name, args=dict(call_args),
                                      verdict=reserved.get("verdict", "unsure"),
                                      cited_evidence=list(reserved.get("cited_evidence", [])),
                                      rationale=str(reserved.get("rationale", ""))[:800])

            if inspect.iscoroutinefunction(fn):
                @functools.wraps(fn)
                async def async_wrapper(*args, **kwargs):
                    action = self._build_or_escalate(build, args, kwargs, tool_name)
                    decision = await asyncio.to_thread(self.decide, action, self._alert_ctx.get())
                    if not decision.permits_execution:
                        raise ActionEscalated(decision)
                    return await fn(**self._execution_args(action, decision))

                return async_wrapper

            @functools.wraps(fn)
            def wrapper(*args, **kwargs):
                action = self._build_or_escalate(build, args, kwargs, tool_name)
                decision = self.decide(action, self._alert_ctx.get())
                if not decision.permits_execution:
                    raise ActionEscalated(decision)
                return fn(**self._execution_args(action, decision))

            return wrapper

        return decorate

    def _build_or_escalate(self, build, args, kwargs, tool_name: str) -> ProposedAction:
        try:
            return build(args, dict(kwargs))
        except (ValidationError, TypeError) as exc:
            decision = self._finish(GateDecision(decision="escalate", tier=None,
                                                 reasons=[f"schema: invalid tool call ({type(exc).__name__})"]),
                                    None, time.perf_counter())
            raise ActionEscalated(decision) from None

    @staticmethod
    def _execution_args(action: ProposedAction, decision: GateDecision) -> dict[str, Any]:
        if decision.enforced and decision.redacted_args is not None:
            return decision.redacted_args
        return action.args

    def call(self, tool_name: str, /, **kwargs: Any) -> Any:
        """Gate and run a registered tool by name (used by the adapters and the proxy)."""
        tool = self.tools.get(tool_name)
        if tool is None or tool.fn is None:
            raise ToolConfigError(f"no executor registered for {tool_name}")
        reserved = {k: kwargs.pop(k) for k in RESERVED_ARGS if k in kwargs}
        params = inspect.signature(tool.fn).parameters
        alert = self._alert_ctx.get()
        alert_id = kwargs.get("alert_id") if "alert_id" in params else kwargs.pop("alert_id", None)
        alert_id = alert_id or (alert.alert_id if alert else "")
        try:
            action = ProposedAction(alert_id=str(alert_id), tool=tool_name, args=kwargs,
                                    verdict=reserved.get("verdict", "unsure"),
                                    cited_evidence=list(reserved.get("cited_evidence") or []),
                                    rationale=str(reserved.get("rationale", ""))[:800])
        except ValidationError:
            decision = self._finish(GateDecision(decision="escalate", tier=None,
                                                 reasons=["schema: invalid tool call (ValidationError)"]),
                                    None, time.perf_counter())
            raise ActionEscalated(decision) from None
        return self.execute(action, self.decide(action, alert))

    @contextmanager
    def using(self, alert: Alert):
        """Bind the alert whose evidence justifies the tool calls made inside the block."""
        token = self._alert_ctx.set(alert)
        try:
            yield alert
        finally:
            self._alert_ctx.reset(token)

    # --- the decision -----------------------------------------------------------

    def decide(self, action: ProposedAction, alert: Alert | None = None, *, mcp: dict[str, Any] | None = None) -> GateDecision:
        start = time.perf_counter()
        state = _State()
        with tracer.start_as_current_span("trustgate.decide") as span:
            span.set_attribute("trustgate.tool", action.tool)
            try:
                future = self._pool.submit(self._checks, action, alert, mcp, state)
                decision = future.result(timeout=self.timeout_s)
            except FutureTimeout:
                decision = self._fail_closed(state, "TimeoutError")
            except Exception as exc:  # the watchdog: any error escalates
                decision = self._fail_closed(state, type(exc).__name__, exc)
            span.set_attribute("trustgate.decision", decision.decision)
        return self._finish(decision, action, start)

    def _fail_closed(self, state: _State, error: str, exc: Exception | None = None) -> GateDecision:
        reason = f"fail-closed: {error}"
        if isinstance(exc, NotConfigured):
            reason += f" ({exc.what} not configured)"
        log.warning("trustgate.fail_closed", error=error)
        return GateDecision(decision="escalate", tier=state.tier, reasons=[reason],
                            recheck_verdict=state.recheck_verdict, recheck_tokens=state.recheck_tokens)

    def _finish(self, decision: GateDecision, action: ProposedAction | None, start: float) -> GateDecision:
        decision.mode = self.mode
        decision.enforced = self.mode == "enforce"
        decision.pack = self.pack.name
        decision.latency_ms = round((time.perf_counter() - start) * 1000, 2)
        if decision.decision != "allow" and not decision.enforced:
            decision.reasons = ["monitor mode: would block"] + decision.reasons
        details: dict[str, Any] = {
            "fail_closed": any(r.startswith("fail-closed") for r in decision.reasons),
            "would_block": decision.would_block,
            "output_entities": sorted({f.entity for f in decision.output_findings}),
        }
        if action is not None:
            details.update(verdict=action.verdict, cited=action.cited_evidence, arg_names=sorted(action.args))
        rec = self.store.audit("decision", alert_id=action.alert_id if action else None,
                               tool=action.tool if action else None, decision=decision, details=details)
        decision.audit_id = rec.id
        if action is not None and decision.decision != "allow" and decision.enforced:
            decision.escalation_id = self.store.open_escalation(action, decision).id
        return decision

    def _checks(self, action: ProposedAction, alert: Alert | None, mcp: dict[str, Any] | None,
                state: _State) -> GateDecision:
        try:
            return self._run_checks(action, alert, mcp, state)
        except _Escalate as esc:
            return GateDecision(decision="escalate", tier=state.tier, reasons=esc.reasons,
                                recheck_verdict=state.recheck_verdict, tainted_spans=esc.tainted,
                                recheck_tokens=state.recheck_tokens)

    def _run_checks(self, action: ProposedAction, alert: Alert | None, mcp: dict[str, Any] | None,
                    state: _State) -> GateDecision:
        # 1. Which tier? (static map; unknown tool escalates)
        try:
            tier = self.tier_of(action.tool)
        except UnknownTool:
            raise _Escalate(["unknown tool"]) from None
        state.tier = int(tier)

        # 2. Schema: the alert exists and every cited ID exists. Read-only T0 calls
        #    that cite nothing (list alerts, query logs) need no alert.
        if alert is None and action.alert_id:
            alert = self.store.get_alert(action.alert_id)
        if tier != Tier.ALWAYS_ALLOWED or action.cited_evidence:
            if alert is None or alert.alert_id != action.alert_id:
                raise _Escalate(["schema: unknown alert"])
            bad = [c for c in action.cited_evidence if not self._citation_exists(c, alert)]
            if bad:
                raise _Escalate([f"schema: cited evidence does not exist: {', '.join(bad[:5])}"])

        # 3. v2: MCP tools must still match their pinned description.
        if mcp is not None and not mcp.get("pinned_ok"):
            raise _Escalate(["MCP tool not pinned or changed since pinning"])

        registered = self.tools.get(action.tool)
        decision = GateDecision(decision="allow", tier=int(tier), reasons=[])
        if tier == Tier.ALWAYS_ALLOWED:
            self._t0(action, alert, state, decision)
            return decision

        policy_input: dict[str, Any] = {
            "pack": self.pack.name,
            "tool": action.tool,
            "tier": int(tier),
            "agent_verdict": action.verdict,
            "cited": action.cited_evidence,
            "alert_severity": alert.severity,
            "ai_evasion_attempt": alert.ai_evasion_attempt,
            "contains_raw_evidence": False,
            "output_entities": [],
        }
        if mcp is not None:
            policy_input["mcp"] = {"server": mcp.get("server"), "pinned_ok": bool(mcp.get("pinned_ok"))}

        if tier == Tier.SECURITY_REDUCING:
            result = self.recheck(alert.facts)
            state.recheck_verdict, state.recheck_tokens = result.verdict, result.tokens
            decision.recheck_verdict, decision.recheck_tokens = result.verdict, result.tokens
            policy_input["recheck_verdict"] = result.verdict
            if not (action.verdict == "benign" and result.verdict == "benign"):
                raise _Escalate([f"facts and text disagree: agent={action.verdict}, facts-only={result.verdict}"],
                                self._tainted(action, alert))
            if not any(c.startswith("facts.") for c in action.cited_evidence):
                raise _Escalate(["no typed-fact citation"], self._tainted(action, alert))

        if tier == Tier.DISRUPTIVE:
            target, fact = value_match.target_of(self.pack, action.tool, action.args,
                                                  registered.target_arg if registered else None)
            targets = value_match.fact_targets(alert.facts, fact)
            policy_input.update(target=target, fact_targets=targets)
            if target is None or target not in targets:
                raise _Escalate(["target not in typed facts"], self._tainted(action, alert))

        if tier == Tier.OUTBOUND:
            self._t3(action, alert, policy_input, decision, registered)

        # 4. Policy (OPA, fixed Rego): every T1-T3 action.
        result = self.policy.decide(policy_input)
        if not result.allow:
            raise _Escalate([f"policy: {r}" for r in result.deny] or ["policy: denied"],
                            self._tainted(action, alert) if tier == Tier.SECURITY_REDUCING else [])

        # 5. Rate limit.
        if not self.limiter.hit(f"{self.pack.name}:t{int(tier)}:{action.tool}", self.pack.rate_limit(tier)):
            raise _Escalate(["rate limit"])
        decision.reasons.append(f"T{int(tier)} checks passed")
        return decision

    def _t0(self, action: ProposedAction, alert: Alert | None, state: _State, decision: GateDecision) -> None:
        try:
            within = self.limiter.hit(f"{self.pack.name}:t0:{action.alert_id or action.tool}",
                                      self.pack.rate_limit(Tier.ALWAYS_ALLOWED))
        except Exception as exc:  # T0 is always allowed; the limiter failing is logged, not fatal
            decision.reasons.append(f"rate limiter unavailable ({type(exc).__name__}); T0 allowed")
            within = True
        if not within:
            raise _Escalate(["rate limit: T0 flood (IOC)"])
        # Agent-written text is scanned for leaks and redacted (never blocked) before it is stored.
        text_args = {k: v for k, v in action.args.items() if k in self.pack.data.get("agent_text", {}).get(action.tool, [])}
        if text_args:
            try:
                scan = self.output_scanner.scan({k: str(v) for k, v in text_args.items()})
                decision.output_findings = scan.findings
                if any(f.action != "allow" for f in scan.findings):
                    decision.redacted_args = {**action.args, **scan.redacted}
            except NotConfigured as exc:
                decision.reasons.append(f"output scanner unavailable ({exc.what}); note stored unscanned")
        # Silent failure 24: a summary concluding "benign" must agree with the facts-only verdict.
        if alert is not None and action.tool in self.pack.data.get("summary_tools", []) and action.verdict == "benign":
            try:
                verdict = self.recheck(alert.facts).verdict
                state.recheck_verdict = decision.recheck_verdict = verdict
            except Exception as exc:  # a note is T0: flag it rather than block it
                verdict = f"unavailable: {type(exc).__name__}"
            if verdict != "benign":
                decision.reasons.append(f"summary conclusion disagrees with facts-only verdict ({verdict}); flagged")
                flagged = dict(decision.redacted_args or action.args)
                for key in self.pack.data.get("agent_text", {}).get(action.tool, []):
                    if key in flagged:
                        flagged[key] = f"[TrustGate: conclusion not confirmed by facts-only verdict ({verdict})] {flagged[key]}"
                decision.redacted_args = flagged
        decision.reasons.append("T0 allowed")

    def _t3(self, action: ProposedAction, alert: Alert, policy_input: dict[str, Any], decision: GateDecision,
            registered: RegisteredTool | None) -> None:
        recipient = value_match.recipient_of(self.pack, action.tool, action.args,
                                             registered.target_arg if registered else None)
        fields = value_match.outbound_fields(self.pack, action.tool, action.args)
        raw_ids = sorted({eid for text in fields.values() for eid in value_match.raw_evidence_in(text, alert)})
        scan = self.output_scanner.scan(fields)  # raises if no backend: T3 fails closed
        decision.output_findings = scan.findings
        policy_input.update(recipient=recipient, contains_raw_evidence=bool(raw_ids), output_entities=scan.entities)
        if raw_ids:
            raise _Escalate(["raw evidence in outbound payload"], raw_ids)
        if scan.blocked_entities:
            raise _Escalate([f"sensitive data in outbound payload: {', '.join(scan.blocked_entities)}"])
        if any(f.action == "redact" for f in scan.findings):
            decision.redacted_args = {**action.args, **scan.redacted}
            decision.reasons.append("outbound payload redacted: " + ", ".join(
                sorted({f.entity for f in scan.findings if f.action == "redact"})))

    @staticmethod
    def _citation_exists(citation: str, alert: Alert) -> bool:
        if citation.startswith("facts."):
            return citation.split(".", 1)[1] in _FACT_FIELDS
        return citation in alert.evidence_by_id()

    @staticmethod
    def _tainted(action: ProposedAction, alert: Alert) -> list[str]:
        """Evidence IDs that tipped the decision: cited untrusted items and detector hits."""
        by_id = alert.evidence_by_id()
        cited = {c for c in action.cited_evidence if c in by_id and by_id[c].trust == Trust.UNTRUSTED}
        flagged = {eid for s in alert.ioc_signals for eid in s.evidence_ids}
        ids = cited | flagged
        if not ids:  # the agent cited only facts: the whole untrusted context is suspect
            ids = {e.id for e in alert.evidence if e.trust == Trust.UNTRUSTED}
        return sorted(ids, key=lambda i: int(i.split("-")[1]))

    # --- execution and the analyst queue -----------------------------------------

    def execute(self, action: ProposedAction, decision: GateDecision) -> Any:
        """Run an allowed action (or any action in monitor mode) through its registered executor."""
        if not decision.permits_execution:
            raise ActionEscalated(decision)
        tool = self.tools.get(action.tool)
        if tool is None or tool.fn is None:
            raise ToolConfigError(f"no executor registered for {action.tool}")
        result = self._invoke(tool, action.alert_id, self._execution_args(action, decision))
        self.store.audit("execution", alert_id=action.alert_id, tool=action.tool,
                         details={"monitor": not decision.enforced, "would_block": decision.would_block,
                                  "audit_id": decision.audit_id})
        return result

    @staticmethod
    def _invoke(tool: RegisteredTool, alert_id: str, args: dict[str, Any]) -> Any:
        """Call an executor, supplying the action's alert_id when the tool takes one."""
        params = inspect.signature(tool.fn).parameters
        call_args = dict(args)
        if "alert_id" in params and "alert_id" not in call_args and alert_id:
            call_args["alert_id"] = alert_id
        return asyncio.run(tool.fn(**call_args)) if tool.is_async else tool.fn(**call_args)

    def resolve_escalation(self, escalation_id: str, *, approve: bool, analyst: str, reason: str) -> dict[str, Any]:
        esc = self.store.get_escalation(escalation_id)
        if esc is None or esc.status != "open":
            raise KeyError(escalation_id)
        if esc.canary:
            outcome = "canary_missed" if approve else "canary_caught"
            self.store.close_escalation(escalation_id, status="approved" if approve else "rejected",
                                        analyst=analyst, reason=reason, result={"canary": outcome})
            self.store.audit("analyst", alert_id=esc.alert_id, tool=esc.tool,
                             details={"escalation_id": escalation_id, "canary": outcome})
            return {"canary": outcome, "executed": False}
        result: Any = None
        if approve:
            action = ProposedAction.model_validate(esc.action)
            tool = self.tools.get(action.tool)
            if tool is None or tool.fn is None:
                raise ToolConfigError(f"no executor registered for {action.tool}")
            result = self._invoke(tool, action.alert_id, action.args)
        self.store.close_escalation(escalation_id, status="approved" if approve else "rejected", analyst=analyst,
                                    reason=reason, result={"result": result} if approve else None)
        self.store.audit("analyst", alert_id=esc.alert_id, tool=esc.tool,
                         details={"escalation_id": escalation_id, "approved": approve, "analyst": analyst,
                                  "reason": reason})
        return {"executed": approve, "result": result}

    def health(self) -> dict[str, Any]:
        checks: dict[str, Any] = {"pack": self.pack.name, "mode": self.mode,
                                  "policy": bool(getattr(self.policy, "healthy", lambda: False)())}
        try:
            checks["rate_limiter"] = self.limiter.hit("healthz", 10**9)
        except Exception as exc:
            checks["rate_limiter"] = f"unavailable: {type(exc).__name__}"
        return checks
