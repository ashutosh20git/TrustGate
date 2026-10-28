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
import datetime as dt
import functools
import inspect
import math
import threading
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
from trustgate.evidence_floor import t1_evidence
from trustgate.ingest.decode import SCAN_TEXT_LIMIT
from trustgate.models import Alert, GateDecision, ProposedAction, Trust, TypedFacts, Verdict
from trustgate.ingest.decode import rot13
from trustgate.output_scan import OutputScanner, ScanResult, regex_findings
from trustgate.policy_client import PolicyPack, load_pack, policy_client
from trustgate.provenance import stamp_for
from trustgate.ratelimit import rate_limiter
from trustgate.recheck import RecheckResult, as_recheck, facts_only_recheck
from trustgate.store import ActionRecord, Escalation, Store
from trustgate.tiers import Tier, UnknownTool

log = structlog.get_logger("trustgate.gate")
tracer = trace.get_tracer("trustgate")

# Fixed text returned to the agent: no evidence content can leak through errors (silent failure 17).
ESCALATED_MESSAGE = "Action not executed: TrustGate escalated it to a human analyst."
BLOCKED_MESSAGE = "Action not executed: its arguments do not match the tool. Check the tool's arguments and try again."


def refusal_message(decision: GateDecision) -> str:
    """The fixed text an agent gets for an action that did not run."""
    return BLOCKED_MESSAGE if decision.decision == "block" else ESCALATED_MESSAGE
RESERVED_ARGS = ("verdict", "cited_evidence", "rationale")
_FACT_FIELDS = set(TypedFacts.model_fields)


def _argument_problem(fn: Callable[..., Any], args: dict[str, Any]) -> str | None:
    """Why `args` cannot call `fn`, or None. alert_id is optional: _invoke supplies it."""
    try:
        params = inspect.signature(fn).parameters.values()
    except (TypeError, ValueError):
        return None  # no inspectable signature (a builtin): leave it to execution
    named = {p.name: p for p in params if p.kind in (p.POSITIONAL_OR_KEYWORD, p.KEYWORD_ONLY)}
    missing = sorted(n for n, p in named.items() if p.default is p.empty and n != "alert_id" and n not in args)
    takes_any = any(p.kind == p.VAR_KEYWORD for p in params)
    unexpected = [] if takes_any else sorted(n[:40] for n in set(args) - set(named))
    parts = ([f"missing: {', '.join(missing)}"] if missing else []) + \
            ([f"unexpected: {', '.join(unexpected[:5])}"] if unexpected else [])
    return "; ".join(parts) or None


class ActionEscalated(Exception):
    def __init__(self, decision: GateDecision):
        super().__init__(ESCALATED_MESSAGE)
        self.decision = decision


class ToolConfigError(ValueError):
    pass


class ApprovalRefused(Exception):
    """An analyst approval the gate will not execute (expired, changed since escalation, one approver)."""


class ApprovalExecutionFailed(Exception):
    """An approved action whose executor raised. The escalation is closed as failed, never left open."""


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
        # Reverse actions (unblock, release, reopen...). Never in self.tools: the agent
        # cannot call them; only an analyst revert or an automatic rollback can.
        self.undo_tools: dict[str, Callable[..., Any]] = {}
        # Checks run on a bounded pool. A check that times out keeps its slot until
        # it really finishes, so hung dependencies show up as saturation and new
        # decisions fail closed at once instead of queueing behind them.
        self.max_inflight = max(1, self.settings.max_inflight_checks)
        self._pool = ThreadPoolExecutor(max_workers=self.max_inflight, thread_name_prefix="trustgate-check")
        self._slots = threading.BoundedSemaphore(self.max_inflight)
        self._counter_lock = threading.Lock()
        self._inflight = 0
        self._abandoned = 0
        self._alert_ctx: contextvars.ContextVar[Alert | None] = contextvars.ContextVar("trustgate_alert", default=None)
        # Outbound text already let through per alert: a secret split across messages is checked
        # as a whole. In memory, per process (bounded); see docs/BENCHMARKS.md.
        self._sent: dict[str, list[str]] = {}
        self._sent_lock = threading.Lock()

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
                    args = self._execution_args(action, decision)
                    result = await fn(**args)
                    self._record_action(action, decision.tier, args, via="gate")
                    return result

                return async_wrapper

            @functools.wraps(fn)
            def wrapper(*args, **kwargs):
                action = self._build_or_escalate(build, args, kwargs, tool_name)
                decision = self.decide(action, self._alert_ctx.get())
                if not decision.permits_execution:
                    raise ActionEscalated(decision)
                args = self._execution_args(action, decision)
                result = fn(**args)
                self._record_action(action, decision.tier, args, via="gate")
                return result

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
            decision = self._run_with_watchdog(action, alert, mcp, state)
            span.set_attribute("trustgate.decision", decision.decision)
        return self._finish(decision, action, start)

    def _run_with_watchdog(self, action: ProposedAction, alert: Alert | None, mcp: dict[str, Any] | None,
                           state: _State) -> GateDecision:
        if not self._slots.acquire(blocking=False):
            return self._fail_closed(state, "GateSaturated")
        abandoned = threading.Event()
        with self._counter_lock:
            self._inflight += 1

        def release(_future) -> None:
            with self._counter_lock:
                self._inflight -= 1
                if abandoned.is_set():
                    self._abandoned -= 1
            self._slots.release()

        try:
            future = self._pool.submit(self._checks, action, alert, mcp, state)
        except Exception as exc:
            release(None)
            return self._fail_closed(state, type(exc).__name__, exc)
        future.add_done_callback(release)
        try:
            return future.result(timeout=self.timeout_s)
        except FutureTimeout:
            if not future.cancel():  # still running: it holds its slot until it ends
                with self._counter_lock:
                    if not future.done():
                        abandoned.set()
                        self._abandoned += 1
            return self._fail_closed(state, "TimeoutError")
        except Exception as exc:  # the watchdog: any error escalates
            return self._fail_closed(state, type(exc).__name__, exc)

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
        if action is not None and decision.decision == "escalate" and decision.enforced:
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

    def _other_t1_causes(self, action: ProposedAction, alert: Alert) -> list[str]:
        """The T1 checks after the re-check that would also fail, for the analyst's explanation."""
        out: list[str] = []
        if alert.ai_evasion_attempt:
            out.append("T1: AI-evasion attempt on this alert")
        if action.verdict == "benign":
            if not any(c.startswith("facts.") for c in action.cited_evidence):
                out.append("no typed-fact citation")
            evidence = t1_evidence(alert.facts, alert.source, self.pack.floor.get("t1_evidence"), action.cited_evidence)
            out += evidence.reasons()
        return out

    def _run_checks(self, action: ProposedAction, alert: Alert | None, mcp: dict[str, Any] | None,
                    state: _State) -> GateDecision:
        # 1. Which tier? (static map; unknown tool escalates)
        try:
            tier = self.tier_of(action.tool)
        except UnknownTool:
            raise _Escalate(["unknown tool"]) from None
        state.tier = int(tier)

        # 1b. Schema: the arguments fit the executor. A call that cannot run is never "allowed", and
        #     is blocked rather than escalated: approving it could not run it either.
        registered = self.tools.get(action.tool)
        if registered is not None and registered.fn is not None:
            problem = _argument_problem(registered.fn, action.args)
            if problem:
                return GateDecision(decision="block", tier=int(tier),
                                    reasons=[f"schema: invalid arguments for {action.tool} ({problem})"])

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
                # The judges' reasons (low confidence, scorecard warnings) are for the analyst only,
                # with every other T1 check that would also fail: a bare "0.82 below 0.90" does not
                # tell the analyst what is wrong (docs/BENCHMARKS.md, explanation accuracy).
                raise _Escalate([f"facts and text disagree: agent={action.verdict}, facts-only={result.verdict}"]
                                + [f"re-check: {r}" for r in result.reasons[:4]]
                                + self._other_t1_causes(action, alert),
                                self._tainted(action, alert))
            if not any(c.startswith("facts.") for c in action.cited_evidence):
                raise _Escalate(["no typed-fact citation"], self._tainted(action, alert))
            evidence = t1_evidence(alert.facts, alert.source, self.pack.floor.get("t1_evidence"),
                                   action.cited_evidence)
            policy_input["t1_evidence"] = evidence.policy_input()
            if evidence.reasons():
                raise _Escalate(evidence.reasons(), self._tainted(action, alert))
            scope = self._expiry_scope(action)
            policy_input["scope"] = {k: v for k, v in scope.items() if k != "reason"}
            if not scope["ok"]:
                raise _Escalate([scope["reason"]])
            history = self._history(alert.alert_id)
            policy_input["history"] = history
            max_t1 = int(self.pack.floor.get("sequence", {}).get("max_t1_per_alert", 1))
            if history["t1_executed"] >= max_t1:
                raise _Escalate([f"sequence: {', '.join(history['tools'][:3])} already ran on this alert; "
                                 "another security-reducing action needs a human"], self._tainted(action, alert))

        if tier == Tier.DISRUPTIVE:
            target, fact = value_match.target_of(self.pack, action.tool, action.args,
                                                  registered.target_arg if registered else None)
            targets = value_match.fact_targets(alert.facts, fact)
            policy_input.update(target=target, fact_targets=targets, target_evidence_ok=False)
            if target is None or target not in targets:
                raise _Escalate(["target not in typed facts"], self._tainted(action, alert))
            # Being in the alert is not enough: the target itself must be shown to be bad, or an
            # attacker who gets a partner's IP or a victim's host into an alert gets it disrupted.
            spec = self.pack.target_spec(action.tool) or {}
            if spec.get("evidence_fact") and target not in value_match.fact_targets(alert.facts, spec["evidence_fact"]):
                raise _Escalate([f"T2: the target has no threat evidence of its own (facts.{spec['evidence_fact']})"],
                                self._tainted(action, alert))
            if spec.get("sources") and alert.source not in spec["sources"]:
                # A host that merely *received* a phishing email is not shown to be compromised:
                # isolation needs an alert about the host itself (EDR), not one that names it.
                raise _Escalate([f"T2: {action.tool} needs an alert about the target itself "
                                 f"(source {', '.join(spec['sources'])}), not a {alert.source} alert"],
                                self._tainted(action, alert))
            if spec.get("requires_verdict"):
                result = self.recheck(alert.facts)
                state.recheck_verdict, state.recheck_tokens = result.verdict, result.tokens
                decision.recheck_verdict, decision.recheck_tokens = result.verdict, result.tokens
                if result.verdict != spec["requires_verdict"]:
                    raise _Escalate([f"T2: the facts do not show compromise (facts-only verdict {result.verdict})"],
                                    self._tainted(action, alert))
            policy_input["target_evidence_ok"] = True

        if tier == Tier.OUTBOUND:
            self._t3(action, alert, policy_input, decision, registered)

        # 4. Policy (OPA, fixed Rego): every T1-T3 action.
        result = self.policy.decide(policy_input)
        if not result.allow:
            raise _Escalate([f"policy: {r}" for r in result.deny] or ["policy: denied"],
                            self._tainted(action, alert) if tier == Tier.SECURITY_REDUCING else [])

        # 5. Rate limit, per tool and, for campaigns, per sender domain.
        if not self.limiter.hit(f"{self.pack.name}:t{int(tier)}:{action.tool}", self.pack.rate_limit(tier)):
            raise _Escalate(["rate limit"])
        campaign = self.pack.campaign_limit(tier)
        if campaign is not None:
            limit, window_s = campaign
            for kind, key in self._campaign_keys(alert.facts):
                if not self.limiter.hit(f"{self.pack.name}:t{int(tier)}:{kind}:{key}", limit, window_s):
                    raise _Escalate([f"campaign rate limit: over {limit} T{int(tier)} actions for one {kind} "
                                     f"in {window_s // 60} min"])
        if tier == Tier.OUTBOUND:
            self._remember_sent(alert.alert_id, value_match.outbound_fields(self.pack, action.tool,
                                                                            decision.redacted_args or action.args))
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
            # Text the agent writes after reading manipulated evidence is stored with
            # that provenance, so whoever reads it later (an analyst, another agent)
            # does not take it as a clean, trusted summary.
            if alert is not None and (alert.ai_evasion_attempt or alert.ioc_signals):
                ids = sorted({eid for sig in alert.ioc_signals for eid in sig.evidence_ids},
                             key=lambda i: int(i.split("-")[1]) if i.split("-")[-1].isdigit() else 0)
                tag = ("[TrustGate provenance: written by the AI agent after reading evidence flagged as "
                       f"AI-evasion{' (' + ', '.join(ids[:5]) + ')' if ids else ''}; treat as untrusted] ")
                tagged = dict(decision.redacted_args or action.args)
                for key in text_args:
                    tagged[key] = tag + str(tagged[key])
                decision.redacted_args = tagged
                decision.reasons.append("agent text tagged with untrusted provenance")
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
        if any(len(text) > SCAN_TEXT_LIMIT for text in fields.values()):
            raise _Escalate([f"outbound payload over {SCAN_TEXT_LIMIT} characters cannot be fully scanned"])
        raw_ids = sorted({eid for text in fields.values() for eid in value_match.raw_evidence_in(text, alert)})
        restated = sorted({eid for text in fields.values() for eid in value_match.restated_evidence_in(text, alert)}
                          - set(raw_ids))
        scan, hidden = self._outbound_scan(fields)  # raises if no backend: T3 fails closed
        decision.output_findings = scan.findings
        policy_input.update(recipient=recipient, contains_raw_evidence=bool(raw_ids or restated),
                            output_entities=sorted(set(scan.entities) | set(hidden)))
        if raw_ids:
            raise _Escalate(["raw evidence in outbound payload"], raw_ids)
        if restated:
            raise _Escalate(["untrusted evidence restated in outbound payload"], restated)
        if scan.blocked_entities:
            raise _Escalate([f"sensitive data in outbound payload: {', '.join(scan.blocked_entities)}"])
        if hidden:
            raise _Escalate([f"sensitive data hidden by encoding in outbound payload: {', '.join(hidden)}"])
        leaked = self._leaked_secrets(alert, fields)
        if leaked:
            raise _Escalate([f"sensitive value from this alert's evidence in outbound text (transformed or split "
                             f"across messages): {', '.join(leaked)}"])
        if any(f.action == "redact" for f in scan.findings):
            decision.redacted_args = {**action.args, **scan.redacted}
            decision.reasons.append("outbound payload redacted: " + ", ".join(
                sorted({f.entity for f in scan.findings if f.action == "redact"})))
        # Provenance survives the hand-off: a receiving agent's gate learns this alert was manipulated.
        stamp = stamp_for(alert, self.pack.name, self.settings.provenance_key)
        if stamp and fields:
            body_arg = list(fields)[-1]  # body_args list the body last (subject, body)
            args = dict(decision.redacted_args or action.args)
            args[body_arg] = f"{args[body_arg]}\n\n{stamp}"
            decision.redacted_args = args
            decision.reasons.append("provenance stamp added")

    def _leaked_secrets(self, alert: Alert, fields: dict[str, str]) -> list[str]:
        """Floor-blocked values from this alert's own evidence, recoverable from this message together
        with everything already sent for the alert (reversed, spelled out, interleaved, split)."""
        secrets = value_match.sensitive_values(alert, set(self.pack.block_entities))
        if not secrets or not fields:
            return []
        with self._sent_lock:
            prior = list(self._sent.get(alert.alert_id, []))
        return value_match.leaked_values(prior + list(fields.values()), secrets)

    def _remember_sent(self, alert_id: str, fields: dict[str, str]) -> None:
        with self._sent_lock:
            history = self._sent.setdefault(alert_id, [])
            history.extend(fields.values())
            del history[:-50]  # bounded per alert
            if len(self._sent) > 10_000:
                self._sent.pop(next(iter(self._sent)))

    def _campaign_keys(self, facts: TypedFacts) -> list[tuple[str, str]]:
        """What links alerts of one campaign even across sender domains: the sender domain, the
        link domains, the attachment hashes and near-duplicate body keys. Shared providers are skipped."""
        keys: list[tuple[str, str]] = []
        if facts.sender_domain and facts.sender_domain not in self.pack.shared_sender_domains:
            keys.append(("sender domain", facts.sender_domain))
        keys += [("link domain", d) for d in facts.url_domains if d not in self.pack.shared_url_domains]
        keys += [("attachment", h) for h in facts.ioc_hashes]
        keys += [("near-duplicate body", b) for b in facts.content_bands]
        return keys

    def _expiry_scope(self, action: ProposedAction) -> dict[str, Any]:
        spec = self.pack.expiry_spec(action.tool)
        if not spec:
            return {"required": False, "ok": True}
        arg, max_hours = spec["ttl_arg"], float(spec["max_hours"])
        try:
            ttl = float(action.args.get(arg))
        except (TypeError, ValueError):
            ttl = None
        ok = ttl is not None and math.isfinite(ttl) and 0 < ttl <= max_hours
        return {"required": True, "ok": ok, "ttl_hours": ttl if ok else None, "max_hours": max_hours,
                "reason": f"T1: {action.tool} changes more than this alert; it needs {arg} in (0, {max_hours:g}] hours"}

    def _outbound_scan(self, fields: dict[str, str]) -> tuple[ScanResult, list[str]]:
        """Scan outbound text as written and as decoded. Returns (scan of the text as written,
        non-allowed entities found only after decoding). Encoded data cannot be redacted in
        place, so anything sensitive hidden that way escalates instead."""
        scan = self.output_scanner.scan(fields)
        seen = {(f.arg, f.entity) for f in scan.findings}
        decoded = {arg: value_match.outbound_view(text) for arg, text in fields.items()}
        changed = {arg: text for arg, text in decoded.items() if text != fields[arg]}
        hidden = {f.entity for f in (self.output_scanner.scan(changed).findings if changed else [])
                  if f.action != "allow" and (f.arg, f.entity) not in seen}
        # ROT13 never reads as English for a key, so it is checked for secrets by pattern only
        # (running name detection over ROT13 gibberish would invent people and places).
        for arg, text in decoded.items():
            plain = {entity for entity, *_ in regex_findings(text)}  # e.g. PAN/IBAN shapes survive ROT13
            for entity, *_ in regex_findings(rot13(text)):
                if (entity not in plain and self.output_scanner.action_for(entity) != "allow"
                        and (arg, entity) not in seen):
                    hidden.add(entity)
        return scan, sorted(hidden)

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
        args = self._execution_args(action, decision)
        result = self._invoke(tool, action.alert_id, args)
        self.store.audit("execution", alert_id=action.alert_id, tool=action.tool,
                         details={"monitor": not decision.enforced, "would_block": decision.would_block,
                                  "audit_id": decision.audit_id})
        self._record_action(action, decision.tier, args, via="gate")
        return result

    # --- action ledger and rollback --------------------------------------------------

    def register_undo(self, name: str, fn: Callable[..., Any]) -> None:
        """Executor for a reverse action named in the pack's "undo" map (e.g. unblock_ip)."""
        self.undo_tools[name] = fn

    def _record_action(self, action: ProposedAction, tier: int | None, args: dict[str, Any], *,
                       via: str) -> ActionRecord | None:
        """Ledger every executed T1/T2 action with its reverse. T0 changes nothing; T3 cannot be unsent."""
        if tier not in (int(Tier.SECURITY_REDUCING), int(Tier.DISRUPTIVE)):
            return None
        spec = self.pack.undo_spec(action.tool) or {}
        undo_args: dict[str, Any] = {}
        if spec:
            alert = self.store.get_alert(action.alert_id) if action.alert_id else None
            for undo_arg, source in spec.get("args", {}).items():
                if source == "$alert_severity":
                    undo_args[undo_arg] = alert.severity if alert else None
                else:
                    undo_args[undo_arg] = args.get(source)
        undo_tool = spec.get("tool")
        if undo_tool and "/" in action.tool:  # MCP alias: the reverse lives on the same server
            undo_tool = f"{action.tool.split('/', 1)[0]}/{undo_tool}"
        return self.store.record_action(ActionRecord(alert_id=action.alert_id, tool=action.tool, tier=int(tier),
                                                     args=dict(args), via=via, undo_tool=undo_tool,
                                                     undo_args=undo_args))

    def revert(self, action_id: str, *, by: str, reason: str) -> ActionRecord:
        """Run an executed action's reverse. Raises KeyError, or ToolConfigError if it cannot be undone."""
        rec = self.store.get_action(action_id)
        if rec is None or rec.status != "executed":
            raise KeyError(action_id)
        name = rec.undo_tool or ""
        fn = self.undo_tools.get(name) or self.undo_tools.get(name.split("/", 1)[-1])
        if fn is None:
            raise ToolConfigError(f"no reverse action registered for {rec.tool}")
        try:
            self._invoke(RegisteredTool(name=name, tier=Tier.ALWAYS_ALLOWED, fn=fn), rec.alert_id, rec.undo_args)
            rec.status = "reverted"
        except Exception as exc:
            rec.status = "revert_failed"
            reason = f"{reason} (revert failed: {type(exc).__name__})"
        rec.reverted_at = dt.datetime.now(dt.timezone.utc)
        rec.reverted_by, rec.revert_reason = by, reason
        self.store.update_action(rec)
        self.store.audit("revert", alert_id=rec.alert_id, tool=rec.tool,
                         details={"action_id": rec.id, "undo_tool": rec.undo_tool, "status": rec.status,
                                  "by": by, "reason": reason})
        return rec

    def revert_alert(self, alert_id: str, *, reason: str, tiers: tuple[int, ...] = (int(Tier.SECURITY_REDUCING),),
                     by: str = "trustgate:auto") -> list[ActionRecord]:
        """Automatic rollback: a later signal contradicts what the action assumed (e.g. the alert
        turned out to be manipulated), so undo its security-reducing actions."""
        out: list[ActionRecord] = []
        for rec in self.store.actions(alert_id, status="executed"):
            if rec.tier in tiers and rec.undo_tool:
                try:
                    out.append(self.revert(rec.id, by=by, reason=reason))
                except (KeyError, ToolConfigError) as exc:
                    self.store.audit("revert", alert_id=alert_id, tool=rec.tool,
                                     details={"action_id": rec.id, "status": "not_reverted", "by": by,
                                              "reason": f"{reason} ({type(exc).__name__})"})
        return out

    def _history(self, alert_id: str) -> dict[str, Any]:
        window = int(self.pack.floor.get("sequence", {}).get("window_s", 86400))
        since = dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=window)
        recs = self.store.actions(alert_id, status="executed", since=since) if alert_id else []
        return {"t1_executed": sum(1 for r in recs if r.tier == 1), "t2_executed": sum(1 for r in recs if r.tier == 2),
                "tools": [r.tool for r in recs]}

    @staticmethod
    def _invoke(tool: RegisteredTool, alert_id: str, args: dict[str, Any]) -> Any:
        """Call an executor, supplying the action's alert_id when the tool takes one."""
        params = inspect.signature(tool.fn).parameters
        call_args = dict(args)
        if "alert_id" in params and "alert_id" not in call_args and alert_id:
            call_args["alert_id"] = alert_id
        return asyncio.run(tool.fn(**call_args)) if tool.is_async else tool.fn(**call_args)

    def resolve_escalation(self, escalation_id: str, *, approve: bool, analyst: str, reason: str,
                           second_analyst: str | None = None) -> dict[str, Any]:
        esc = self.store.get_escalation(escalation_id)
        if esc is None or esc.status != "open":
            raise KeyError(escalation_id)
        if not (analyst or "").strip():
            raise ApprovalRefused("an analyst identity is required")
        if esc.canary:
            outcome = "canary_missed" if approve else "canary_caught"
            self.store.close_escalation(escalation_id, status="approved" if approve else "rejected",
                                        analyst=analyst, reason=reason, result={"canary": outcome})
            self.store.audit("analyst", alert_id=esc.alert_id, tool=esc.tool,
                             details={"escalation_id": escalation_id, "canary": outcome})
            return {"canary": outcome, "executed": False}
        result: Any = None
        if approve:
            # An approval is checked again when it is used: the world may have moved
            # on since the escalation was raised, and one person is not enough for
            # disruptive or outbound actions.
            action = ProposedAction.model_validate(esc.action)
            try:
                tool = self._approval_executor(esc, action, analyst, second_analyst)
                args = self._approved_args(action, esc)
            except ApprovalRefused as refused:
                self.store.audit("analyst", alert_id=esc.alert_id, tool=esc.tool,
                                 details={"escalation_id": escalation_id, "approved": False, "refused": str(refused),
                                          "analyst": analyst, "second_analyst": second_analyst})
                raise
            try:
                result = self._invoke(tool, action.alert_id, args)
            except Exception as exc:
                # The tool may have partly run, so the escalation is not left open
                # for a silent retry: it is closed as failed and audited, and the
                # agent must propose the action again.
                error = type(exc).__name__
                self.store.close_escalation(escalation_id, status="failed", analyst=analyst, reason=reason,
                                            result={"error": error})
                self.store.audit("execution_failed", alert_id=esc.alert_id, tool=esc.tool,
                                 details={"escalation_id": escalation_id, "error": error, "analyst": analyst,
                                          "second_analyst": second_analyst})
                raise ApprovalExecutionFailed(f"approved action failed to execute ({error}); "
                                              "escalation closed as failed") from None
            self._record_action(action, esc.tier, args, via="approval")
        self.store.close_escalation(escalation_id, status="approved" if approve else "rejected", analyst=analyst,
                                    reason=reason, result={"result": result} if approve else None)
        self.store.audit("analyst", alert_id=esc.alert_id, tool=esc.tool,
                         details={"escalation_id": escalation_id, "approved": approve, "analyst": analyst,
                                  "second_analyst": second_analyst, "reason": reason})
        return {"executed": approve, "result": result}

    def _approval_executor(self, esc: Escalation, action: ProposedAction, analyst: str,
                           second_analyst: str | None) -> RegisteredTool:
        created = esc.created_at if esc.created_at.tzinfo else esc.created_at.replace(tzinfo=dt.timezone.utc)
        age_s = (dt.datetime.now(dt.timezone.utc) - created).total_seconds()
        if age_s > self.settings.escalation_ttl_s:
            self.store.close_escalation(esc.id, status="expired", analyst=analyst,
                                        reason=f"approval after {int(age_s)} s; limit {int(self.settings.escalation_ttl_s)} s")
            raise ApprovalRefused("escalation expired; the agent must propose the action again")
        try:
            tier = self.tier_of(action.tool)
        except UnknownTool:
            raise ApprovalRefused("tool is no longer in the policy pack") from None
        if esc.tier is not None and int(tier) != esc.tier:
            raise ApprovalRefused(f"tool tier changed since escalation (T{esc.tier} -> T{int(tier)})")
        if "/" in action.tool:
            server, name = action.tool.split("/", 1)
            pin = self.store.get_pin(server, name)
            if pin is not None and pin.status != "pinned":
                raise ApprovalRefused(f"MCP tool is {pin.status} since escalation")
        if tier >= Tier.DISRUPTIVE:
            second = (second_analyst or "").strip().lower()
            if not second or second == analyst.strip().lower():
                raise ApprovalRefused(f"T{int(tier)} approvals need a second, different analyst")
        tool = self.tools.get(action.tool)
        if tool is None or tool.fn is None:
            raise ToolConfigError(f"no executor registered for {action.tool}")
        return tool

    def _approved_args(self, action: ProposedAction, esc: Escalation) -> dict[str, Any]:
        """T3 payloads are scanned again: floor-blocked data never leaves, approved or not."""
        if esc.tier != int(Tier.OUTBOUND):
            return action.args
        fields = value_match.outbound_fields(self.pack, action.tool, action.args)
        if any(len(text) > SCAN_TEXT_LIMIT for text in fields.values()):
            raise ApprovalRefused("outbound payload is too large to scan")
        try:
            scan, hidden = self._outbound_scan(fields)
        except NotConfigured as exc:
            raise ApprovalRefused(f"output scanner unavailable ({exc.what}); outbound approval fails closed") from None
        blocked = sorted(set(scan.blocked_entities) | {e for e in hidden if self.output_scanner.action_for(e) == "block"})
        alert = self.store.get_alert(action.alert_id)
        if alert is not None:
            blocked = sorted(set(blocked) | set(self._leaked_secrets(alert, fields)))
        if blocked:
            raise ApprovalRefused(f"{', '.join(blocked)} may never leave, even with approval")
        if any(f.action == "redact" for f in scan.findings):
            return {**action.args, **scan.redacted}
        return action.args

    def health(self) -> dict[str, Any]:
        with self._counter_lock:
            inflight, abandoned = self._inflight, self._abandoned
        checks: dict[str, Any] = {"pack": self.pack.name, "mode": self.mode,
                                  "policy": bool(getattr(self.policy, "healthy", lambda: False)()),
                                  "checks_inflight": inflight, "checks_abandoned": abandoned,
                                  "saturated": inflight >= self.max_inflight}
        try:
            checks["rate_limiter"] = self.limiter.hit("healthz", 10**9)
        except Exception as exc:
            checks["rate_limiter"] = f"unavailable: {type(exc).__name__}"
        return checks
