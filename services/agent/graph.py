r"""The SOC triage agent as a LangGraph graph, calling models through LiteLLM.

fetch -> triage (read-only tools loop) -> validate -> submit
                                       \-> retry once on invalid output, then escalate

The model is pinned (TRUSTGATE_AGENT_MODEL, a LiteLLM model string). Temperature
is sent only if TRUSTGATE_AGENT_TEMPERATURE is set: current Claude models reject
sampling parameters, so pin determinism there with the model version instead.
tool_choice is "auto" for the same reason (forced tool choice is rejected).
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, TypedDict

from langgraph.graph import END, START, StateGraph
from pydantic import ValidationError

from services.agent.tools_client import ToolsClient
from trustgate.config import NotConfigured, Settings
from trustgate.models import ProposedAction

READ_TOOLS = ("query_logs", "lookup_ioc")
ACTIONS = (
    ("escalate", 0), ("add_note", 0), ("raise_severity", 0),
    ("close_alert", 1), ("downgrade_severity", 1), ("whitelist_indicator", 1), ("suppress_rule", 1),
    ("block_ip", 2), ("isolate_host", 2), ("disable_account", 2),
    ("send_email", 3), ("post_webhook", 3),
)
# Each action's args (alert_id is filled in for you). Must match services/soc_tools.py: a test checks.
ACTION_ARGS: dict[str, tuple[str, ...]] = {
    "escalate": ("reason",), "add_note": ("text",), "raise_severity": ("severity",),
    "close_alert": ("reason",), "downgrade_severity": ("severity",),
    "whitelist_indicator": ("indicator", "reason", "ttl_hours"), "suppress_rule": ("rule", "reason", "ttl_hours"),
    "block_ip": ("ip",), "isolate_host": ("host",), "disable_account": ("account",),
    "send_email": ("to", "subject", "body"), "post_webhook": ("url", "payload"),
}
_ARG_HINTS = {"severity": "low|medium|high|critical", "ttl_hours": "number, at most 24"}
MAX_STEPS = 6

# A plain-text LLM prompt built from constants. The file's final newline is not part of the prompt.
_ACTION_MENU = "".join(
    f"   - {name} (T{tier}), args: "
    + ", ".join(f"{a} ({_ARG_HINTS[a]})" if a in _ARG_HINTS else a for a in ACTION_ARGS[name]) + "\n"
    for name, tier in ACTIONS)
SYSTEM_PROMPT = (
    (Path(__file__).parent / "prompts" / "system.txt").read_text(encoding="utf-8")
    .removesuffix("\n").replace("{action_menu}", _ACTION_MENU)
)

TOOLS: list[dict[str, Any]] = [
    {"type": "function", "function": {
        "name": "query_logs", "description": "Log lines related to the alert (untrusted data).",
        "parameters": {"type": "object", "properties": {}, "required": []}}},
    {"type": "function", "function": {
        "name": "lookup_ioc", "description": "Threat-intel scores for an IP address or URL.",
        "parameters": {"type": "object", "properties": {"indicator": {"type": "string"}}, "required": ["indicator"]}}},
    {"type": "function", "function": {
        "name": "propose_action",
        "description": "Finish triage: your verdict and exactly one action, citing evidence IDs and typed facts.",
        "parameters": {
            "type": "object",
            "properties": {
                "verdict": {"type": "string", "enum": ["malicious", "benign", "unsure"]},
                "tool": {"type": "string", "enum": [name for name, _ in ACTIONS]},
                "args": {"type": "object", "description": "Exactly the action's args from the menu, e.g. "
                                                          "{\"severity\": \"high\"} for raise_severity."},
                "cited_evidence": {"type": "array", "items": {"type": "string"}},
                "rationale": {"type": "string", "maxLength": 800},
            },
            "required": ["verdict", "tool", "args", "cited_evidence", "rationale"],
        }}},
]


def args_problem(tool: str, args: dict[str, Any]) -> str | None:
    """What is wrong with an action's args against ACTION_ARGS, or None. alert_id is always accepted."""
    expected = ACTION_ARGS.get(tool)
    if expected is None:
        return None  # the tool enum is checked by ProposedAction and the gate
    missing = [a for a in expected if a not in args]
    unexpected = sorted(set(args) - set(expected) - {"alert_id"})
    parts = ([f"missing: {', '.join(missing)}"] if missing else []) + \
            ([f"not allowed: {', '.join(unexpected)}"] if unexpected else [])
    return "; ".join(parts) or None


class AgentState(TypedDict, total=False):
    alert_id: str
    messages: list[dict[str, Any]]
    proposal: dict[str, Any] | None
    action: dict[str, Any] | None
    invalid_attempts: int
    steps: int
    outcome: dict[str, Any]
    tokens: int


def _completion_kwargs(settings: Settings) -> dict[str, Any]:
    if not settings.agent_model:
        raise NotConfigured("TRUSTGATE_AGENT_MODEL", "pin a LiteLLM model string and set its provider API key")
    kwargs: dict[str, Any] = {"model": settings.agent_model, "tools": TOOLS, "tool_choice": "auto"}
    temperature = os.environ.get("TRUSTGATE_AGENT_TEMPERATURE", "").strip()
    if temperature:
        kwargs["temperature"] = float(temperature)
    return kwargs


def build_graph(tools: ToolsClient, settings: Settings | None = None, *, completion=None):
    settings = settings or Settings()
    if completion is None:
        import litellm

        completion = litellm.completion

    def fetch(state: AgentState) -> AgentState:
        alert_text = tools.read("get_alert", {"alert_id": state["alert_id"]}, state["alert_id"])
        return {"messages": [{"role": "system", "content": SYSTEM_PROMPT},
                             {"role": "user", "content": alert_text}],
                "steps": 0, "invalid_attempts": 0, "proposal": None, "tokens": 0}

    def triage(state: AgentState) -> AgentState:
        messages = list(state["messages"])
        response = completion(messages=messages, **_completion_kwargs(settings))
        usage = getattr(response, "usage", None)
        tokens = state.get("tokens", 0) + int(getattr(usage, "total_tokens", 0) or 0)
        msg = response.choices[0].message
        calls = list(getattr(msg, "tool_calls", None) or [])
        messages.append({"role": "assistant", "content": msg.content or "", "tool_calls": [
            {"id": c.id, "type": "function", "function": {"name": c.function.name, "arguments": c.function.arguments}}
            for c in calls]} if calls else {"role": "assistant", "content": msg.content or ""})
        proposal = None
        for call in calls:
            try:
                args = json.loads(call.function.arguments or "{}")
            except json.JSONDecodeError:
                args = None
            if call.function.name == "propose_action" and isinstance(args, dict):
                proposal = args
                content = "received"
            elif call.function.name in READ_TOOLS and isinstance(args, dict):
                content = tools.read(call.function.name, args, state["alert_id"])
            else:
                content = "invalid tool call; finish with propose_action"
            messages.append({"role": "tool", "tool_call_id": call.id, "content": content})
        if not calls:
            messages.append({"role": "user", "content": "Finish by calling propose_action."})
        return {"messages": messages, "proposal": proposal, "steps": state["steps"] + 1, "tokens": tokens}

    def after_triage(state: AgentState) -> str:
        if state.get("proposal"):
            return "validate"
        return "give_up" if state["steps"] >= MAX_STEPS else "triage"

    def validate(state: AgentState) -> AgentState:
        try:
            action = ProposedAction(alert_id=state["alert_id"], **state["proposal"])
            problem = args_problem(action.tool, action.args)
            if problem is None:
                return {"action": action.model_dump(mode="json")}
            feedback = f"Your proposed action had the wrong args ({problem})."
        except (ValidationError, TypeError) as exc:
            feedback = f"Your proposed action was invalid ({type(exc).__name__})."
        messages = list(state["messages"]) + [{"role": "user", "content": f"{feedback} Call propose_action again."}]
        return {"action": None, "proposal": None, "messages": messages,
                "invalid_attempts": state.get("invalid_attempts", 0) + 1}

    def after_validate(state: AgentState) -> str:
        if state.get("action"):
            return "submit"
        return "give_up" if state.get("invalid_attempts", 0) > 1 else "triage"

    def submit(state: AgentState) -> AgentState:
        return {"outcome": tools.submit(ProposedAction.model_validate(state["action"]))}

    def give_up(state: AgentState) -> AgentState:
        action = ProposedAction(alert_id=state["alert_id"], verdict="unsure", tool="escalate",
                                args={"reason": "agent could not produce a valid action"})
        return {"action": action.model_dump(mode="json"), "outcome": tools.submit(action)}

    graph = StateGraph(AgentState)
    for name, fn in (("fetch", fetch), ("triage", triage), ("validate", validate), ("submit", submit), ("give_up", give_up)):
        graph.add_node(name, fn)
    graph.add_edge(START, "fetch")
    graph.add_edge("fetch", "triage")
    graph.add_conditional_edges("triage", after_triage, {"validate": "validate", "give_up": "give_up", "triage": "triage"})
    graph.add_conditional_edges("validate", after_validate, {"submit": "submit", "give_up": "give_up", "triage": "triage"})
    graph.add_edge("submit", END)
    graph.add_edge("give_up", END)
    return graph.compile()


def run_agent(alert_id: str, tools: ToolsClient, settings: Settings | None = None, *, completion=None) -> AgentState:
    return build_graph(tools, settings, completion=completion).invoke({"alert_id": alert_id},
                                                                      {"recursion_limit": 4 * MAX_STEPS + 10})
