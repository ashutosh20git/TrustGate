"""A tool call whose args cannot run the tool is blocked, never "allowed" (live-agent finding).

A real 3B agent proposed raise_severity with args={} and add_note with {"note": ...}: the gate
said allow and every call then failed with TypeError, so the audit recorded allows for actions
that never ran. The gate now checks args against the executor, and the agent is told each
action's args and retries with the exact problem.
"""

from __future__ import annotations

import dataclasses
import inspect
import json
from types import SimpleNamespace

from conftest import requires_opa

from services.agent.graph import ACTION_ARGS, ACTIONS, SYSTEM_PROMPT, args_problem, run_agent
from services.soc_tools import soc_tool_functions
from trustgate.gate import BLOCKED_MESSAGE, refusal_message
from trustgate.models import Alert, ProposedAction, TypedFacts


def _alert(store) -> Alert:
    alert = Alert(alert_id="A-1", source="email", severity="high", facts=TypedFacts(dmarc_pass=False), evidence=[])
    store.put_alert(alert)
    return alert


def _register(gate):
    def raise_severity(alert_id: str, severity: str) -> dict:
        return {"alert_id": alert_id, "severity": severity}

    def add_note(alert_id: str, text: str) -> dict:
        return {"alert_id": alert_id, "text": text}

    gate.register("raise_severity", 0, raise_severity)
    gate.register("add_note", 0, add_note)


def test_missing_arg_is_blocked_with_the_reason_and_not_queued(gate, store):
    _alert(store)
    _register(gate)
    d = gate.decide(ProposedAction(alert_id="A-1", verdict="unsure", tool="raise_severity", args={}))
    assert d.decision == "block"
    assert d.reasons == ["schema: invalid arguments for raise_severity (missing: severity)"]
    assert d.escalation_id is None and store.escalations("open") == []  # approving it could not run it
    assert refusal_message(d) == BLOCKED_MESSAGE


def test_wrong_arg_name_is_blocked(gate, store):
    _alert(store)
    _register(gate)
    d = gate.decide(ProposedAction(alert_id="A-1", verdict="unsure", tool="add_note",
                                   args={"note": "x", "ttl_hours": 24}))
    assert d.decision == "block"
    assert d.reasons == ["schema: invalid arguments for add_note (missing: text; unexpected: note, ttl_hours)"]


@requires_opa
def test_correct_args_still_allow_and_run(gate, store):
    _alert(store)
    _register(gate)
    action = ProposedAction(alert_id="A-1", verdict="malicious", tool="raise_severity", args={"severity": "critical"})
    d = gate.decide(action)
    assert d.decision == "allow"
    assert gate.execute(action, d) == {"alert_id": "A-1", "severity": "critical"}


def test_agent_arg_table_matches_the_real_tools():
    tools = soc_tool_functions(client=None, store=None)
    for name, _tier in ACTIONS:
        params = [p for p in inspect.signature(tools[name]).parameters if p != "alert_id"]
        assert tuple(params) == ACTION_ARGS[name], name


def test_prompt_lists_each_actions_args():
    assert "raise_severity (T0), args: severity (low|medium|high|critical)" in SYSTEM_PROMPT
    assert "add_note (T0), args: text" in SYSTEM_PROMPT


def test_args_problem():
    assert args_problem("raise_severity", {"severity": "high"}) is None
    assert args_problem("raise_severity", {"severity": "high", "alert_id": "A-1"}) is None
    assert args_problem("add_note", {"note": "x"}) == "missing: text; not allowed: note"


class _Tools:
    def __init__(self):
        self.submitted: list[ProposedAction] = []

    def read(self, tool, args, alert_id):
        return "alert text"

    def submit(self, action):
        self.submitted.append(action)
        return {"decision": {"decision": "allow"}}


def _proposal(args: dict) -> SimpleNamespace:
    call = SimpleNamespace(id="c1", function=SimpleNamespace(name="propose_action", arguments=json.dumps(
        {"verdict": "unsure", "tool": "raise_severity", "args": args, "cited_evidence": [], "rationale": ""})))
    return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content="", tool_calls=[call]))],
                           usage=None)


def test_agent_retries_with_the_exact_arg_problem(settings):
    settings = dataclasses.replace(settings, agent_model="test/model")
    replies = iter([_proposal({}), _proposal({"severity": "high"})])
    seen: list[list[dict]] = []

    def completion(messages, **_):
        seen.append(list(messages))
        return next(replies)

    tools = _Tools()
    run_agent("A-1", tools, settings, completion=completion)
    assert "wrong args (missing: severity)" in seen[1][-1]["content"]
    assert [a.args for a in tools.submitted] == [{"severity": "high"}]
