"""Tool-calling adapter (OpenAI format). LiteLLM speaks this format for every
provider it routes to, including Anthropic, so one adapter covers both.

    schemas = tool_schemas(gate)                      # pass as tools=...
    for call in response.choices[0].message.tool_calls:
        content = dispatch(gate, call)                # -> role="tool" message content
"""

from __future__ import annotations

import json
from typing import Any

from trustgate.adapters._schema import args_model
from trustgate.gate import ESCALATED_MESSAGE, ActionEscalated, Gate, refusal_message


def tool_schemas(gate: Gate, names: list[str] | None = None) -> list[dict[str, Any]]:
    out = []
    for tool in gate.tools.values():
        if names is not None and tool.name not in names:
            continue
        out.append({
            "type": "function",
            "function": {
                "name": tool.name,
                "description": (tool.description or tool.name)[:1024],
                "parameters": args_model(tool).model_json_schema(),
            },
        })
    return out


def dispatch(gate: Gate, tool_call: Any) -> str:
    """Run one tool call through the gate; returns the tool message content."""
    function = tool_call["function"] if isinstance(tool_call, dict) else tool_call.function
    name = function["name"] if isinstance(function, dict) else function.name
    raw_args = function["arguments"] if isinstance(function, dict) else function.arguments
    try:
        kwargs = json.loads(raw_args or "{}")
    except json.JSONDecodeError:
        return ESCALATED_MESSAGE + " (arguments were not valid JSON)"
    if name not in gate.tools:
        return ESCALATED_MESSAGE + " (unknown tool)"
    try:
        result = gate.call(name, **kwargs)
    except ActionEscalated as exc:
        return refusal_message(exc.decision)
    return json.dumps(result, default=str)
