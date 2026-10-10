"""LangGraph adapter: gated tools as LangChain StructuredTools for a ToolNode.

    tools = langgraph_tools(gate)
    graph.add_node("tools", ToolNode(tools))

An escalated call returns the fixed escalation message to the model instead of
raising, so the graph keeps running.
"""

from __future__ import annotations

from typing import Any

from langchain_core.tools import StructuredTool

from trustgate.adapters._schema import args_model
from trustgate.gate import ESCALATED_MESSAGE, ActionEscalated, Gate


def _runner(gate: Gate, tool_name: str):
    def run(**kwargs: Any) -> Any:
        try:
            return gate.call(tool_name, **kwargs)
        except ActionEscalated:
            return ESCALATED_MESSAGE

    return run


def langgraph_tools(gate: Gate, names: list[str] | None = None) -> list[StructuredTool]:
    tools: list[StructuredTool] = []
    for tool in gate.tools.values():
        if names is not None and tool.name not in names:
            continue
        if tool.fn is None:
            continue
        tools.append(StructuredTool.from_function(
            func=_runner(gate, tool.name),
            name=tool.name,
            description=(tool.description or tool.name)[:1024],
            args_schema=args_model(tool),
        ))
    return tools
