"""MCP gateway (v2): a proxy in front of any MCP server, with tool pinning.

    python -m trustgate.mcp.gateway --server-name mock-soc --policy packs/soc.rego -- <upstream command...>

The agent connects to the gateway instead of the upstream server; its code does
not change. The gateway:
  * lists only tools whose pin is intact, serving the pinned description;
  * re-checks the live description on every call, so a rug pull between list and
    call disables the tool;
  * adds verdict / cited_evidence / rationale / alert_id to each gated tool's
    schema and sends every call through the TrustGate decision before forwarding.
"""

from __future__ import annotations

import argparse
import asyncio
import copy
import os
import sys
from typing import Any

import anyio
import structlog
from mcp import ClientSession, StdioServerParameters
from mcp import types
from mcp.client.stdio import stdio_client
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server
from pydantic import ValidationError

from trustgate import __version__
from trustgate.config import Settings
from trustgate.detector import Detector
from trustgate.gate import ESCALATED_MESSAGE, RESERVED_ARGS, Gate
from trustgate.mcp.pinning import ToolPinRegistry
from trustgate.models import ProposedAction
from trustgate.tiers import UnknownTool

log = structlog.get_logger("trustgate.mcp")


def augment_schema(schema: dict[str, Any] | None, tier: int | None) -> dict[str, Any]:
    out = copy.deepcopy(schema) if schema else {}
    out.setdefault("type", "object")
    props = out.setdefault("properties", {})
    props.setdefault("alert_id", {"type": "string", "description": "ID of the alert this action is about."})
    if tier is None or tier >= 1:
        props["verdict"] = {"type": "string", "enum": ["malicious", "benign", "unsure"],
                            "description": "Your verdict on the alert."}
        props["cited_evidence"] = {"type": "array", "items": {"type": "string"},
                                   "description": "Evidence IDs (ev-N) and typed facts (facts.<name>) that justify this action."}
        props["rationale"] = {"type": "string", "maxLength": 800}
        out["required"] = sorted(set(out.get("required", [])) | {"alert_id", "verdict", "cited_evidence"})
    return out


def _error(text: str) -> types.CallToolResult:
    return types.CallToolResult(content=[types.TextContent(type="text", text=text)], is_error=True)


class Gateway:
    def __init__(self, upstream: ClientSession, server_name: str, gate: Gate, registry: ToolPinRegistry):
        self.upstream = upstream
        self.server_name = server_name
        self.gate = gate
        self.registry = registry

    def gate_name(self, tool: str) -> str:
        return f"{self.server_name}/{tool}"

    def _tier(self, tool: str) -> int | None:
        try:
            return int(self.gate.tier_of(self.gate_name(tool)))
        except UnknownTool:
            return None

    async def _upstream_tools(self) -> dict[str, dict[str, Any]]:
        result = await self.upstream.list_tools()
        return {t.name: {"name": t.name, "description": t.description or "", "inputSchema": t.input_schema or {}}
                for t in result.tools}

    async def list_tools(self, ctx, params) -> types.ListToolsResult:
        tools = await self._upstream_tools()
        results = await asyncio.to_thread(self.registry.register, self.server_name, list(tools.values()))
        listed: list[types.Tool] = []
        for res in results:
            if not res.callable:
                log.warning("trustgate.mcp.tool_hidden", tool=res.name, status=res.status, reasons=res.reasons)
                continue
            pin = self.gate.store.get_pin(self.server_name, res.name)
            listed.append(types.Tool(name=res.name, description=pin.description,
                                     input_schema=augment_schema(pin.input_schema, self._tier(res.name))))
        return types.ListToolsResult(tools=listed)

    async def call_tool(self, ctx, params) -> types.CallToolResult:
        name = params.name
        arguments = dict(params.arguments or {})
        live = (await self._upstream_tools()).get(name)
        pinned_ok = False
        if live is not None:
            result = (await asyncio.to_thread(self.registry.register, self.server_name, [live]))[0]
            pinned_ok = result.callable

        reserved = {k: arguments.pop(k) for k in RESERVED_ARGS if k in arguments}
        upstream_props = (live or {}).get("inputSchema", {}).get("properties", {})
        alert_id = arguments.get("alert_id") if "alert_id" in upstream_props else arguments.pop("alert_id", "")
        try:
            action = ProposedAction(alert_id=str(alert_id or ""), tool=self.gate_name(name), args=arguments,
                                    verdict=reserved.get("verdict", "unsure"),
                                    cited_evidence=list(reserved.get("cited_evidence") or []),
                                    rationale=str(reserved.get("rationale", ""))[:800])
        except ValidationError:
            return _error(ESCALATED_MESSAGE + " (invalid tool call)")

        decision = await asyncio.to_thread(self.gate.decide, action, None,
                                           mcp={"server": self.server_name, "pinned_ok": pinned_ok})
        if not decision.permits_execution:
            return _error(f"{ESCALATED_MESSAGE} Escalation: {decision.escalation_id or 'n/a'}")
        call_args = decision.redacted_args if decision.enforced and decision.redacted_args is not None else arguments
        result = await self.upstream.call_tool(name, call_args)
        await asyncio.to_thread(self.gate.store.audit, "execution", alert_id=action.alert_id, tool=action.tool,
                                details={"via": "mcp_gateway", "monitor": not decision.enforced,
                                         "would_block": decision.would_block, "audit_id": decision.audit_id})
        return types.CallToolResult(content=list(getattr(result, "content", []) or []),
                                    structured_content=getattr(result, "structured_content", None),
                                    is_error=bool(getattr(result, "is_error", False)))


async def serve(upstream_cmd: list[str], server_name: str, gate: Gate, registry: ToolPinRegistry) -> None:
    params = StdioServerParameters(command=upstream_cmd[0], args=upstream_cmd[1:], env=dict(os.environ))
    async with stdio_client(params) as (up_read, up_write):
        async with ClientSession(up_read, up_write) as upstream:
            await upstream.initialize()
            gateway = Gateway(upstream, server_name, gate, registry)
            server = Server("trustgate-gateway", version=__version__,
                            instructions="TrustGate MCP gateway: tool calls are checked before they run.",
                            on_list_tools=gateway.list_tools, on_call_tool=gateway.call_tool)
            async with stdio_server() as (read, write):
                await server.run(read, write, server.create_initialization_options())


def main(argv: list[str] | None = None) -> None:
    # stdout carries the MCP protocol; all logs go to stderr.
    structlog.configure(logger_factory=structlog.PrintLoggerFactory(file=sys.stderr))
    parser = argparse.ArgumentParser(prog="trustgate-mcp-gateway")
    parser.add_argument("--server-name", required=True, help="name for the upstream server, used in pins and tool names")
    parser.add_argument("--policy", default=None, help="policy pack, e.g. packs/soc.rego")
    parser.add_argument("--mode", default=None, choices=["enforce", "monitor"])
    parser.add_argument("upstream", nargs=argparse.REMAINDER, help="-- command to start the upstream MCP server")
    args = parser.parse_args(argv)
    command = args.upstream[1:] if args.upstream[:1] == ["--"] else args.upstream
    if not command:
        parser.error("give the upstream server command after --")
    settings = Settings()
    gate = Gate(policy=args.policy or settings.policy, mode=args.mode, settings=settings)
    registry = ToolPinRegistry(gate.store, Detector(settings))
    anyio.run(serve, command, args.server_name, gate, registry)


if __name__ == "__main__":
    main()
