"""Tool stubs. The agent holds no tool credentials: everything goes through the proxy.

DirectToolsClient exists only for evaluation config A (the undefended agent),
where the agent's proposed action runs straight against the mock SOC.
"""

from __future__ import annotations

import inspect
from typing import Any, Callable, Protocol

import httpx

from trustgate.models import ProposedAction


class ToolsClient(Protocol):
    def read(self, tool: str, args: dict[str, Any], alert_id: str) -> str: ...
    def submit(self, action: ProposedAction) -> dict[str, Any]: ...


class ProxyToolsClient:
    def __init__(self, proxy_url: str, *, client: httpx.Client | None = None):
        self._http = client or httpx.Client(base_url=proxy_url, timeout=60)

    def read(self, tool: str, args: dict[str, Any], alert_id: str) -> str:
        action = ProposedAction(alert_id=alert_id, verdict="unsure", tool=tool, args=args)
        body = self.submit(action)
        if not body.get("executed"):
            return body.get("message") or "tool call not executed"
        result = body.get("result")
        return result if isinstance(result, str) else str(result)

    def submit(self, action: ProposedAction) -> dict[str, Any]:
        resp = self._http.post(f"/v1/tools/{action.tool}", json=action.model_dump(mode="json"))
        resp.raise_for_status()
        return resp.json()


class DirectToolsClient:
    """Config A only: no gate, the agent's action executes as proposed."""

    def __init__(self, functions: dict[str, Callable[..., Any]]):
        self.functions = functions

    def _call(self, tool: str, args: dict[str, Any]) -> Any:
        fn = self.functions[tool]
        accepted = inspect.signature(fn).parameters
        return fn(**{k: v for k, v in args.items() if k in accepted})

    def read(self, tool: str, args: dict[str, Any], alert_id: str) -> str:
        result = self._call(tool, {"alert_id": alert_id, **args})
        return result if isinstance(result, str) else str(result)

    def submit(self, action: ProposedAction) -> dict[str, Any]:
        if action.tool not in self.functions:
            return {"executed": False, "error": "unknown tool"}
        result = self._call(action.tool, {"alert_id": action.alert_id, **action.args})
        return {"executed": True, "result": result, "decision": None}
