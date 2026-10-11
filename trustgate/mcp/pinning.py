"""MCP tool pinning + description scan (v2).

At registration each tool's name, description and input schema are hashed
(SHA-256, hashlib). Descriptions are untrusted text: the IOC detector scans
them with its tool-poisoning rules. A tool whose hash later changes (a rug pull)
is disabled until an analyst re-pins it through an explicit approval step that
is written to the audit trail. A tool name already served by another server
(shadowing) or a description that names another server's tools is quarantined.

A pin covers what a tool says, not what it returns. The first successful
response sets a baseline shape (content types, structured-content keys); a later
response with a new content type or new keys disables the tool the same way a
changed description does.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any

from trustgate.detector import Detector
from trustgate.store import Store, ToolPin, ToolResponseShape, _now


def tool_digest(name: str, description: str, input_schema: dict[str, Any] | None) -> str:
    canonical = json.dumps({"name": name, "description": description or "", "inputSchema": input_schema or {}},
                           sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass
class PinResult:
    server: str
    name: str
    status: str            # pinned, disabled, quarantined
    digest: str
    reasons: list[str] = field(default_factory=list)
    event: str = "unchanged"  # registered, unchanged, changed

    @property
    def callable(self) -> bool:
        return self.status == "pinned"


class ToolPinRegistry:
    def __init__(self, store: Store, detector: Detector | None = None):
        self.store = store
        self.detector = detector or Detector(use_models=False)

    def _scan(self, server: str, name: str, description: str, other_tools: dict[str, str]) -> list[str]:
        reasons: list[str] = []
        result = self.detector.scan_tool_description("ev-1", description)
        if result.flagged:
            rules = sorted({s.rule for s in result.signals})
            reasons.append(f"description scan: {', '.join(rules[:6])} (score {result.score})")
        for other, other_server in other_tools.items():
            if other != name and re.search(rf"\b{re.escape(other)}\b", description):
                reasons.append(f"cross-tool reference: mentions '{other}' from server '{other_server}'")
        return reasons

    def register(self, server: str, tools: list[dict[str, Any]]) -> list[PinResult]:
        """tools: [{"name", "description", "inputSchema"}] as listed by the upstream server."""
        other_tools = {p.name: p.server for p in self.store.pins() if p.server != server}
        results: list[PinResult] = []
        for tool in tools:
            name = str(tool["name"])
            description = str(tool.get("description") or "")
            schema = dict(tool.get("inputSchema") or {})
            digest = tool_digest(name, description, schema)
            pin = self.store.get_pin(server, name)

            if pin is None:
                reasons = self._scan(server, name, description, other_tools)
                if name in other_tools:
                    reasons.append(f"shadowing: '{name}' is also served by '{other_tools[name]}'")
                status = "quarantined" if reasons else "pinned"
                self.store.put_pin(ToolPin(server=server, name=name, sha256=digest, description=description,
                                           input_schema=schema, status=status, reasons=reasons,
                                           last_seen_sha256=digest, last_seen_description=description,
                                           last_seen_schema=schema))
                self._audit(server, name, "registered", status, reasons, digest)
                results.append(PinResult(server, name, status, digest, reasons, "registered"))
                continue

            if digest == pin.sha256:
                results.append(PinResult(server, name, pin.status, digest, list(pin.reasons), "unchanged"))
                continue

            if digest == pin.last_seen_sha256 and pin.status != "pinned":
                results.append(PinResult(server, name, pin.status, digest, list(pin.reasons), "unchanged"))
                continue

            # Rug pull: the description or schema changed after install.
            reasons = ["description or schema changed since pinning"] + self._scan(server, name, description, other_tools)
            pin.status = "disabled"
            pin.reasons = reasons
            pin.last_seen_sha256 = digest
            pin.last_seen_description = description
            pin.last_seen_schema = schema
            self.store.put_pin(pin)
            self._audit(server, name, "changed", "disabled", reasons, digest)
            results.append(PinResult(server, name, "disabled", digest, reasons, "changed"))
        return results

    def check_response(self, server: str, name: str, content_types: list[str],
                       structured_keys: list[str] | None) -> list[str]:
        """Compare a successful response with the tool's baseline. Returns drift reasons (empty = fine)."""
        baseline = self.store.get_shape(server, name)
        if baseline is None:
            self.store.put_shape(ToolResponseShape(server=server, name=name, content_types=sorted(content_types),
                                                   structured_keys=structured_keys))
            return []
        reasons: list[str] = []
        new_types = sorted(set(content_types) - set(baseline.content_types))
        if new_types and baseline.content_types:
            reasons.append(f"response content types changed: new {', '.join(new_types)}")
        if structured_keys is not None:
            if baseline.structured_keys is None:
                reasons.append("response started returning structured content")
            else:
                new_keys = sorted(set(structured_keys) - set(baseline.structured_keys))
                if new_keys:
                    reasons.append(f"response has new structured keys: {', '.join(new_keys[:8])}")
        if not baseline.content_types and content_types:
            baseline.content_types = sorted(content_types)  # first non-empty response fills the baseline
            self.store.put_shape(baseline)
        if reasons:
            pin = self.store.get_pin(server, name)
            if pin is not None:
                pin.status = "disabled"
                pin.reasons = ["response shape changed since baseline"] + reasons
                self.store.put_pin(pin)
                self._audit(server, name, "response_drift", "disabled", pin.reasons, pin.sha256)
        return reasons

    def is_callable(self, server: str, name: str, digest: str | None = None) -> bool:
        pin = self.store.get_pin(server, name)
        if pin is None or pin.status != "pinned":
            return False
        return digest is None or digest == pin.sha256

    def approve(self, server: str, name: str, *, approver: str, reason: str) -> ToolPin:
        """Explicit re-pin: accept the last-seen description and schema."""
        pin = self.store.get_pin(server, name)
        if pin is None:
            raise KeyError(f"{server}/{name}")
        previous = pin.sha256
        pin.sha256 = pin.last_seen_sha256
        pin.description = pin.last_seen_description
        pin.input_schema = pin.last_seen_schema
        pin.status = "pinned"
        pin.reasons = []
        pin.approved_by = approver
        pin.pinned_at = _now()
        self.store.put_pin(pin)
        self.store.delete_shape(server, name)  # the next response sets a fresh baseline
        self.store.audit("mcp_pin", tool=f"{server}/{name}", details={
            "event": "re-pinned", "approver": approver, "reason": reason,
            "previous_sha256": previous, "sha256": pin.sha256})
        return pin

    def _audit(self, server: str, name: str, event: str, status: str, reasons: list[str], digest: str) -> None:
        self.store.audit("mcp_pin", tool=f"{server}/{name}",
                         details={"event": event, "status": status, "reasons": reasons, "sha256": digest})
