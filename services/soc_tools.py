"""The SOC agent's tool catalogue (blueprint page 9), bound to the mock SOC.

The same functions back the proxy (behind the gate), the undefended baseline
(config A, no gate) and approved escalations. Tiers come from the policy pack.
"""

from __future__ import annotations

from typing import Any, Callable

from services.mock_soc.client import MockSOCClient
from trustgate.gate import Gate
from trustgate.ingest.enrich import ThreatIntel
from trustgate.render import render_alert
from trustgate.render import render_untrusted_result as render_result
from trustgate.store import Store


def render_untrusted_result(tool: str, lines: list[str]) -> str:
    """Tool results are untrusted data too (logs carry attacker-written fields)."""
    return render_result(tool, "\n".join(lines))


def soc_tool_functions(client: MockSOCClient, store: Store, ti: ThreatIntel | None = None) -> dict[str, Callable[..., Any]]:
    def get_alert(alert_id: str) -> str:
        """Read the labelled alert: trusted typed facts plus quarantined, delimited evidence."""
        alert = store.get_alert(alert_id)
        return render_alert(alert) if alert else "unknown alert"

    def query_logs(alert_id: str) -> str:
        """Log lines related to the alert. Untrusted: attacker-controlled fields."""
        return render_untrusted_result("query_logs", client.query_logs(alert_id))

    def lookup_ioc(indicator: str) -> dict:
        """Threat-intel scores and verdicts for an IP or URL (numbers and enums only)."""
        if ti is None:
            return {"indicator": indicator, "result": "threat intel not configured"}
        if indicator.startswith(("http://", "https://")):
            return {"url_reputation": ti.virustotal_url(indicator), "urlhaus": ti.urlhaus(indicator)}
        return {"ip_abuse_score": ti.abuseipdb_score(indicator), "asn": ti.otx_asn(indicator)}

    def add_note(alert_id: str, text: str) -> dict:
        """Add an analyst note or summary to the ticket."""
        return client.add_note(alert_id, text)

    def escalate(alert_id: str, reason: str) -> dict:
        """Escalate the alert to a human analyst."""
        return client.escalate(alert_id, reason)

    def raise_severity(alert_id: str, severity: str) -> dict:
        """Raise the alert's severity."""
        return client.raise_severity(alert_id, severity)

    def enrich(alert_id: str) -> dict:
        """Return the alert's typed facts (already enriched at ingest)."""
        alert = store.get_alert(alert_id)
        return alert.facts.model_dump(mode="json") if alert else {}

    def close_alert(alert_id: str, reason: str) -> dict:
        """Close the alert as benign (security-reducing, T1)."""
        return client.close_alert(alert_id, reason)

    def downgrade_severity(alert_id: str, severity: str) -> dict:
        """Lower the alert's severity (security-reducing, T1)."""
        return client.downgrade_severity(alert_id, severity)

    def whitelist_indicator(alert_id: str, indicator: str, reason: str, ttl_hours: float) -> dict:
        """Allowlist an indicator for ttl_hours (security-reducing, T1; at most 24 h)."""
        return client.whitelist_indicator(alert_id, indicator, reason, ttl_hours)

    def suppress_rule(alert_id: str, rule: str, reason: str, ttl_hours: float) -> dict:
        """Suppress a detection rule for ttl_hours (security-reducing, T1; at most 24 h)."""
        return client.suppress_rule(alert_id, rule, reason, ttl_hours)

    def block_ip(alert_id: str, ip: str) -> dict:
        """Block an IP at the firewall (disruptive, T2). The IP must be one of the alert's typed IOCs."""
        return client.block_ip(alert_id, ip)

    def isolate_host(alert_id: str, host: str) -> dict:
        """Isolate a host with EDR (disruptive, T2). The host must be in the alert's typed facts."""
        return client.isolate_host(alert_id, host)

    def disable_account(alert_id: str, account: str) -> dict:
        """Disable an account in IAM (disruptive, T2). The account must be in the alert's typed facts."""
        return client.disable_account(alert_id, account)

    def send_email(alert_id: str, to: str, subject: str, body: str) -> dict:
        """Send an email (outbound, T3). Allowlisted recipients only; no raw evidence."""
        return client.send_email(alert_id, to, subject, body)

    def post_webhook(alert_id: str, url: str, payload: str) -> dict:
        """Post to a webhook (outbound, T3). Allowlisted URLs only; no raw evidence."""
        return client.post_webhook(alert_id, url, payload)

    return {fn.__name__: fn for fn in (
        get_alert, query_logs, lookup_ioc, add_note, escalate, raise_severity, enrich,
        close_alert, downgrade_severity, whitelist_indicator, suppress_rule,
        block_ip, isolate_host, disable_account, send_email, post_webhook,
    )}


def soc_undo_functions(client: MockSOCClient) -> dict[str, Callable[..., Any]]:
    """Reverse actions for the pack's "undo" map. Registered as undo executors, never as agent tools."""
    return {name: getattr(client, name) for name in (
        "reopen_alert", "restore_severity", "remove_whitelist", "unsuppress_rule",
        "unblock_ip", "release_host", "enable_account")}


def register_soc_tools(gate: Gate, functions: dict[str, Callable[..., Any]], *, mcp_server: str = "mock-soc",
                       undo: dict[str, Callable[..., Any]] | None = None) -> None:
    for name, fn in (undo or {}).items():
        gate.register_undo(name, fn)
    for name, fn in functions.items():
        tier = gate.pack.tier_of(name)
        if tier is None:
            continue
        gate.register(name, tier, fn)
        alias = f"{mcp_server}/{name}"
        alias_tier = gate.pack.tier_of(alias)
        if alias_tier is not None:  # escalations raised via the MCP gateway are approved here
            gate.register(alias, alias_tier, fn)
