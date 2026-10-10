"""The mock SOC as an MCP server: the upstream the TrustGate MCP gateway fronts in the demo.

    python -m trustgate.mcp.gateway --server-name mock-soc -- python -m services.mock_soc.mcp_server

It holds the mock SOC token; the agent never talks to it directly.
"""

from __future__ import annotations

from mcp.server.mcpserver import MCPServer

from services.mock_soc.client import MockSOCClient
from trustgate.config import Settings

server = MCPServer("mock-soc", instructions="Sandboxed SOC tools. Every action changes local state only.")
_client: MockSOCClient | None = None


def client() -> MockSOCClient:
    global _client
    if _client is None:
        settings = Settings()
        _client = MockSOCClient(settings.mock_soc_url, settings.mock_soc_token)
    return _client


@server.tool()
def query_logs(alert_id: str) -> list[str]:
    """Log lines related to an alert. Untrusted: attacker-controlled fields."""
    return client().query_logs(alert_id)


@server.tool()
def add_note(alert_id: str, text: str) -> dict:
    """Add a note or summary to the alert's ticket."""
    return client().add_note(alert_id, text)


@server.tool()
def escalate(alert_id: str, reason: str) -> dict:
    """Escalate an alert to a human analyst."""
    return client().escalate(alert_id, reason)


@server.tool()
def close_alert(alert_id: str, reason: str) -> dict:
    """Close an alert as benign."""
    return client().close_alert(alert_id, reason)


@server.tool()
def downgrade_severity(alert_id: str, severity: str) -> dict:
    """Lower an alert's severity."""
    return client().downgrade_severity(alert_id, severity)


@server.tool()
def whitelist_indicator(alert_id: str, indicator: str, reason: str) -> dict:
    """Allowlist an indicator."""
    return client().whitelist_indicator(alert_id, indicator, reason)


@server.tool()
def suppress_rule(alert_id: str, rule: str, reason: str) -> dict:
    """Suppress a detection rule."""
    return client().suppress_rule(alert_id, rule, reason)


@server.tool()
def block_ip(alert_id: str, ip: str) -> dict:
    """Block an IP address at the firewall."""
    return client().block_ip(alert_id, ip)


@server.tool()
def isolate_host(alert_id: str, host: str) -> dict:
    """Isolate a host with EDR."""
    return client().isolate_host(alert_id, host)


@server.tool()
def disable_account(alert_id: str, account: str) -> dict:
    """Disable a user account."""
    return client().disable_account(alert_id, account)


@server.tool()
def send_email(alert_id: str, to: str, subject: str, body: str) -> dict:
    """Send an email from the SOC outbox."""
    return client().send_email(alert_id, to, subject, body)


@server.tool()
def post_webhook(alert_id: str, url: str, payload: str) -> dict:
    """Post a message to a webhook."""
    return client().post_webhook(alert_id, url, payload)


if __name__ == "__main__":
    server.run("stdio")
