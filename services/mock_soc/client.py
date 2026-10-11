"""HTTP client for the mock SOC. Only the proxy (and the undefended baseline) hold its token."""

from __future__ import annotations

from typing import Any

import httpx

from trustgate.config import NotConfigured


class MockSOCClient:
    def __init__(self, base_url: str | None = None, token: str | None = None, *, client: httpx.Client | None = None):
        if client is None:
            if not token:
                raise NotConfigured("MOCK_SOC_TOKEN", "run scripts/init_secrets.py")
            client = httpx.Client(base_url=base_url or "http://localhost:8090", timeout=10)
        if token:
            client.headers["Authorization"] = f"Bearer {token}"
        self._http = client

    def _post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        resp = self._http.post(path, json=body)
        resp.raise_for_status()
        return resp.json()

    def close_alert(self, alert_id: str, reason: str) -> dict:
        return self._post("/tickets/close", {"alert_id": alert_id, "reason": reason})

    def downgrade_severity(self, alert_id: str, severity: str) -> dict:
        return self._post("/tickets/downgrade", {"alert_id": alert_id, "severity": severity})

    def raise_severity(self, alert_id: str, severity: str) -> dict:
        return self._post("/tickets/raise_severity", {"alert_id": alert_id, "severity": severity})

    def add_note(self, alert_id: str, text: str) -> dict:
        return self._post("/tickets/note", {"alert_id": alert_id, "text": text})

    def escalate(self, alert_id: str, reason: str) -> dict:
        return self._post("/tickets/escalate", {"alert_id": alert_id, "reason": reason})

    def suppress_rule(self, alert_id: str, rule: str, reason: str, ttl_hours: float | None = None) -> dict:
        return self._post("/rules/suppress", {"alert_id": alert_id, "rule": rule, "reason": reason,
                                              "ttl_hours": ttl_hours})

    def whitelist_indicator(self, alert_id: str, indicator: str, reason: str, ttl_hours: float | None = None) -> dict:
        return self._post("/whitelist/add", {"alert_id": alert_id, "indicator": indicator, "reason": reason,
                                             "ttl_hours": ttl_hours})

    def block_ip(self, alert_id: str, ip: str) -> dict:
        return self._post("/firewall/block", {"alert_id": alert_id, "ip": ip})

    def isolate_host(self, alert_id: str, host: str) -> dict:
        return self._post("/edr/isolate", {"alert_id": alert_id, "host": host})

    def disable_account(self, alert_id: str, account: str) -> dict:
        return self._post("/iam/disable", {"alert_id": alert_id, "account": account})

    def send_email(self, alert_id: str, to: str, subject: str, body: str) -> dict:
        return self._post("/outbox/send", {"alert_id": alert_id, "to": to, "subject": subject, "body": body})

    def post_webhook(self, alert_id: str, url: str, payload: str) -> dict:
        return self._post("/webhook/post", {"alert_id": alert_id, "url": url, "payload": payload})

    # Reverse actions (analyst revert / automatic rollback only)
    def reopen_alert(self, alert_id: str) -> dict:
        return self._post("/tickets/reopen", {"alert_id": alert_id})

    def restore_severity(self, alert_id: str, severity: str) -> dict:
        return self._post("/tickets/restore_severity", {"alert_id": alert_id, "severity": severity})

    def remove_whitelist(self, alert_id: str, indicator: str) -> dict:
        return self._post("/whitelist/remove", {"alert_id": alert_id, "indicator": indicator})

    def unsuppress_rule(self, alert_id: str, rule: str) -> dict:
        return self._post("/rules/unsuppress", {"alert_id": alert_id, "rule": rule})

    def unblock_ip(self, alert_id: str, ip: str) -> dict:
        return self._post("/firewall/unblock", {"alert_id": alert_id, "ip": ip})

    def release_host(self, alert_id: str, host: str) -> dict:
        return self._post("/edr/release", {"alert_id": alert_id, "host": host})

    def enable_account(self, alert_id: str, account: str) -> dict:
        return self._post("/iam/enable", {"alert_id": alert_id, "account": account})

    def query_logs(self, alert_id: str) -> list[str]:
        resp = self._http.get("/logs", params={"alert_id": alert_id})
        resp.raise_for_status()
        return list(resp.json()["lines"])

    def seed_logs(self, alert_id: str, lines: list[str]) -> dict:
        return self._post("/logs/seed", {"alert_id": alert_id, "lines": lines})

    def state(self, alert_id: str | None = None) -> list[dict]:
        resp = self._http.get("/state", params={"alert_id": alert_id} if alert_id else None)
        resp.raise_for_status()
        return list(resp.json()["effects"])

    def reset(self) -> dict:
        return self._post("/reset", {})
