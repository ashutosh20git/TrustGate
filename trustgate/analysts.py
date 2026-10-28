"""Analyst identities for approving escalations and re-pinning MCP tools.

An approval is only as strong as the identity behind it. Names typed into a
request body prove nothing: anyone who can reach the proxy (including a hijacked
agent on agent-net) could approve its own escalated action with two made-up
names. Approvals therefore need a bearer token, and the analyst's identity comes
from the token, never from the request.

The proxy holds only SHA-256 hashes of the tokens (Docker secret
"analyst_tokens", one "name:sha256hex" per line, written by
scripts/init_secrets.py). With no directory configured, approvals are refused.

Everyone in that file is an admin. Admins add the rest of the team from the
dashboard's Team page (Team below): those members live in the database, again as
hashes only, and work or stop working at once, with no restart.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from trustgate.store import Store

NAME = re.compile(r"^[a-z0-9._@-]{1,64}$")
ROLES = ("analyst", "admin")
_LINE = re.compile(r"^\s*([A-Za-z0-9._@-]{1,64})\s*:\s*([0-9a-fA-F]{64})\s*$")


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class AnalystDirectory:
    def __init__(self, entries: dict[str, str] | None = None):
        self._by_hash = {h.lower(): name for name, h in (entries or {}).items()}

    @classmethod
    def parse(cls, text: str | None) -> "AnalystDirectory":
        """Lines (or comma-separated items) of "name:sha256hex"; anything else is ignored."""
        entries: dict[str, str] = {}
        for item in re.split(r"[\n,]", text or ""):
            match = _LINE.match(item)
            if match:
                entries[match.group(1).lower()] = match.group(2)
        return cls(entries)

    @property
    def configured(self) -> bool:
        return bool(self._by_hash)

    @property
    def names(self) -> set[str]:
        return set(self._by_hash.values())

    def identify(self, token: str | None) -> str | None:
        """The analyst a bearer token belongs to, or None."""
        if not token:
            return None
        digest = token_hash(token.strip())
        for known, name in self._by_hash.items():
            if hmac.compare_digest(known, digest):
                return name
        return None


def new_token() -> str:
    return secrets.token_urlsafe(32)


@dataclass(frozen=True)
class Member:
    name: str
    role: str  # analyst, admin
    source: str  # "setup" (the secret file) or "team" (added in the dashboard)

    @property
    def admin(self) -> bool:
        return self.role == "admin"


class Team:
    """Who may sign in: the setup file's people (all admins) plus those admins added."""

    def __init__(self, directory: AnalystDirectory, store: "Store"):
        self.directory = directory
        self.store = store

    @property
    def configured(self) -> bool:
        return self.directory.configured or self.store.has_members()

    def identify(self, token: str | None) -> Member | None:
        if not token or not token.strip():
            return None
        name = self.directory.identify(token)
        if name is not None:
            return Member(name, "admin", "setup")
        row = self.store.member_by_token_hash(token_hash(token.strip()))
        return Member(row.name, row.role, "team") if row is not None else None
