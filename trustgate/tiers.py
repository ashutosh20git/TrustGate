"""Action tiers: a static map, written once. No model writes policy at runtime."""

from __future__ import annotations

from enum import IntEnum


class Tier(IntEnum):
    ALWAYS_ALLOWED = 0      # read, note, escalate, raise severity, enrich
    SECURITY_REDUCING = 1   # close benign, downgrade, whitelist, suppress
    DISRUPTIVE = 2          # block IP, isolate host, disable account
    OUTBOUND = 3            # email, webhook, external message

    @classmethod
    def parse(cls, value: int | str | "Tier") -> "Tier":
        if isinstance(value, Tier):
            return value
        if isinstance(value, str) and value.upper().startswith("T") and value[1:].isdigit():
            value = int(value[1:])
        return cls(int(value))


class UnknownTool(KeyError):
    """Raised for a tool missing from the tier map; the gate escalates it."""
