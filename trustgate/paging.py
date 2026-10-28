"""Cursor (keyset) pagination for the analyst API's growing lists.

A page is "the next N rows after this sort key", not "skip N rows". New alerts,
escalations and audit records arrive while an analyst is scrolling (the dashboard
refreshes every 10 seconds); with offsets every arrival shifts the rows, so a row is
shown twice or skipped. Keyset pages stay put, and a deep page costs the same as the
first because the database seeks to the key through an index instead of counting
past skipped rows.

The cursor is opaque to clients: the last row's sort key as base64url JSON. A
malformed cursor raises BadCursor (the proxy answers 400), never a guess. The proxy returns the next cursor in the
X-Next-Cursor header (absent on the last page) so list bodies keep their shape.
"""

from __future__ import annotations

import base64
import datetime as dt
import json
from typing import Any

NEXT_CURSOR = "X-Next-Cursor"
TOTAL_COUNT = "X-Total-Count"


class BadCursor(ValueError):
    pass


def as_utc(value: dt.datetime) -> dt.datetime:
    """Timestamps compare as aware UTC; a naive one from the database is already UTC."""
    if value.tzinfo is None:
        return value.replace(tzinfo=dt.timezone.utc)
    return value.astimezone(dt.timezone.utc)


def encode(*key: Any) -> str:
    parts = [as_utc(k).isoformat() if isinstance(k, dt.datetime) else k for k in key]
    return base64.urlsafe_b64encode(json.dumps(parts, separators=(",", ":")).encode()).decode().rstrip("=")


def decode(cursor: str | None, types: tuple[type, ...]) -> tuple[Any, ...] | None:
    """The sort key a cursor carries, checked against the expected types; None for no cursor."""
    if not cursor:
        return None
    try:
        raw = json.loads(base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)))
        if not isinstance(raw, list) or len(raw) != len(types):
            raise ValueError
        key = []
        for value, kind in zip(raw, types):
            if kind is dt.datetime:
                key.append(as_utc(dt.datetime.fromisoformat(value)))
            elif isinstance(value, kind) and not isinstance(value, bool):
                key.append(value)
            else:
                raise ValueError
        return tuple(key)
    except (ValueError, TypeError, UnicodeDecodeError, json.JSONDecodeError):
        raise BadCursor("invalid cursor") from None
