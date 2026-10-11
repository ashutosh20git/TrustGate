"""Provenance labels that survive a hand-off between agents.

When agent A's output becomes agent B's input (A emails a summary to a mailbox B
triages, or posts to a webhook B reads), B's trust labels used to start from
zero: whatever A had learnt about manipulation was lost. Outbound text from an
alert that carried injection signals now ends with a one-line stamp:

    [trustgate-provenance v1 src=soc:E-0042 taint=ev-3,ev-5 ai_evasion=1 sig=...]

The receiving TrustGate's splitter turns a stamp into an IOC signal, and into an
AI-evasion tag when the upstream alert had one. Stamps only ever *raise*
suspicion: there is no "clean" stamp, so forging one gains an attacker nothing
but scrutiny. With TRUSTGATE_PROVENANCE_KEY shared between gates, stamps are
HMAC-signed and the receiver reports whether the signature checked out.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass

from trustgate.models import Alert

_STAMP = re.compile(r"\[trustgate-provenance v1 src=(?P<src>[A-Za-z0-9_.:/-]{1,160}) "
                    r"taint=(?P<taint>[a-z0-9,-]{1,200}) ai_evasion=(?P<ai>[01]) sig=(?P<sig>[0-9a-f]{32}|unsigned)\]")


@dataclass
class Stamp:
    src: str
    taint: list[str]
    ai_evasion: bool
    valid: bool | None  # None: unsigned, or no key here to check it


def _sig(key: str, src: str, taint: str, ai: str) -> str:
    return hmac.new(key.encode(), f"v1|{src}|{taint}|{ai}".encode(), hashlib.sha256).hexdigest()[:32]


def stamp_for(alert: Alert, pack: str, key: str | None) -> str | None:
    """The stamp for outbound text derived from this alert, or None when the alert carries no taint."""
    if not (alert.ai_evasion_attempt or alert.ioc_signals):
        return None
    ids = sorted({e for s in alert.ioc_signals for e in s.evidence_ids if re.fullmatch(r"ev-\d+", e)},
                 key=lambda i: int(i.split("-")[1]))
    src, taint, ai = f"{pack}:{alert.alert_id}", ",".join(ids[:20]) or "-", "1" if alert.ai_evasion_attempt else "0"
    if not re.fullmatch(r"[A-Za-z0-9_.:/-]{1,160}", src):
        src = f"{pack}:redacted-id"
    sig = _sig(key, src, taint, ai) if key else "unsigned"
    return f"[trustgate-provenance v1 src={src} taint={taint} ai_evasion={ai} sig={sig}]"


def read_stamps(text: str, key: str | None) -> list[Stamp]:
    out = []
    for m in _STAMP.finditer(text or ""):
        sig = m.group("sig")
        if sig == "unsigned" or not key:
            valid = None
        else:
            valid = hmac.compare_digest(sig, _sig(key, m.group("src"), m.group("taint"), m.group("ai")))
        taint = [] if m.group("taint") == "-" else m.group("taint").split(",")
        out.append(Stamp(src=m.group("src"), taint=taint, ai_evasion=m.group("ai") == "1", valid=valid))
    return out
