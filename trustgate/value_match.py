"""Value-matching at the tool boundary (silent failure 16).

The gate cannot see how the model turned untrusted text into an argument, so
high-impact arguments must exactly equal values from the typed facts (T2), or
be on the pack allowlist with no raw evidence in the body (T3).

Outbound text is checked in its decoded form (outbound_view): zero-width
characters, homoglyphs, base64 and URL encoding are undone first, so an agent
cannot carry evidence or a secret out by encoding it. Matching ignores
everything but letters and digits, so inserted punctuation or spacing does not
hide a quote either.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from trustgate.ingest.decode import sanitise
from trustgate.models import Alert, Trust, TypedFacts
from trustgate.policy_client import PolicyPack

RAW_EVIDENCE_WINDOW = 40
_NON_ALNUM = re.compile(r"[\W_]+")


def _norm_value(value: Any) -> str:
    text = str(value).strip().lower()
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return text


def target_of(pack: PolicyPack, tool: str, args: dict[str, Any], override_arg: str | None = None) -> tuple[str | None, str | None]:
    """(target value, typed-fact name it must match). fact None = no fact can justify it."""
    spec = pack.target_spec(tool) or {}
    arg = override_arg or spec.get("arg")
    if not arg or arg not in args:
        return None, spec.get("fact")
    return _norm_value(args[arg]), spec.get("fact")


def fact_targets(facts: TypedFacts, fact: str | None) -> list[str]:
    if not fact:
        return []
    return sorted(_norm_value(v) for v in facts.target_values(fact))


def target_in_facts(target: str | None, fact: str | None, facts: TypedFacts) -> bool:
    return target is not None and target in fact_targets(facts, fact)


def recipient_of(pack: PolicyPack, tool: str, args: dict[str, Any], override_arg: str | None = None) -> str | None:
    spec = pack.outbound_spec(tool) or {}
    arg = override_arg or spec.get("recipient_arg")
    if not arg or arg not in args:
        return None
    return str(args[arg]).strip().lower()


def outbound_fields(pack: PolicyPack, tool: str, args: dict[str, Any], extra: list[str] | None = None) -> dict[str, str]:
    """Every argument that carries content out: pack body args, else all string args."""
    spec = pack.outbound_spec(tool) or {}
    names = list(spec.get("body_args") or []) + list(extra or [])
    if not names:
        names = [k for k, v in args.items() if isinstance(v, str) and k != spec.get("recipient_arg")]
    return {name: str(args[name]) for name in names if name in args and args[name] is not None}


def outbound_view(text: str) -> str:
    """Outbound text as a reader could recover it: normalised, plus hidden and decoded parts."""
    return sanitise(str(text), max_chars=len(str(text)) + 1).scan_text


def _norm_text(text: str) -> str:
    return _NON_ALNUM.sub("", text).lower()


def raw_evidence_in(text: str, alert: Alert, window: int = RAW_EVIDENCE_WINDOW) -> list[str]:
    """IDs of untrusted evidence items quoted (>= window letters and digits) anywhere in text,
    including inside encoded or obfuscated parts."""
    haystack = _norm_text(outbound_view(text))
    if len(haystack) < window:
        return []
    shingles = {haystack[i : i + window] for i in range(len(haystack) - window + 1)}
    hits: list[str] = []
    for ev in alert.evidence:
        if ev.trust != Trust.UNTRUSTED:
            continue
        content = _norm_text(ev.content)
        if any(content[i : i + window] in shingles for i in range(len(content) - window + 1)):
            hits.append(ev.id)
    return hits
