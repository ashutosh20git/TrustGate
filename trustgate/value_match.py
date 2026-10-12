"""Value-matching at the tool boundary (silent failure 16).

The gate cannot see how the model turned untrusted text into an argument, so
high-impact arguments must exactly equal values from the typed facts (T2), or
be on the pack allowlist with no raw evidence in the body (T3).

Outbound text is checked in its decoded form (outbound_view): zero-width
characters, homoglyphs, base64, URL, hex and ROT13 encoding are undone first, so
an agent cannot carry evidence or a secret out by encoding it. Matching ignores
everything but letters and digits, so inserted punctuation or spacing does not
hide a quote either. restated_evidence_in catches light paraphrase: most of an
evidence item's distinctive words reappearing, in any order. A full rewrite in
other words is not caught (that needs a semantic model; stated as a limit).
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from trustgate.ingest.decode import rot13, sanitise
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


_STOPWORDS = frozenset("""about above after again against because before being below between could doing
during further having other their there these those through under until which while would should
please thanks regards dear hello email message alert today""".split())
_WORD = re.compile(r"[^\W\d_]{5,}")
RESTATE_MIN_WORDS = 8
RESTATE_RATIO = 0.6


def _distinctive(text: str) -> set[str]:
    return {w for w in (m.group(0).lower() for m in _WORD.finditer(text)) if w not in _STOPWORDS}


def restated_evidence_in(text: str, alert: Alert, *, min_words: int = RESTATE_MIN_WORDS,
                         ratio: float = RESTATE_RATIO) -> list[str]:
    """IDs of untrusted evidence items whose distinctive words mostly reappear in text (light
    paraphrase: reordered, partly reworded). Items with fewer than min_words such words are skipped."""
    view = outbound_view(text)
    words = _distinctive(view) | _distinctive(rot13(view))
    hits = []
    for ev in alert.evidence:
        if ev.trust != Trust.UNTRUSTED:
            continue
        mine = _distinctive(ev.content)
        if len(mine) >= min_words and len(mine & words) / len(mine) >= ratio:
            hits.append(ev.id)
    return hits


def outbound_view(text: str) -> str:
    """Outbound text as a reader could recover it: normalised, plus hidden and decoded parts."""
    return sanitise(str(text), max_chars=len(str(text)) + 1).scan_text


def _norm_text(text: str) -> str:
    return _NON_ALNUM.sub("", text).lower()


def raw_evidence_in(text: str, alert: Alert, window: int = RAW_EVIDENCE_WINDOW) -> list[str]:
    """IDs of untrusted evidence items quoted (>= window letters and digits) anywhere in text,
    including inside encoded or obfuscated parts."""
    view = outbound_view(text)
    haystack = _norm_text(view) + "|" + _norm_text(rot13(view))
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


# --- known-secret tracking ------------------------------------------------------------------
# The adaptive red-team (eval/adaptive_attack.py) carried a card number or API key out past the
# outbound scanner by reversing it, spelling digits as words, interleaving filler words, or
# splitting it across several messages. Pattern matching cannot see those. Instead, the gate
# knows which sensitive values the alert's own evidence contains, and checks outbound text,
# and everything already sent for the alert, for enough of each value under every transform.

_DIGIT_WORDS = {w: str(i) for i, w in enumerate("zero one two three four five six seven eight nine".split())}
SECRET_WINDOW = 4        # fragment length used to cover a secret
SECRET_COVERAGE = 0.6    # share of a secret's characters that, recovered, counts as a leak (partial counts)


def sensitive_values(alert: Alert, entities: set[str]) -> dict[str, str]:
    """Normalised sensitive values in the alert's untrusted evidence -> entity type."""
    from trustgate.output_scan import regex_findings

    out: dict[str, str] = {}
    for ev in alert.evidence:
        if ev.trust != Trust.UNTRUSTED:
            continue
        for entity, start, end, _score in regex_findings(ev.content):
            if entity in entities:
                value = _norm_text(ev.content[start:end])
                if len(value) >= 8:
                    out[value] = entity
    return out


def _projections(text: str) -> list[str]:
    """Readings of text an attacker's recipient could recover a value from."""
    view = outbound_view(text)
    words = re.findall(r"[a-z]+|\d+", view.lower())
    spelled = "".join(_DIGIT_WORDS.get(w, w) for w in words)
    # Drop filler words between fragments ("4111 then 1111", "part 2: 11111").
    fragments = "".join(w for w in re.findall(r"[A-Za-z0-9]+", view) if any(c.isdigit() for c in w) or w.isupper())
    base = [_norm_text(view), spelled, "".join(ch for ch in view if ch.isdigit()), _norm_text(fragments)]
    return base + [p[::-1] for p in base] + [_norm_text(rot13(view))]


def leaked_values(texts: list[str], values: dict[str, str], *, window: int = SECRET_WINDOW,
                  coverage: float = SECRET_COVERAGE) -> list[str]:
    """Entity types of sensitive values recoverable from texts taken together (messages already
    sent for the alert plus the new one): a value counts as leaked when fragments of it covering
    at least `coverage` of its characters appear in one reading of the text."""
    if not values or not texts:
        return []
    readings = [p for text in texts for p in _projections(text)]
    for i, text in enumerate(texts):  # fragments split across messages, in sending order
        if i:
            readings += _projections(" ".join(texts[: i + 1]))
    hits = []
    for value, entity in values.items():
        covered = [False] * len(value)
        for start in range(len(value) - window + 1):
            piece = value[start:start + window]
            if any(piece in r for r in readings):
                for k in range(start, start + window):
                    covered[k] = True
        if sum(covered) / len(value) >= coverage:
            hits.append(entity)
    return sorted(set(hits))
