"""Deterministic minimum evidence for T1 (security-reducing) actions.

The facts-only re-check is a model, and it can be wrong in two silent ways:

* Missing facts. When a threat-intel lookup fails or a parser finds nothing,
  facts stay unknown. Only the re-check prompt says "unknown is not evidence of
  safety"; a small model may still answer benign. Here, a T1 action needs its
  core facts known and no failed lookup, in code.
* Facts the attacker can buy. SPF, DKIM and DMARC pass on a domain the attacker
  owns; an aged domain can be bought; a link to a large file-sharing site has a
  clean reputation. A re-check over only those facts says benign. For sources
  that list costly_support, a T1 action also needs at least one fact a fresh
  campaign cannot buy cheaply (for email: the sender has delivered mail before).
* A compromised real account. Sender history is costly to fake, but a hijacked
  mailbox has it. When the known sender behaves unusually (a Reply-To on another
  domain, its first link or attachment, a new sending IP, a link domain nobody in
  the organisation has seen) history stops counting. Organisation history counts
  as costly support too: an attacker can send mail but cannot make staff reply.
* Citations that prove nothing. Citing any facts.* name used to be enough, even
  one unrelated to "benign" (facts.ioc_ips). At least one cited fact must now
  actually support benign (benign_support conditions).

Config lives in packs/floor.json ("t1_evidence") so no pack can loosen it.
"""

from __future__ import annotations

import operator
from dataclasses import dataclass, field
from typing import Any

from trustgate.models import TypedFacts

_OPS = {">=": operator.ge, ">": operator.gt, "<=": operator.le, "<": operator.lt, "==": operator.eq}
# Values that mean "this fact was never established".
_UNKNOWN = {None, "unknown", "not_run"}


@dataclass
class T1Evidence:
    unknown_core: list[str] = field(default_factory=list)
    costly_required: bool = False
    costly_support: list[str] = field(default_factory=list)
    enrichment_failed: bool = False
    cited_support: list[str] = field(default_factory=list)
    sender_anomalies: list[str] = field(default_factory=list)
    unknown_behaviour: list[str] = field(default_factory=list)
    history_discounted: bool = False  # the sender had history, but it could not count

    @property
    def cited_support_ok(self) -> bool:
        return bool(self.cited_support)

    @property
    def costly_ok(self) -> bool:
        return not self.costly_required or bool(self.costly_support)

    def reasons(self) -> list[str]:
        out: list[str] = []
        if self.enrichment_failed:
            out.append("T1: a threat-intel lookup failed; facts are missing, not clean")
        if self.unknown_core:
            out.append(f"T1: core facts unknown: {', '.join(self.unknown_core)}")
        if not self.costly_ok and self.sender_anomalies:
            out.append("T1: the sender has history, but is behaving unusually ("
                       + ", ".join(self.sender_anomalies) + "): a compromised account looks like this")
        elif not self.costly_ok and self.unknown_behaviour and self.history_discounted:
            out.append("T1: the sender has history, but whether it is behaving normally is unknown ("
                       + ", ".join(self.unknown_behaviour) + " not supplied): a compromised account cannot be ruled out")
        elif not self.costly_ok:
            out.append("T1: no fact the attacker cannot cheaply control supports benign")
        if not self.cited_support_ok:
            out.append("T1: no cited typed fact supports benign")
        return out

    def policy_input(self) -> dict[str, Any]:
        return {"unknown_core": self.unknown_core, "costly_support": self.costly_support,
                "costly_ok": self.costly_ok, "enrichment_failed": self.enrichment_failed,
                "cited_support": self.cited_support, "cited_support_ok": self.cited_support_ok}


def _holds(facts: TypedFacts, cond: dict[str, Any]) -> bool:
    value = getattr(facts, cond["fact"], None)
    op = _OPS.get(cond.get("op", ">="))
    if value is None or op is None:
        return False
    try:
        return bool(op(value, cond["value"]))
    except TypeError:
        return False


def t1_evidence(facts: TypedFacts, source: str, config: dict[str, Any] | None,
                cited: list[str] | None = None) -> T1Evidence:
    config = config or {}
    core = config.get("core_facts", {}).get(source, [])
    conditions = config.get("costly_support", {}).get(source, [])
    result = T1Evidence(enrichment_failed=facts.enrichment_failed, costly_required=bool(conditions))
    for name in core:
        if getattr(facts, name, None) in _UNKNOWN:
            result.unknown_core.append(name)
    result.sender_anomalies = [name for name in config.get("costly_negated_by", []) if getattr(facts, name, None) is True]
    # Unknown is not "behaving normally": without these signals a hijacked mailbox is invisible
    # (docs/BENCHMARKS.md, account takeover: 75% of replayed phishing closed before this).
    result.unknown_behaviour = [name for name in config.get("costly_requires_known", []) if getattr(facts, name, None) is None]
    for cond in conditions:
        # History (the sender's or the organisation's) is exactly what a hijacked mailbox has.
        history = cond["fact"].startswith(("sender_", "org_"))
        if not _holds(facts, cond):
            continue
        if history and (result.sender_anomalies or result.unknown_behaviour):
            result.history_discounted = True
            continue
        result.costly_support.append(f"{cond['fact']} {cond.get('op', '>=')} {cond['value']}")
    cited_facts = {c.split(".", 1)[1] for c in (cited or []) if c.startswith("facts.")}
    for cond in config.get("benign_support", []):
        if cond["fact"] in cited_facts and _holds(facts, cond):
            result.cited_support.append(cond["fact"])
    return result
