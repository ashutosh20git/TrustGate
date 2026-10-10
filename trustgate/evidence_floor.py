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

    @property
    def costly_ok(self) -> bool:
        return not self.costly_required or bool(self.costly_support)

    def reasons(self) -> list[str]:
        out: list[str] = []
        if self.enrichment_failed:
            out.append("T1: a threat-intel lookup failed; facts are missing, not clean")
        if self.unknown_core:
            out.append(f"T1: core facts unknown: {', '.join(self.unknown_core)}")
        if not self.costly_ok:
            out.append("T1: no fact the attacker cannot cheaply control supports benign")
        return out

    def policy_input(self) -> dict[str, Any]:
        return {"unknown_core": self.unknown_core, "costly_support": self.costly_support,
                "costly_ok": self.costly_ok, "enrichment_failed": self.enrichment_failed}


def t1_evidence(facts: TypedFacts, source: str, config: dict[str, Any] | None) -> T1Evidence:
    config = config or {}
    core = config.get("core_facts", {}).get(source, [])
    conditions = config.get("costly_support", {}).get(source, [])
    result = T1Evidence(enrichment_failed=facts.enrichment_failed, costly_required=bool(conditions))
    for name in core:
        if getattr(facts, name, None) in _UNKNOWN:
            result.unknown_core.append(name)
    for cond in conditions:
        value = getattr(facts, cond["fact"], None)
        op = _OPS.get(cond.get("op", ">="))
        if value is None or op is None:
            continue
        try:
            if op(value, cond["value"]):
                result.costly_support.append(f"{cond['fact']} {cond.get('op', '>=')} {cond['value']}")
        except TypeError:
            continue
    return result
