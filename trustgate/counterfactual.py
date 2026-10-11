"""Counterfactual explanations for escalations: what would have let the action through.

A detector gives a score; the gate gives reasons. Neither tells the analyst what
is *missing*. For a T1 action this tries changing up to two typed facts to the
value that supports "benign" and re-runs the deterministic checks (the facts-only
re-check and the evidence floor) on each candidate, so the analyst reads, for
example, "Would allow if facts.dmarc_pass were True (now False)". Blocks no fact
can lift (an AI-evasion tag, a critical alert, a critical-asset target) are listed
as "never automatic". T2 and T3 explanations come from the value-match and
allowlist checks.

Computed on demand for one escalation (it calls the re-check once per candidate),
never on the decision path.
"""

from __future__ import annotations

from itertools import combinations
from typing import TYPE_CHECKING, Any

from trustgate import value_match
from trustgate.evidence_floor import t1_evidence
from trustgate.models import Alert, ProposedAction, TypedFacts
from trustgate.tiers import Tier

if TYPE_CHECKING:
    from trustgate.gate import Gate
    from trustgate.store import Escalation

_BENIGN_TARGET = {"==": lambda v: v, ">=": lambda v: v, ">": lambda v: v + 1, "<": lambda v: 0, "<=": lambda v: v}


def _candidates(config: dict[str, Any], source: str) -> dict[str, Any]:
    """fact -> the value that would support benign, from the floor's own conditions."""
    out: dict[str, Any] = {"enrichment_failed": False}
    conditions = list(config.get("benign_support", [])) + list(config.get("costly_support", {}).get(source, []))
    for cond in conditions:
        target = _BENIGN_TARGET.get(cond.get("op", ">="))
        if target is None:
            continue
        value, prev = target(cond["value"]), out.get(cond["fact"])
        both_numbers = all(isinstance(x, int) and not isinstance(x, bool) for x in (value, prev))
        out[cond["fact"]] = max(value, prev) if both_numbers else value  # e.g. the stricter sender history
    return out


def _fmt(fact: str, new: Any, old: Any) -> str:
    return f"facts.{fact} were {new!r} (now {old!r})"


def explain(gate: "Gate", esc: "Escalation") -> dict[str, Any]:
    action = ProposedAction.model_validate(esc.action)
    alert = gate.store.get_alert(action.alert_id)
    out: dict[str, Any] = {"escalation_id": esc.id, "tool": action.tool, "tier": esc.tier,
                           "reasons": list(esc.reasons), "would_allow_if": [], "never_automatic": [], "notes": []}
    if alert is None:
        out["never_automatic"].append("the alert no longer exists")
        return out
    if esc.tier == int(Tier.SECURITY_REDUCING):
        _explain_t1(gate, action, alert, out)
    elif esc.tier == int(Tier.DISRUPTIVE):
        _explain_t2(gate, action, alert, out)
    elif esc.tier == int(Tier.OUTBOUND):
        _explain_t3(gate, action, alert, out)
    else:
        out["notes"].append("no counterfactual for this tier; see the reasons")
    return out


def _explain_t1(gate: "Gate", action: ProposedAction, alert: Alert, out: dict[str, Any]) -> None:
    if alert.ai_evasion_attempt:
        out["never_automatic"].append("the alert is tagged as an AI-evasion attempt; untrusted text can raise "
                                      "suspicion but never lower it")
    if alert.severity == "critical":
        out["never_automatic"].append("closing or downgrading a critical alert always needs a human")
    if action.verdict != "benign":
        out["never_automatic"].append(f"the agent's own verdict is {action.verdict!r}, not benign")
    scope = gate._expiry_scope(action)
    if not scope["ok"]:
        out["would_allow_if"].append(f"args.ttl_hours were set, at most {scope['max_hours']:g}")
    history = gate._history(alert.alert_id)
    if history["t1_executed"]:
        out["never_automatic"].append(f"{', '.join(history['tools'][:3])} already ran on this alert")

    config = gate.pack.floor.get("t1_evidence", {})
    facts = alert.facts

    def passes(candidate: TypedFacts, changed: tuple[str, ...]) -> bool:
        cited = list(action.cited_evidence) + [f"facts.{f}" for f in changed]
        if t1_evidence(candidate, alert.source, config, cited).reasons():
            return False
        if recheck_ok is False:
            return True  # floor only: the re-check could not run
        return gate.recheck(candidate).verdict == "benign"

    recheck_ok: bool | None = None
    try:
        current_ok = passes(facts, ())
        recheck_ok = True
    except Exception as exc:  # the re-check model is down: explain the floor alone
        recheck_ok = False
        out["notes"].append(f"re-check unavailable ({type(exc).__name__}); only the evidence floor was tested")
        current_ok = passes(facts, ())
    if current_ok:
        out["notes"].append("the typed facts already support this action; it was stopped by the other reasons")
        return

    candidates = {f: v for f, v in _candidates(config, alert.source).items() if getattr(facts, f, None) != v}
    for size in (1, 2):
        found = []
        for combo in combinations(sorted(candidates), size):
            try:
                changed = facts.model_copy(update={f: candidates[f] for f in combo})
                if passes(changed, combo):
                    found.append(" and ".join(_fmt(f, candidates[f], getattr(facts, f)) for f in combo))
            except Exception:  # noqa: BLE001 - one bad candidate does not void the rest
                continue
        if found:
            out["would_allow_if"].extend(found)
            return
    out["notes"].append("no change of up to two typed facts would let this action run automatically")


def _explain_t2(gate: "Gate", action: ProposedAction, alert: Alert, out: dict[str, Any]) -> None:
    registered = gate.tools.get(action.tool)
    target, fact = value_match.target_of(gate.pack, action.tool, action.args,
                                          registered.target_arg if registered else None)
    targets = value_match.fact_targets(alert.facts, fact)
    if target is None or target not in targets:
        shown = ", ".join(targets[:10]) or "none"
        out["would_allow_if"].append(f"the target were one of the alert's typed facts.{fact}: {shown} "
                                     f"(now {target!r})")
    if target is not None and target in gate.pack.critical_assets:
        out["never_automatic"].append(f"{target} is a critical asset: two analysts must approve")


def _explain_t3(gate: "Gate", action: ProposedAction, alert: Alert, out: dict[str, Any]) -> None:
    registered = gate.tools.get(action.tool)
    recipient = value_match.recipient_of(gate.pack, action.tool, action.args,
                                         registered.target_arg if registered else None)
    if recipient not in gate.pack.allowlist:
        out["would_allow_if"].append(f"the recipient were on the allowlist: {', '.join(sorted(gate.pack.allowlist))} "
                                     f"(now {recipient!r})")
    fields = value_match.outbound_fields(gate.pack, action.tool, action.args)
    quoted = sorted({eid for text in fields.values() for eid in value_match.raw_evidence_in(text, alert)})
    if quoted:
        out["would_allow_if"].append(f"the payload did not quote untrusted evidence {', '.join(quoted)}")
    blocked = [r for r in out["reasons"] if "may never leave" in r or "sensitive data" in r]
    if blocked:
        out["never_automatic"].extend(blocked)
