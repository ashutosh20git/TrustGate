"""Every tool maps to exactly one tier; an unknown tool escalates (blueprint test_tiers)."""

from __future__ import annotations

import pytest

from conftest import requires_opa

from trustgate.models import Alert, ProposedAction, TypedFacts
from trustgate.policy_client import load_pack
from trustgate.tiers import Tier, UnknownTool


def _alert(store, facts: TypedFacts) -> Alert:
    alert = Alert(alert_id="A-1", source="email", severity="high", facts=facts, evidence=[])
    store.put_alert(alert)
    return alert


def test_every_pack_tool_has_one_valid_tier():
    pack = load_pack("packs/soc.rego")
    for tool, tier in pack.data["tools"].items():
        assert tier in (0, 1, 2, 3), tool
        assert pack.tier_of(tool) == Tier(tier)


def test_unknown_tool_raises_then_escalates(gate, store):
    _alert(store, TypedFacts())
    with pytest.raises(UnknownTool):
        gate.tier_of("no_such_tool")
    d = gate.decide(ProposedAction(alert_id="A-1", verdict="benign", tool="no_such_tool", args={}))
    assert d.decision == "escalate"
    assert "unknown tool" in d.reasons


@requires_opa
def test_t0_always_allowed(gate, store):
    _alert(store, TypedFacts(dmarc_pass=False))
    d = gate.decide(ProposedAction(alert_id="A-1", verdict="unsure", tool="add_note",
                                   args={"text": "looking into this"}))
    assert d.decision == "allow"
    assert d.tier == 0
