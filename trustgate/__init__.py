"""TrustGate: a deterministic action gate for AI agents.

Untrusted text can raise suspicion but never lower it. Every security-reducing
action has to prove itself on evidence the attacker cannot write.
"""

from trustgate.gate import ESCALATED_MESSAGE, ActionEscalated, Gate
from trustgate.models import Alert, Evidence, GateDecision, ProposedAction, Trust, TypedFacts
from trustgate.recheck import facts_only_recheck
from trustgate.tiers import Tier

__all__ = [
    "ActionEscalated",
    "Alert",
    "ESCALATED_MESSAGE",
    "Evidence",
    "Gate",
    "GateDecision",
    "ProposedAction",
    "Tier",
    "Trust",
    "TypedFacts",
    "facts_only_recheck",
]

__version__ = "2.0.0"
