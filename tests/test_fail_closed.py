"""Any dependency failure makes T1-T3 escalate, never execute (blueprint test_fail_closed).

Covers silent failure 19 (failing open) and the fail-closed watchdog.
"""

from __future__ import annotations

import pytest

from conftest import facts_recheck, requires_opa

from trustgate.config import NotConfigured
from trustgate.gate import Gate
from trustgate.models import Alert, ProposedAction, TypedFacts
from trustgate.policy_client import PolicyUnavailable
from trustgate.ratelimit import MemoryRateLimiter


class BrokenPolicy:
    def decide(self, policy_input):
        raise PolicyUnavailable("opa is down")

    def healthy(self):
        return False


class BrokenRecheck:
    def __call__(self, facts):
        raise ConnectionError("ollama is down")


class BrokenLimiter:
    def hit(self, bucket, limit):
        raise NotConfigured("REDIS_URL")


def _seed(store, facts=None):
    alert = Alert(alert_id="A-1", source="email", severity="high", facts=facts or TypedFacts(dmarc_pass=False),
                  evidence=[])
    store.put_alert(alert)
    return alert


@requires_opa
def test_recheck_down_escalates_t1(settings, store, opa_engine):
    _seed(store)
    gate = Gate("packs/soc.rego", recheck=lambda f: BrokenRecheck()(f), mode="enforce", settings=settings,
                store=store, policy_engine=opa_engine, limiter=MemoryRateLimiter())
    d = gate.decide(ProposedAction(alert_id="A-1", verdict="benign", tool="close_alert",
                                   args={"reason": "x"}, cited_evidence=["facts.dmarc_pass"]))
    assert d.decision == "escalate"
    assert any("fail-closed" in r for r in d.reasons)


def test_policy_down_escalates_t1(settings, store):
    _seed(store)
    gate = Gate("packs/soc.rego", recheck=facts_recheck, mode="enforce", settings=settings, store=store,
                policy_engine=BrokenPolicy(), limiter=MemoryRateLimiter())
    d = gate.decide(ProposedAction(alert_id="A-1", verdict="benign", tool="close_alert",
                                   args={"reason": "x"}, cited_evidence=["facts.dmarc_pass"]))
    # The re-check will already disagree (dmarc fail), but even a benign-facts alert fails closed:
    alert2 = Alert(alert_id="A-2", source="email", severity="low", facts=TypedFacts(dmarc_pass=True, sender_prior_messages=12, reply_to_mismatch=False, sender_first_link=False, sender_new_sending_ip=False,
                   url_reputation="clean"), evidence=[])
    store.put_alert(alert2)
    d2 = gate.decide(ProposedAction(alert_id="A-2", verdict="benign", tool="close_alert",
                                    args={"reason": "x"}, cited_evidence=["facts.dmarc_pass"]))
    assert d2.decision == "escalate"
    assert any("fail-closed" in r for r in d2.reasons)


@requires_opa
def test_rate_limiter_down_escalates_t1(settings, store, opa_engine):
    alert2 = Alert(alert_id="A-2", source="email", severity="low",
                   facts=TypedFacts(dmarc_pass=True, url_reputation="clean", sender_prior_messages=12, reply_to_mismatch=False, sender_first_link=False, sender_new_sending_ip=False), evidence=[])
    store.put_alert(alert2)
    gate = Gate("packs/soc.rego", recheck=facts_recheck, mode="enforce", settings=settings, store=store,
                policy_engine=opa_engine, limiter=BrokenLimiter())
    d = gate.decide(ProposedAction(alert_id="A-2", verdict="benign", tool="close_alert",
                                   args={"reason": "x"}, cited_evidence=["facts.dmarc_pass"]))
    assert d.decision == "escalate"
    assert any("fail-closed" in r for r in d.reasons)


@requires_opa
def test_timeout_escalates(settings, store, opa_engine):
    import time

    def slow(facts):
        time.sleep(2)
        return "benign"

    _seed(store, TypedFacts(dmarc_pass=True, url_reputation="clean", sender_prior_messages=12, reply_to_mismatch=False, sender_first_link=False, sender_new_sending_ip=False))
    gate = Gate("packs/soc.rego", recheck=slow, mode="enforce", settings=settings, store=store,
                policy_engine=opa_engine, limiter=MemoryRateLimiter(), timeout_s=0.2)
    d = gate.decide(ProposedAction(alert_id="A-1", verdict="benign", tool="close_alert",
                                   args={"reason": "x"}, cited_evidence=["facts.dmarc_pass"]))
    assert d.decision == "escalate"
    assert any("TimeoutError" in r for r in d.reasons)
