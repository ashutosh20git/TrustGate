"""Rule scorecard: a transparent second judge for the facts-only re-check.

The re-check model (Ollama or XGBoost) can be wrong in ways nobody can read off
it. The scorecard is a fixed, explainable rule set over the same typed facts.
The configured re-check runs both, and a T1 action needs *both* to say benign
(trustgate/recheck.py EnsembleRecheck): a blind spot in one judge cannot open the
gate on its own.

It answers:
  malicious  a fact says the alert is bad (DMARC failed, a malicious URL, file or IP)
  unsure     any warning sign, or no fact positively supports benign
  benign     no warning sign, and at least one strong fact supports benign

"Strong" means costly for an attacker: history with the organisation, a clean
sandbox or IP reputation, BIMI. SPF/DKIM/DMARC pass and a signed process are cheap
(an attacker who owns the domain passes DMARC), so they never count as strong.

It is deliberately conservative: when in doubt it says unsure, which escalates.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from trustgate.models import TypedFacts, Verdict

ABUSE_MALICIOUS = 75
ABUSE_CLEAN = 25
FRESH_DAYS = 30
ESTABLISHED_SENDER = 3


@dataclass
class Score:
    verdict: Verdict
    malicious: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    support: list[str] = field(default_factory=list)


def _looks_like_email(f: TypedFacts) -> bool:
    return any(v is not None for v in (f.spf_pass, f.dkim_pass, f.sender_prior_messages, f.org_replied_to_sender,
                                       f.sender_domain, f.reply_to_mismatch))


def score(facts: TypedFacts) -> Score:
    f = facts
    malicious: list[str] = []
    if f.dmarc_pass is False:
        malicious.append("dmarc_pass is False")
    if f.url_reputation == "malicious":
        malicious.append("url_reputation is malicious")
    if f.sandbox_verdict == "malicious":
        malicious.append("sandbox_verdict is malicious")
    if f.ip_abuse_score is not None and f.ip_abuse_score >= ABUSE_MALICIOUS:
        malicious.append(f"ip_abuse_score >= {ABUSE_MALICIOUS}")

    warnings: list[str] = []
    checks = [
        (f.url_reputation == "suspicious", "url_reputation is suspicious"),
        (f.sandbox_verdict == "suspicious", "sandbox_verdict is suspicious"),
        (f.ip_abuse_score is not None and ABUSE_CLEAN <= f.ip_abuse_score < ABUSE_MALICIOUS, "ip_abuse_score is elevated"),
        (f.spf_pass is False, "spf_pass is False"),
        (f.dkim_pass is False, "dkim_pass is False"),
        (f.enrichment_failed, "a threat-intel lookup failed"),
        (f.attachment_parse_failed, "an attachment could not be parsed"),
        (f.attachment_hidden_content, "an attachment hides content"),
        (f.attachment_has_macros, "an attachment has macros or active content"),
        (f.attachment_has_qr, "an attachment carries a QR code"),
        (f.reply_to_mismatch is True, "Reply-To is on another domain"),
        (f.sender_first_link is True, "the sender's first link"),
        (f.sender_first_attachment is True, "the sender's first attachment"),
        (f.sender_new_sending_ip is True, "a new sending IP for this sender"),
        (f.org_url_domain_first_seen is True, "a link domain nobody here has seen"),
        (f.sender_domain_age_days is not None and f.sender_domain_age_days < FRESH_DAYS, "the sender domain is new"),
        (f.cert_age_days is not None and f.cert_age_days < FRESH_DAYS, "the link host's certificate is new"),
        (f.domain_first_seen_days is not None and f.domain_first_seen_days < FRESH_DAYS, "the domain first resolved recently"),
        (f.process_signed is False, "the process is unsigned"),
        (f.dmarc_pass is None and _looks_like_email(f), "the email's DMARC result is unknown"),
        (f.asset_criticality == "critical", "the asset is critical"),
    ]
    warnings = [why for cond, why in checks if cond]

    support: list[str] = []
    strong = [
        (f.sandbox_verdict == "clean", "sandbox_verdict clean"),
        (f.ip_abuse_score is not None and f.ip_abuse_score < ABUSE_CLEAN, "ip_abuse_score low"),
        (f.sender_prior_messages is not None and f.sender_prior_messages >= ESTABLISHED_SENDER, "sender history"),
        (f.org_replied_to_sender is True, "the organisation has replied to this sender"),
        (f.bimi_pass is True, "bimi_pass"),
    ]
    support = [why for cond, why in strong if cond]

    if malicious:
        verdict: Verdict = "malicious"
    elif warnings or not support:
        verdict = "unsure"
    else:
        verdict = "benign"
    return Score(verdict=verdict, malicious=malicious, warnings=warnings, support=support)
