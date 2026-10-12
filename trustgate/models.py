"""Shared data contracts (blueprint page 8), extended for v2.

Every service builds against these models. Typed facts carry no free strings an
attacker could write; everything attacker-written is an Evidence item that
defaults to untrusted.
"""

from __future__ import annotations

import re
import secrets
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, field_validator

Verdict = Literal["malicious", "benign", "unsure"]
Severity = Literal["low", "medium", "high", "critical"]
SEVERITY_ORDER: tuple[Severity, ...] = ("low", "medium", "high", "critical")

MAX_FACT_LIST = 256
_HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")
# Identifiers from SIEM / EDR structured fields. The charset leaves no room for
# sentences, so an identifier cannot carry an instruction into the re-check.
_HOSTNAME = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,62})(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}))*$")
_ACCOUNT = re.compile(r"^[A-Za-z0-9._@\\-]{1,64}$")
_EVIDENCE_ID = re.compile(r"^ev-\d{1,5}$")
_BAND = re.compile(r"^b\d:[0-9a-f]{16}$")
_TOOL_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_.:/-]{0,127}$")


class Trust(str, Enum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"


class TypedFacts(BaseModel):
    """Produced by code from channels the attacker cannot edit."""

    model_config = ConfigDict(extra="forbid")

    spf_pass: bool | None = None
    dkim_pass: bool | None = None
    dmarc_pass: bool | None = None
    sender_domain_age_days: int | None = Field(None, ge=0)
    url_reputation: Literal["clean", "suspicious", "malicious", "unknown"] = "unknown"
    ip_abuse_score: int | None = Field(None, ge=0, le=100)
    sandbox_verdict: Literal["clean", "suspicious", "malicious", "not_run"] = "not_run"
    ioc_ips: list[IPvAnyAddress] = Field(default_factory=list, max_length=MAX_FACT_LIST)
    ioc_hashes: list[str] = Field(default_factory=list, max_length=MAX_FACT_LIST)
    # IOC IPs with threat evidence of their own (abuse score, threat feed). Being in an alert is not
    # enough to be blocked: an attacker can get a partner's IP logged by spoofing it.
    malicious_ips: list[IPvAnyAddress] = Field(default_factory=list, max_length=MAX_FACT_LIST)
    asn: int | None = Field(None, ge=0)
    # Identifiers from the SIEM's structured fields, used for T2 value-matching only.
    hosts: list[str] = Field(default_factory=list, max_length=MAX_FACT_LIST)
    accounts: list[str] = Field(default_factory=list, max_length=MAX_FACT_LIST)
    # v2: computed by deterministic attachment parsers. The attacker influences
    # these, so they may only ever push the re-check towards suspicion.
    attachment_count: int = Field(0, ge=0)
    attachment_parse_failed: bool = False
    attachment_hidden_content: bool = False
    attachment_has_macros: bool = False
    attachment_has_qr: bool = False  # a QR code in an image: links no text filter sees (quishing)
    # How many messages this exact sender delivered to the organisation before
    # this one (MTA/SIEM history). Unlike SPF/DKIM/DMARC, domain age or a clean
    # URL, an attacker cannot buy this cheaply for a fresh campaign.
    sender_prior_messages: int | None = Field(None, ge=0)
    # Sender domain from the parsed email, used only as a campaign rate-limit key.
    sender_domain: str | None = None
    # True when a threat-intel lookup errored (not merely unconfigured): the
    # facts it would have produced are missing, not clean.
    enrichment_failed: bool = False
    # Campaign keys (trustgate/ingest/campaign.py): link domains and near-duplicate body keys.
    url_domains: list[str] = Field(default_factory=list, max_length=MAX_FACT_LIST)
    content_bands: list[str] = Field(default_factory=list, max_length=16)
    # A known sender behaving unusually: how a compromised account looks. From the email
    # headers (reply_to_mismatch) and MTA/SIEM history (the sender_* facts). Each can only
    # raise suspicion; any one set cancels sender history as support for "benign".
    reply_to_mismatch: bool | None = None
    sender_first_link: bool | None = None
    sender_first_attachment: bool | None = None
    sender_new_sending_ip: bool | None = None
    # Facts a campaign cannot buy, from the organisation's own history (SIEM / mail gateway).
    # Relationship: has anyone here ever replied to this sender? An attacker can send mail
    # but cannot make staff answer it.
    org_replied_to_sender: bool | None = None
    # Messages from this sender's domain to anyone in the organisation before this one.
    org_sender_domain_messages: int | None = Field(None, ge=0)
    # Nobody in the organisation has received or clicked this link domain before.
    org_url_domain_first_seen: bool | None = None
    # How many times this attachment hash was seen across the organisation before.
    org_attachment_prevalence: int | None = Field(None, ge=0)
    # Richer authentication and infrastructure signals. arc_pass and bimi_pass come from
    # the trusted Authentication-Results header; the others from enrichment feeds.
    arc_pass: bool | None = None
    bimi_pass: bool | None = None
    cert_age_days: int | None = Field(None, ge=0)              # TLS certificate of the link host
    domain_first_seen_days: int | None = Field(None, ge=0)     # passive DNS: days since first resolution
    # Endpoint context from the CMDB / EDR.
    asset_criticality: Literal["low", "medium", "high", "critical"] | None = None
    process_signed: bool | None = None                          # the flagged process has a valid signature

    @field_validator("url_domains")
    @classmethod
    def _url_domains_are_hostnames(cls, v: list[str]) -> list[str]:
        out = [d.strip().lower() for d in v]
        for d in out:
            if not _HOSTNAME.match(d):
                raise ValueError(f"invalid url domain in typed facts: {d[:40]!r}")
        return out

    @field_validator("content_bands")
    @classmethod
    def _bands_shape(cls, v: list[str]) -> list[str]:
        for b in v:
            if not _BAND.match(b):
                raise ValueError("content_bands must look like 'b0:<16 hex>'")
        return v

    @field_validator("sender_domain")
    @classmethod
    def _domain_is_hostname(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = v.strip().lower()
        if not _HOSTNAME.match(v):
            raise ValueError(f"invalid sender domain in typed facts: {v[:40]!r}")
        return v

    @field_validator("ioc_hashes")
    @classmethod
    def _hashes_are_sha256(cls, v: list[str]) -> list[str]:
        out = [h.strip().lower() for h in v]
        for h in out:
            if not _HEX_SHA256.match(h):
                raise ValueError("ioc_hashes accepts hex SHA-256 only")
        return out

    @field_validator("hosts")
    @classmethod
    def _hosts_are_hostnames(cls, v: list[str]) -> list[str]:
        out = [h.strip().lower() for h in v]
        for h in out:
            if not _HOSTNAME.match(h):
                raise ValueError(f"invalid hostname in typed facts: {h[:40]!r}")
        return out

    @field_validator("accounts")
    @classmethod
    def _accounts_are_identifiers(cls, v: list[str]) -> list[str]:
        out = [a.strip().lower() for a in v]
        for a in out:
            if not _ACCOUNT.match(a):
                raise ValueError(f"invalid account identifier in typed facts: {a[:40]!r}")
        return out

    def recheck_view(self) -> dict[str, Any]:
        """Numbers, booleans and enums only: the re-check never sees identifiers."""
        return {
            "spf_pass": self.spf_pass,
            "dkim_pass": self.dkim_pass,
            "dmarc_pass": self.dmarc_pass,
            "sender_domain_age_days": self.sender_domain_age_days,
            "url_reputation": self.url_reputation,
            "ip_abuse_score": self.ip_abuse_score,
            "sandbox_verdict": self.sandbox_verdict,
            "ioc_ip_count": len(self.ioc_ips),
            "ioc_hash_count": len(self.ioc_hashes),
            "asn_known": self.asn is not None,
            "attachment_count": self.attachment_count,
            "attachment_parse_failed": self.attachment_parse_failed,
            "attachment_hidden_content": self.attachment_hidden_content,
            "attachment_has_macros": self.attachment_has_macros,
            "attachment_has_qr": self.attachment_has_qr,
            "sender_prior_messages": self.sender_prior_messages,
            "enrichment_failed": self.enrichment_failed,
            "reply_to_mismatch": self.reply_to_mismatch,
            "sender_first_link": self.sender_first_link,
            "sender_first_attachment": self.sender_first_attachment,
            "sender_new_sending_ip": self.sender_new_sending_ip,
            "org_replied_to_sender": self.org_replied_to_sender,
            "org_sender_domain_messages": self.org_sender_domain_messages,
            "org_url_domain_first_seen": self.org_url_domain_first_seen,
            "org_attachment_prevalence": self.org_attachment_prevalence,
            "arc_pass": self.arc_pass,
            "bimi_pass": self.bimi_pass,
            "cert_age_days": self.cert_age_days,
            "domain_first_seen_days": self.domain_first_seen_days,
            "asset_criticality": self.asset_criticality,
            "process_signed": self.process_signed,
        }

    def target_values(self, fact: str) -> set[str]:
        """Exact values a T2 target may match ("ioc_ips", "hosts", "accounts")."""
        values = getattr(self, fact)
        return {str(v).lower() for v in values}


class Evidence(BaseModel):
    """Everything attacker-written. Default untrusted = fail closed."""

    id: str
    field: str
    trust: Trust = Trust.UNTRUSTED
    content: str
    flags: list[str] = Field(default_factory=list)
    origin: Literal["alert", "attachment", "mcp_tool", "tool_result", "agent", "analyst"] = "alert"
    raw_length: int = 0

    @field_validator("id")
    @classmethod
    def _id_shape(cls, v: str) -> str:
        if not _EVIDENCE_ID.match(v):
            raise ValueError("evidence id must look like 'ev-7'")
        return v


class IOCSignal(BaseModel):
    """One detector hit. Scores only; no authority."""

    source: str  # "regex", "stitch", "prompt_guard_2", "llm_guard:<scanner>", "decode"
    rule: str
    score: float = Field(ge=0.0, le=1.0)
    evidence_ids: list[str] = Field(default_factory=list)
    start: int | None = None
    end: int | None = None
    excerpt: str = ""


class LabelCoverage(BaseModel):
    total_fields: int = 0
    labelled_fields: int = 0
    unlabelled: list[str] = Field(default_factory=list)

    @property
    def ratio(self) -> float:
        return 1.0 if self.total_fields == 0 else self.labelled_fields / self.total_fields


class Alert(BaseModel):
    alert_id: str
    source: Literal["email", "network", "endpoint", "auth"]
    severity: Severity  # from SIEM structured fields only, then raised by IOCs
    facts: TypedFacts
    evidence: list[Evidence]
    original_severity: Severity | None = None
    tags: list[str] = Field(default_factory=list)  # "AI-evasion attempt", "hidden content"
    ioc_signals: list[IOCSignal] = Field(default_factory=list)
    detector_score: float = 0.0
    detectors_run: list[str] = Field(default_factory=list)
    label_coverage: LabelCoverage = Field(default_factory=LabelCoverage)
    delimiter: str = Field(default_factory=lambda: secrets.token_hex(8))

    @property
    def ai_evasion_attempt(self) -> bool:
        return "AI-evasion attempt" in self.tags

    def evidence_by_id(self) -> dict[str, Evidence]:
        return {e.id: e for e in self.evidence}

    def flag_ai_evasion(self, signal: IOCSignal) -> bool:
        """Record an injection IOC found after ingest (e.g. in a tool result). True if newly tagged."""
        self.ioc_signals.append(signal)
        if self.ai_evasion_attempt:
            return False
        self.tags.append("AI-evasion attempt")
        self.severity = SEVERITY_ORDER[min(len(SEVERITY_ORDER) - 1, SEVERITY_ORDER.index(self.severity) + 1)]
        return True


class ProposedAction(BaseModel):
    """What the agent must output."""

    alert_id: str
    verdict: Verdict
    tool: str
    args: dict[str, Any] = Field(default_factory=dict)
    cited_evidence: list[str] = Field(default_factory=list)  # "ev-7" or "facts.dmarc_pass"
    rationale: str = Field("", max_length=800)

    @field_validator("tool")
    @classmethod
    def _tool_name(cls, v: str) -> str:
        if not _TOOL_NAME.match(v):
            raise ValueError("invalid tool name")
        return v


class OutputFinding(BaseModel):
    """A sensitive value found in outbound text. The value itself is never stored."""

    entity: str
    start: int
    end: int
    score: float
    arg: str = ""
    action: Literal["allow", "redact", "block"] = "redact"


class GateDecision(BaseModel):
    decision: Literal["allow", "escalate", "block"]
    tier: Literal[0, 1, 2, 3] | None
    reasons: list[str]
    recheck_verdict: Verdict | None = None
    tainted_spans: list[str] = Field(default_factory=list)  # evidence IDs that tipped it
    latency_ms: float = 0.0
    # v2
    mode: Literal["enforce", "monitor"] = "enforce"
    enforced: bool = True
    pack: str = ""
    output_findings: list[OutputFinding] = Field(default_factory=list)
    redacted_args: dict[str, Any] | None = None
    recheck_tokens: int = 0
    audit_id: str | None = None
    escalation_id: str | None = None

    @property
    def would_block(self) -> bool:
        return self.decision != "allow"

    @property
    def permits_execution(self) -> bool:
        """Monitor mode logs would-block decisions but never stops the action."""
        return self.decision == "allow" or not self.enforced
