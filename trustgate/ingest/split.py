"""Evidence splitter: raw alert -> typed facts (trusted) + quarantined text (untrusted).

Every input field has a trust label from a static registry. A field the
registry does not know becomes untrusted evidence and is counted against label
coverage (fail closed, silent failure 12). Severity, source and identities come
only from the SIEM's structured fields, never from text a model reads.
"""

from __future__ import annotations

import base64
import binascii
from fnmatch import fnmatch
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from trustgate.config import Settings
from trustgate.detector import Detector
from trustgate.ingest.attachments import AttachmentResult, parse_attachment
from trustgate.ingest.decode import sanitise
from trustgate.ingest.enrich import EnrichmentReport, ThreatIntel
from trustgate.ingest.parsers.email import ParsedEmail, live_auth, parse_email
from trustgate.models import (
    SEVERITY_ORDER,
    Alert,
    Evidence,
    LabelCoverage,
    Severity,
    Trust,
    TypedFacts,
)

AI_EVASION_TAG = "AI-evasion attempt"
HIDDEN_CONTENT_TAG = "hidden content"

# Static trust labels for the top-level raw-alert fields.
FIELD_LABELS: dict[str, Trust] = {
    "alert_id": Trust.TRUSTED,
    "source": Trust.TRUSTED,
    "severity": Trust.TRUSTED,
    "rule_name": Trust.TRUSTED,
    "observed": Trust.TRUSTED,       # SIEM structured fields: IOC lists, asset IDs, ASN
    "enrichment": Trust.TRUSTED,     # verdicts already computed by trusted systems
    "email.envelope": Trust.TRUSTED,  # MTA log: client IP, MAIL FROM, HELO
    "email.raw": Trust.UNTRUSTED,
    "email.raw_b64": Trust.UNTRUSTED,
    "fields": Trust.UNTRUSTED,       # attacker-controlled free text (User-Agent, URI, ...)
    "log_entries": Trust.UNTRUSTED,
    "attachments": Trust.UNTRUSTED,
}
_FACT_KEYS = set(TypedFacts.model_fields)


class RawAttachment(BaseModel):
    filename: str = ""
    content_b64: str


class RawAlert(BaseModel):
    """What the SIEM webhook posts. Unknown keys are kept and treated as untrusted."""

    model_config = ConfigDict(extra="allow")

    alert_id: str
    source: Literal["email", "network", "endpoint", "auth"]
    severity: Severity
    rule_name: str | None = None
    observed: dict[str, Any] = Field(default_factory=dict)
    enrichment: dict[str, Any] = Field(default_factory=dict)
    email: dict[str, Any] | None = None
    fields: dict[str, str] = Field(default_factory=dict)
    log_entries: list[str] = Field(default_factory=list)
    attachments: list[RawAttachment] = Field(default_factory=list)


class EvidenceBuilder:
    def __init__(self, max_chars: int):
        self.items: list[Evidence] = []
        self.scan_parts: list[tuple[str, str]] = []
        self.max_chars = max_chars

    def add(self, field: str, raw: str, *, origin: str = "alert", flags: list[str] | None = None,
            is_html: bool | None = None) -> Evidence | None:
        if raw is None or str(raw).strip() == "":
            return None
        decoded = sanitise(str(raw), max_chars=self.max_chars, is_html=is_html)
        evidence = Evidence(
            id=f"ev-{len(self.items) + 1}",
            field=field,
            trust=Trust.UNTRUSTED,
            content=decoded.text,
            flags=sorted(set((flags or []) + decoded.flags)),
            origin=origin,
            raw_length=decoded.raw_length,
        )
        self.items.append(evidence)
        self.scan_parts.append((evidence.id, decoded.scan_text))
        return evidence


def _raise(severity: Severity, steps: int = 1) -> Severity:
    idx = min(len(SEVERITY_ORDER) - 1, SEVERITY_ORDER.index(severity) + steps)
    return SEVERITY_ORDER[idx]


def _label_coverage(raw: RawAlert, payload: dict[str, Any]) -> LabelCoverage:
    paths: list[str] = []
    for key, value in payload.items():
        if key == "email" and isinstance(value, dict):
            paths.extend(f"email.{k}" for k in value)
        else:
            paths.append(key)
    unlabelled = [p for p in paths if not any(fnmatch(p, pattern) for pattern in FIELD_LABELS)]
    return LabelCoverage(total_fields=len(paths), labelled_fields=len(paths) - len(unlabelled), unlabelled=unlabelled)


def _facts_from_trusted(raw: RawAlert, notes: list[str]) -> dict[str, Any]:
    values: dict[str, Any] = {}
    for source in (raw.observed, raw.enrichment):
        for key, value in source.items():
            if key in _FACT_KEYS:
                values[key] = value
            else:
                notes.append(f"ignored trusted field without a fact type: {key}")
    # Validate field by field so one bad value cannot void the rest.
    clean: dict[str, Any] = {}
    for key, value in values.items():
        try:
            TypedFacts.model_validate({key: value})
            clean[key] = value
        except ValidationError:
            notes.append(f"dropped invalid fact: {key}")
    return clean


class Splitter:
    def __init__(self, settings: Settings | None = None, *, detector: Detector | None = None,
                 threat_intel: ThreatIntel | None = None, enrich: bool = True):
        self.settings = settings or Settings()
        self.detector = detector or Detector(self.settings)
        self._ti = threat_intel
        self._enrich = enrich
        self.notes: list[str] = []

    @property
    def threat_intel(self) -> ThreatIntel:
        if self._ti is None:
            self._ti = ThreatIntel(self.settings)
        return self._ti

    def split(self, payload: dict[str, Any]) -> Alert:
        raw = RawAlert.model_validate(payload)
        notes: list[str] = []
        builder = EvidenceBuilder(self.settings.max_field_chars)
        facts = _facts_from_trusted(raw, notes)
        urls: list[str] = []
        file_hashes: list[str] = list(facts.get("ioc_hashes", []))
        sender_domain = ""
        attachments: list[AttachmentResult] = []

        if raw.email:
            parsed = self._email(raw, builder, facts, notes)
            if parsed is not None:
                urls.extend(parsed.urls)
                sender_domain = parsed.from_domain
                if sender_domain and facts.get("sender_domain") is None:
                    try:
                        facts["sender_domain"] = TypedFacts.model_validate({"sender_domain": sender_domain}).sender_domain
                    except ValidationError:
                        notes.append("sender domain is not a valid hostname; no campaign key")
                for i, (filename, data) in enumerate(parsed.attachments):
                    attachments.append(parse_attachment(i, filename, data))

        for name, value in raw.fields.items():
            builder.add(f"fields.{name}", value)
        for i, entry in enumerate(raw.log_entries):
            builder.add(f"log_entries[{i}]", entry)

        offset = len(attachments)
        for j, att in enumerate(raw.attachments):
            try:
                data = base64.b64decode(att.content_b64, validate=True)
            except (binascii.Error, ValueError):
                data = b""
            attachments.append(parse_attachment(offset + j, att.filename, data))
        for att in attachments:
            builder.add(f"attachment[{att.index}].filename", att.filename, origin="attachment",
                        flags=[f for f in att.flags if f == "type_mismatch"])
            for part in att.parts:
                builder.add(part.field, part.text, origin="attachment", flags=part.flags)
            file_hashes.append(att.sha256)
        if attachments:
            facts["attachment_count"] = len(attachments)
            facts["attachment_parse_failed"] = any(a.parse_failed for a in attachments)
            facts["attachment_hidden_content"] = any(a.hidden_content for a in attachments)
            facts["attachment_has_macros"] = any(a.has_macros for a in attachments)

        # Payload keys the registry does not know: untrusted evidence, counted.
        coverage = _label_coverage(raw, payload)
        for key in coverage.unlabelled:
            value = payload.get(key) if "." not in key else (payload.get("email") or {}).get(key.split(".", 1)[1])
            builder.add(f"unlabelled.{key}", str(value), flags=["unlabelled"])

        if self._enrich:
            report = self._enrichment(facts, urls, file_hashes, sender_domain)
            for key in ("ip_abuse_score", "asn", "sender_domain_age_days"):
                if facts.get(key) is None and getattr(report, key) is not None:
                    facts[key] = getattr(report, key)
            if facts.get("url_reputation", "unknown") == "unknown":
                facts["url_reputation"] = report.url_reputation
            if facts.get("sandbox_verdict", "not_run") == "not_run":
                facts["sandbox_verdict"] = report.sandbox_verdict
            if report.failed:
                facts["enrichment_failed"] = True
            notes.extend(report.sources)
            notes.extend(f"enrichment lookup failed: {f}" for f in report.failed)

        alert = Alert(
            alert_id=raw.alert_id,
            source=raw.source,
            severity=raw.severity,
            original_severity=raw.severity,
            facts=TypedFacts.model_validate(facts),
            evidence=builder.items,
            label_coverage=coverage,
        )
        self._detect(alert, builder)
        self.notes = notes
        return alert

    def _email(self, raw: RawAlert, builder: EvidenceBuilder, facts: dict[str, Any], notes: list[str]) -> ParsedEmail | None:
        email_block = raw.email or {}
        data: bytes | None = None
        if email_block.get("raw_b64"):
            try:
                data = base64.b64decode(email_block["raw_b64"])
            except (binascii.Error, ValueError):
                notes.append("email.raw_b64 is not valid base64")
        elif email_block.get("raw"):
            data = str(email_block["raw"]).encode("utf-8", errors="replace")
        if data is None:
            return None
        try:
            parsed = parse_email(data, trusted_authserv_id=self.settings.mta_authserv_id)
        except Exception as exc:  # unparseable email: keep it as one flagged evidence item
            builder.add("email.raw", data.decode("utf-8", errors="replace"), flags=["unparseable"])
            notes.append(f"email parse failed: {type(exc).__name__}")
            return None

        auth = parsed.auth
        envelope = email_block.get("envelope") or {}
        if auth.source == "none" and envelope:
            auth = live_auth(data, parsed.from_domain, envelope)
        if auth.source == "none":
            notes.append("email auth: TRUSTGATE_MTA_AUTHSERV_ID not set and no envelope; SPF/DKIM/DMARC unknown")
        for key in ("spf_pass", "dkim_pass", "dmarc_pass"):
            if facts.get(key) is None and getattr(auth, key) is not None:
                facts[key] = getattr(auth, key)

        builder.add("email.from_display", parsed.from_display)
        builder.add("email.from_address", parsed.from_address)
        builder.add("email.subject", parsed.subject)
        builder.add("email.body", parsed.body_text, is_html=False)
        builder.add("email.body_html", parsed.body_html, is_html=True)
        for name, value in parsed.untrusted_headers.items():
            builder.add(f"email.header.{name}", value)
        for value in parsed.spoofed_auth_headers:
            builder.add("email.header.Authentication-Results(spoofed)", value, flags=["spoofed_metadata"])
        return parsed

    def _enrichment(self, facts: dict[str, Any], urls: list[str], hashes: list[str], domain: str) -> EnrichmentReport:
        ips = [str(ip) for ip in facts.get("ioc_ips", [])]
        try:
            return self.threat_intel.enrich(ips=ips, urls=urls, file_hashes=hashes, sender_domain=domain)
        except Exception as exc:
            report = EnrichmentReport()
            report.sources.append(f"enrichment failed: {type(exc).__name__}")
            report.failed.append(f"enrichment: {type(exc).__name__}")
            return report

    def _detect(self, alert: Alert, builder: EvidenceBuilder) -> None:
        result = self.detector.scan(builder.scan_parts)
        alert.ioc_signals = result.signals
        alert.detector_score = result.score
        alert.detectors_run = result.detectors_run
        raised = 0
        if result.flagged:
            alert.tags.append(AI_EVASION_TAG)
            raised += 1
        hidden_flags = {"hidden_text", "truncated", "zero_width", "bidi_control", "spoofed_metadata"}
        if any(hidden_flags & set(e.flags) for e in alert.evidence):
            alert.tags.append(HIDDEN_CONTENT_TAG)
            raised += 1
        if raised:
            alert.severity = _raise(alert.severity, raised)
