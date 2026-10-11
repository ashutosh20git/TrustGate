"""Compliance evidence packs built from the hash-chained audit trail.

Evidence to support a review, not a compliance determination: TrustGate cannot
see where logs are stored, whether clocks follow the mandated time source, or
whether an event is legally reportable. Those items are listed as "confirm"
for a human. Frameworks:

* cert-in   CERT-In Directions of 28 April 2022 under section 70B(6) of the IT Act:
            report incidents within 6 hours of noticing them; keep ICT logs for a
            rolling 180 days within India; synchronise clocks to NIC/NPL NTP.
* dpdp      Digital Personal Data Protection Act 2023: section 8(5) reasonable
            security safeguards against personal data breach; section 8(6) intimate
            the Data Protection Board and each affected Data Principal of a breach.
* iso27001  ISO/IEC 27001:2022 Annex A 5.24-5.28 (incident management) and
            8.15-8.16 (logging, monitoring).
"""

from __future__ import annotations

import datetime as dt
from typing import Any

from trustgate.store import Store

FRAMEWORKS = ("cert-in", "dpdp", "iso27001")
DISCLAIMER = ("Evidence collected by TrustGate to support a compliance review. It is not a compliance "
              "determination; items marked 'confirm' need a human.")
CERT_IN_REPORT_HOURS = 6
CERT_IN_RETENTION_DAYS = 180
PERSONAL_ENTITIES = {"PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "IN_AADHAAR", "IN_PAN", "US_SSN", "CREDIT_CARD",
                     "IBAN_CODE", "US_DRIVER_LICENSE", "US_PASSPORT", "LOCATION", "IP_ADDRESS", "SENSITIVE"}


def _utc(value: dt.datetime) -> dt.datetime:
    return value if value.tzinfo else value.replace(tzinfo=dt.timezone.utc)


def collect(store: Store, now: dt.datetime | None = None) -> dict[str, Any]:
    """Framework-neutral evidence: log integrity and coverage, incidents, personal-data events,
    human decisions and rollbacks."""
    now = now or dt.datetime.now(dt.timezone.utc)
    records = store.audit_trail(limit=10_000_000)
    oldest = _utc(records[0].ts) if records else None

    incidents: dict[str, dict[str, Any]] = {}

    def incident(alert_id: str | None, ts: dt.datetime, why: str) -> None:
        if not alert_id:
            return
        row = incidents.setdefault(alert_id, {"alert_id": alert_id, "noticed_at": _utc(ts), "signals": []})
        row["noticed_at"] = min(row["noticed_at"], _utc(ts))
        if why not in row["signals"]:
            row["signals"].append(why)

    for alert in store.list_alerts(limit=1_000_000):
        if alert.ai_evasion_attempt:
            first = next((r.ts for r in records if r.alert_id == alert.alert_id), now)
            incident(alert.alert_id, first, "AI-evasion attempt in alert evidence")

    personal: list[dict[str, Any]] = []
    for r in records:
        details = r.details or {}
        if r.kind == "mcp_output":
            incident(r.alert_id, r.ts, "injection found in a tool result")
        if r.kind == "decision" and r.tier == 3:
            entities = sorted(set(details.get("output_entities", [])) & PERSONAL_ENTITIES)
            if entities:
                left = r.decision == "allow" or not r.enforced  # allowed (redacted) or monitor mode
                personal.append({"ts": _utc(r.ts).isoformat(), "alert_id": r.alert_id, "tool": r.tool,
                                 "entities": entities, "decision": r.decision, "enforced": r.enforced,
                                 "outcome": ("sent in monitor mode: possible breach" if not r.enforced and
                                             r.decision != "allow" else
                                             "sent with redaction" if left else "held for a human")})
                if not r.enforced and r.decision != "allow":
                    incident(r.alert_id, r.ts, "personal data sent while the gate was in monitor mode")
        if r.kind == "decision" and any("raw evidence" in x or "sensitive data" in x for x in (r.reasons or [])):
            incident(r.alert_id, r.ts, "attempted data exfiltration stopped")

    analyst = [r for r in records if r.kind == "analyst"]
    return {
        "generated_at": now.isoformat(),
        "logs": {
            "records": len(records),
            "hash_chain_intact": store.verify_audit_chain(),
            "oldest": oldest.isoformat() if oldest else None,
            "newest": _utc(records[-1].ts).isoformat() if records else None,
            "days_covered": round((now - oldest).total_seconds() / 86400, 2) if oldest else 0.0,
            "timestamps": "UTC, recorded by the gate host clock",
        },
        "incidents": [{**row, "noticed_at": row["noticed_at"].isoformat()}
                      for row in sorted(incidents.values(), key=lambda x: x["noticed_at"])],
        "personal_data_events": personal,
        "human_decisions": {
            "resolved": sum(1 for r in analyst if "approved" in (r.details or {})),
            "with_second_analyst": sum(1 for r in analyst if (r.details or {}).get("second_analyst")),
            "refused_approvals": sum(1 for r in analyst if (r.details or {}).get("refused")),
        },
        "rollbacks": sum(1 for r in records if r.kind == "revert" and (r.details or {}).get("status") == "reverted"),
        "fail_closed_decisions": sum(1 for r in records if r.kind == "decision" and (r.details or {}).get("fail_closed")),
    }


def report(store: Store, framework: str, now: dt.datetime | None = None) -> dict[str, Any]:
    if framework not in FRAMEWORKS:
        raise ValueError(f"framework must be one of {', '.join(FRAMEWORKS)}")
    ev = collect(store, now)
    builder = {"cert-in": _cert_in, "dpdp": _dpdp, "iso27001": _iso27001}[framework]
    return {"framework": framework, "disclaimer": DISCLAIMER, "controls": builder(ev), "evidence": ev}


def _status(ok: bool | None) -> str:
    return "met" if ok else "confirm" if ok is None else "gap"


def _cert_in(ev: dict[str, Any]) -> list[dict[str, Any]]:
    logs = ev["logs"]
    deadlines = []
    for inc in ev["incidents"]:
        noticed = dt.datetime.fromisoformat(inc["noticed_at"])
        deadlines.append({**inc, "report_by": (noticed + dt.timedelta(hours=CERT_IN_REPORT_HOURS)).isoformat()})
    return [
        {"id": "CERT-In 2022 (ii)", "requirement": "Report cyber incidents to CERT-In within 6 hours of noticing",
         "status": "confirm" if deadlines else "met",
         "evidence": f"{len(deadlines)} incident candidate(s) with noticed time and 6-hour deadline; a human "
                     "decides which are reportable", "items": deadlines},
        {"id": "CERT-In 2022 (iv)", "requirement": "Keep ICT system logs for a rolling 180 days within India",
         # Never "met": TrustGate cannot see where the logs are stored.
         "status": "gap" if not logs["hash_chain_intact"] else "confirm",
         "evidence": f"{logs['records']} audit records covering {logs['days_covered']} days; hash chain "
                     f"{'intact' if logs['hash_chain_intact'] else 'BROKEN'}. Confirm the storage location "
                     "is in India and the retention policy is 180+ days."},
        {"id": "CERT-In 2022 (i)", "requirement": "Synchronise ICT clocks to NIC or NPL NTP servers",
         "status": "confirm", "evidence": "Timestamps are UTC from the gate host; confirm the host's NTP source."},
    ]


def _dpdp(ev: dict[str, Any]) -> list[dict[str, Any]]:
    events = ev["personal_data_events"]
    possible = [e for e in events if e["outcome"].startswith("sent in monitor mode")]
    return [
        {"id": "DPDP 2023 s.8(5)", "requirement": "Reasonable security safeguards to prevent personal data breach",
         "status": "met" if not possible else "gap",
         "evidence": f"{len(events)} outbound action(s) carried personal data: "
                     f"{sum(1 for e in events if e['outcome'] == 'held for a human')} held for a human, "
                     f"{sum(1 for e in events if e['outcome'] == 'sent with redaction')} sent with redaction, "
                     f"{len(possible)} sent while in monitor mode.", "items": events},
        {"id": "DPDP 2023 s.8(6)", "requirement": "Intimate the Board and each affected Data Principal of a "
                                                 "personal data breach",
         "status": "confirm" if possible else "met",
         "evidence": f"{len(possible)} possible breach(es) to assess (personal data left while the gate only "
                     "monitored). Timelines and form follow the DPDP Rules.", "items": possible},
    ]


def _iso27001(ev: dict[str, Any]) -> list[dict[str, Any]]:
    logs, human = ev["logs"], ev["human_decisions"]
    return [
        {"id": "A.5.24", "requirement": "Incident management planning and preparation", "status": "confirm",
         "evidence": "Escalation queue, two-analyst approvals for T2/T3, canaries and rollback exist; confirm "
                     "they are in the documented incident procedure."},
        {"id": "A.5.25", "requirement": "Assessment and decision on information security events", "status": "met",
         "evidence": f"Every tool call has a recorded gate decision; {human['resolved']} human decision(s), "
                     f"{human['with_second_analyst']} with a second analyst, {human['refused_approvals']} "
                     "approval(s) refused on re-check."},
        {"id": "A.5.26", "requirement": "Response to information security incidents", "status": "met",
         "evidence": f"{len(ev['incidents'])} incident candidate(s); {ev['rollbacks']} automatic or analyst "
                     "rollback(s) of executed actions.", "items": ev["incidents"]},
        {"id": "A.5.27", "requirement": "Learning from information security incidents", "status": "confirm",
         "evidence": "Escalation reasons, counterfactual explanations and analyst scores are available; confirm "
                     "they feed a post-incident review."},
        {"id": "A.5.28", "requirement": "Collection of evidence",
         "status": _status(logs["hash_chain_intact"]),
         "evidence": f"Hash-chained audit trail, {logs['records']} records, chain "
                     f"{'intact' if logs['hash_chain_intact'] else 'BROKEN'}."},
        {"id": "A.8.15", "requirement": "Logging", "status": _status(logs["records"] > 0 and logs["hash_chain_intact"]),
         "evidence": f"Records from {logs['oldest']} to {logs['newest']}; SIEM export via JSON lines / Splunk HEC "
                     "when configured."},
        {"id": "A.8.16", "requirement": "Monitoring activities", "status": "met",
         "evidence": f"{ev['fail_closed_decisions']} fail-closed decision(s) recorded; monitor-mode rollout "
                     "report and analyst scores available."},
    ]


def to_markdown(rep: dict[str, Any]) -> str:
    lines = [f"# TrustGate compliance evidence: {rep['framework']}", "", f"_{rep['disclaimer']}_", "",
             f"Generated {rep['evidence']['generated_at']}", "", "| Control | Requirement | Status | Evidence |",
             "|---|---|---|---|"]
    for c in rep["controls"]:
        lines.append(f"| {c['id']} | {c['requirement']} | {c['status']} | {c['evidence']} |")
    return "\n".join(lines) + "\n"
