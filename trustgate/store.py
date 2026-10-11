"""Storage: labelled alerts, the audit trail, the escalation queue and MCP tool pins.

SQLModel over SQLite (default) or PostgreSQL (DATABASE_URL). Each audit record
carries the hash of the previous one, so the trail is tamper-evident. Every
record also goes to structlog and, when configured, to the JSON-lines SIEM
stream and Splunk HEC (v2 "SIEM export").
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import threading
import uuid
from typing import Any

import httpx
import structlog
from sqlalchemy import JSON, Column, Text
from sqlmodel import Field, Session, SQLModel, create_engine, select

from trustgate.config import Settings
from trustgate.models import Alert, GateDecision, ProposedAction

log = structlog.get_logger("trustgate.audit")


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _utc_iso(value: dt.datetime | None) -> str | None:
    """Stable text for hashing, whether the database hands back aware or naive UTC."""
    if value is None:
        return None
    if value.tzinfo is not None:
        value = value.astimezone(dt.timezone.utc).replace(tzinfo=None)
    return value.isoformat()


def _id() -> str:
    return uuid.uuid4().hex[:16]


class AlertRecord(SQLModel, table=True):
    alert_id: str = Field(primary_key=True)
    created_at: dt.datetime = Field(default_factory=_now)
    payload: str = Field(sa_column=Column(Text))


class AuditRecord(SQLModel, table=True):
    seq: int | None = Field(default=None, primary_key=True)  # insertion order for the hash chain
    id: str = Field(default_factory=_id, index=True, unique=True)
    ts: dt.datetime = Field(default_factory=_now, index=True)
    kind: str = Field(default="decision", index=True)  # decision, execution, analyst, mcp_pin, fail_closed
    alert_id: str | None = Field(default=None, index=True)
    tool: str | None = None
    tier: int | None = None
    decision: str | None = None
    mode: str | None = None
    enforced: bool | None = None
    pack: str | None = None
    reasons: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    recheck_verdict: str | None = None
    tainted_spans: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    latency_ms: float | None = None
    recheck_tokens: int | None = None
    details: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    prev_hash: str = ""
    record_hash: str = ""


class Escalation(SQLModel, table=True):
    id: str = Field(default_factory=_id, primary_key=True)
    created_at: dt.datetime = Field(default_factory=_now, index=True)
    status: str = Field(default="open", index=True)  # open, approved, rejected
    alert_id: str = Field(index=True)
    tool: str
    tier: int | None = None
    action: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    reasons: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    tainted_spans: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    recheck_verdict: str | None = None
    dedupe_key: str = Field(index=True)
    duplicates: int = 0
    canary: bool = False
    analyst: str | None = None
    analyst_reason: str | None = None
    decided_at: dt.datetime | None = None
    result: dict[str, Any] | None = Field(default=None, sa_column=Column(JSON))


class ToolPin(SQLModel, table=True):
    server: str = Field(primary_key=True)
    name: str = Field(primary_key=True)
    sha256: str
    description: str = Field(sa_column=Column(Text))
    input_schema: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    status: str = "pinned"  # pinned, disabled (changed), quarantined (scan or shadowing)
    reasons: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    pinned_at: dt.datetime = Field(default_factory=_now)
    approved_by: str | None = None
    last_seen_sha256: str = ""
    last_seen_description: str = Field(default="", sa_column=Column(Text))
    last_seen_schema: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))


class ActionRecord(SQLModel, table=True):
    """An executed T1/T2 action and how to undo it (automatic rollback, sequence policy)."""

    id: str = Field(default_factory=_id, primary_key=True)
    ts: dt.datetime = Field(default_factory=_now, index=True)
    alert_id: str = Field(index=True)
    tool: str
    tier: int
    args: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    via: str = "gate"  # gate, approval, mcp_gateway
    undo_tool: str | None = None
    undo_args: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    status: str = Field(default="executed", index=True)  # executed, reverted, revert_failed
    reverted_at: dt.datetime | None = None
    reverted_by: str | None = None
    revert_reason: str | None = None


class ToolResponseShape(SQLModel, table=True):
    """Baseline shape of an MCP tool's successful responses (content types, structured keys)."""

    server: str = Field(primary_key=True)
    name: str = Field(primary_key=True)
    content_types: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    structured_keys: list[str] | None = Field(default=None, sa_column=Column(JSON))
    first_seen: dt.datetime = Field(default_factory=_now)


class Store:
    def __init__(self, database_url: str | None = None, *, settings: Settings | None = None):
        self.settings = settings or Settings()
        url = database_url or self.settings.database_url
        connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
        self.engine = create_engine(url, connect_args=connect_args)
        SQLModel.metadata.create_all(self.engine)
        self._audit_lock = threading.Lock()
        self._hec = httpx.Client(timeout=5) if self.settings.splunk_hec_url and self.settings.splunk_hec_token else None

    def session(self) -> Session:
        return Session(self.engine, expire_on_commit=False)

    # --- alerts ---------------------------------------------------------------

    def put_alert(self, alert: Alert) -> None:
        with self.session() as s:
            s.merge(AlertRecord(alert_id=alert.alert_id, payload=alert.model_dump_json()))
            s.commit()

    def get_alert(self, alert_id: str) -> Alert | None:
        with self.session() as s:
            rec = s.get(AlertRecord, alert_id)
            return Alert.model_validate_json(rec.payload) if rec else None

    def list_alerts(self, limit: int = 100) -> list[Alert]:
        with self.session() as s:
            rows = s.exec(select(AlertRecord).order_by(AlertRecord.created_at.desc()).limit(limit)).all()
            return [Alert.model_validate_json(r.payload) for r in rows]

    # --- audit ----------------------------------------------------------------

    def audit(self, kind: str, *, alert_id: str | None = None, tool: str | None = None,
              decision: GateDecision | None = None, details: dict[str, Any] | None = None) -> AuditRecord:
        with self._audit_lock, self.session() as s:
            last = s.exec(select(AuditRecord).order_by(AuditRecord.seq.desc()).limit(1)).first()
            rec = AuditRecord(kind=kind, alert_id=alert_id, tool=tool, details=details or {},
                              prev_hash=last.record_hash if last else "")
            if decision is not None:
                rec.tier = decision.tier
                rec.decision = decision.decision
                rec.mode = decision.mode
                rec.enforced = decision.enforced
                rec.pack = decision.pack
                rec.reasons = decision.reasons
                rec.recheck_verdict = decision.recheck_verdict
                rec.tainted_spans = decision.tainted_spans
                rec.latency_ms = decision.latency_ms
                rec.recheck_tokens = decision.recheck_tokens
            rec.record_hash = hashlib.sha256((rec.prev_hash + _canonical(rec)).encode()).hexdigest()
            s.add(rec)
            s.commit()
        self._export(rec)
        return rec

    def audit_trail(self, alert_id: str | None = None, limit: int = 500) -> list[AuditRecord]:
        with self.session() as s:
            q = select(AuditRecord).order_by(AuditRecord.seq)
            if alert_id:
                q = q.where(AuditRecord.alert_id == alert_id)
            return list(s.exec(q.limit(limit)).all())

    def verify_audit_chain(self) -> bool:
        prev = ""
        for rec in self.audit_trail(limit=1_000_000):
            if rec.prev_hash != prev:
                return False
            if hashlib.sha256((rec.prev_hash + _canonical(rec)).encode()).hexdigest() != rec.record_hash:
                return False
            prev = rec.record_hash
        return True

    def _export(self, rec: AuditRecord) -> None:
        event = json.loads(rec.model_dump_json())
        log.info("trustgate.audit", **{k: v for k, v in event.items() if k in ("kind", "alert_id", "tool", "decision", "tier", "mode")})
        if self.settings.siem_jsonl_path:
            with open(self.settings.siem_jsonl_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(event, sort_keys=True) + "\n")
        if self._hec is not None:
            try:
                self._hec.post(self.settings.splunk_hec_url,
                               headers={"Authorization": f"Splunk {self.settings.splunk_hec_token}"},
                               json={"event": event, "sourcetype": "trustgate:audit"})
            except httpx.HTTPError:
                log.warning("trustgate.siem_export_failed", audit_id=rec.id)

    # --- action ledger ----------------------------------------------------------

    def record_action(self, rec: ActionRecord) -> ActionRecord:
        with self.session() as s:
            s.add(rec)
            s.commit()
            return rec

    def get_action(self, action_id: str) -> ActionRecord | None:
        with self.session() as s:
            return s.get(ActionRecord, action_id)

    def actions(self, alert_id: str | None = None, *, status: str | None = None,
                since: dt.datetime | None = None, limit: int = 500) -> list[ActionRecord]:
        with self.session() as s:
            q = select(ActionRecord).order_by(ActionRecord.ts.desc())
            if alert_id:
                q = q.where(ActionRecord.alert_id == alert_id)
            if status:
                q = q.where(ActionRecord.status == status)
            if since is not None:
                q = q.where(ActionRecord.ts >= since)
            return list(s.exec(q.limit(limit)).all())

    def update_action(self, rec: ActionRecord) -> None:
        with self.session() as s:
            s.merge(rec)
            s.commit()

    def analyst_scores(self, *, min_decisions: int = 10, fast_s: float = 15.0,
                       high_approval: float = 0.95) -> dict[str, Any]:
        """Is the human queue still a check? Per analyst: decisions, approval rate, canaries
        approved (a planted known-bad item waved through), and decision speed.

        Flags, each with its reason: any canary approved; or, with at least
        min_decisions, approving almost everything or deciding faster than fast_s
        seconds at the median (rubber-stamping). A flag asks for a review of the
        analyst's queue, not a verdict on the person.
        """
        rows: dict[str, dict[str, Any]] = {}
        for esc in self.escalations(None, limit=1_000_000):
            if esc.status == "open" or not esc.analyst or esc.status == "expired":
                continue
            row = rows.setdefault(esc.analyst, {"analyst": esc.analyst, "decisions": 0, "approved": 0,
                                                "rejected": 0, "canary_caught": 0, "canary_missed": 0,
                                                "_latencies": []})
            row["decisions"] += 1
            if esc.status in ("approved", "failed"):
                row["approved"] += 1
            elif esc.status == "rejected":
                row["rejected"] += 1
            if esc.canary:
                outcome = (esc.result or {}).get("canary")
                if outcome in ("canary_caught", "canary_missed"):
                    row[outcome] += 1
            if esc.decided_at is not None:
                created = esc.created_at if esc.created_at.tzinfo else esc.created_at.replace(tzinfo=dt.timezone.utc)
                decided = esc.decided_at if esc.decided_at.tzinfo else esc.decided_at.replace(tzinfo=dt.timezone.utc)
                row["_latencies"].append(max(0.0, (decided - created).total_seconds()))
        out = []
        for row in sorted(rows.values(), key=lambda r: r["analyst"]):
            latencies = sorted(row.pop("_latencies"))
            row["approval_rate"] = round(row["approved"] / row["decisions"], 4) if row["decisions"] else 0.0
            row["median_decision_s"] = latencies[len(latencies) // 2] if latencies else None
            flags = []
            if row["canary_missed"]:
                flags.append(f"approved {row['canary_missed']} planted known-bad canary item(s)")
            if row["decisions"] >= min_decisions and row["approval_rate"] >= high_approval:
                flags.append(f"approves {row['approval_rate']:.0%} of escalations")
            if (row["decisions"] >= min_decisions and row["median_decision_s"] is not None
                    and row["median_decision_s"] < fast_s):
                flags.append(f"median decision in {row['median_decision_s']:.0f} s")
            row["flags"] = flags
            row["review"] = bool(flags)
            out.append(row)
        return {"criteria": f"review if any canary approved; or, with {min_decisions}+ decisions, approval rate "
                            f">= {high_approval:.0%} or median decision under {fast_s:g} s",
                "analysts": out}

    def rollout_report(self, *, min_samples: int = 50) -> dict[str, Any]:
        """Monitor-mode readiness per tool: what enforcing would have blocked, and why.

        A tool is ready to enforce once it has min_samples monitor decisions and
        none failed closed (a failing dependency would block everything once
        enforced). Would-block counts are shown, not judged: blocked attacks are
        the point, so an analyst reviews the top reasons before switching.
        """
        tools: dict[str, dict[str, Any]] = {}
        for rec in self.audit_trail(limit=1_000_000):
            if rec.kind != "decision" or rec.mode != "monitor" or not rec.tool:
                continue
            row = tools.setdefault(rec.tool, {"tool": rec.tool, "tier": rec.tier, "decisions": 0,
                                              "would_block": 0, "fail_closed": 0, "_reasons": {}})
            row["decisions"] += 1
            if rec.decision != "allow":
                row["would_block"] += 1
                for reason in rec.reasons or []:
                    if reason != "monitor mode: would block":
                        row["_reasons"][reason] = row["_reasons"].get(reason, 0) + 1
            if (rec.details or {}).get("fail_closed"):
                row["fail_closed"] += 1
        out = []
        for row in sorted(tools.values(), key=lambda r: r["tool"]):
            reasons = row.pop("_reasons")
            row["would_block_rate"] = round(row["would_block"] / row["decisions"], 4)
            row["top_reasons"] = [r for r, _ in sorted(reasons.items(), key=lambda kv: -kv[1])[:3]]
            row["ready_to_enforce"] = row["decisions"] >= min_samples and row["fail_closed"] == 0
            out.append(row)
        return {"criteria": f"ready = at least {min_samples} monitor decisions and none failed closed; "
                            "review top would-block reasons before enforcing",
                "tools": out}

    # --- escalations ----------------------------------------------------------

    def open_escalation(self, action: ProposedAction, decision: GateDecision, *, canary: bool = False) -> Escalation:
        key = hashlib.sha256(json.dumps([action.alert_id, action.tool, action.args], sort_keys=True,
                                        default=str).encode()).hexdigest()[:24]
        with self.session() as s:
            existing = s.exec(select(Escalation).where(Escalation.dedupe_key == key,
                                                       Escalation.status == "open")).first()
            if existing and not canary:
                existing.duplicates += 1  # deduplicated (silent failure 22)
                s.add(existing)
                s.commit()
                return existing
            esc = Escalation(alert_id=action.alert_id, tool=action.tool, tier=decision.tier,
                             action=action.model_dump(), reasons=decision.reasons,
                             tainted_spans=decision.tainted_spans, recheck_verdict=decision.recheck_verdict,
                             dedupe_key=key, canary=canary)
            s.add(esc)
            s.commit()
            return esc

    def escalations(self, status: str | None = "open", limit: int = 200) -> list[Escalation]:
        with self.session() as s:
            q = select(Escalation).order_by(Escalation.created_at.desc())
            if status:
                q = q.where(Escalation.status == status)
            return list(s.exec(q.limit(limit)).all())

    def get_escalation(self, esc_id: str) -> Escalation | None:
        with self.session() as s:
            return s.get(Escalation, esc_id)

    def close_escalation(self, esc_id: str, *, status: str, analyst: str, reason: str,
                         result: dict[str, Any] | None = None) -> Escalation:
        with self.session() as s:
            esc = s.get(Escalation, esc_id)
            if esc is None:
                raise KeyError(esc_id)
            esc.status = status
            esc.analyst = analyst
            esc.analyst_reason = reason
            esc.decided_at = _now()
            esc.result = result
            s.add(esc)
            s.commit()
            return esc

    # --- MCP tool pins ----------------------------------------------------------

    def get_pin(self, server: str, name: str) -> ToolPin | None:
        with self.session() as s:
            return s.get(ToolPin, (server, name))

    def put_pin(self, pin: ToolPin) -> None:
        with self.session() as s:
            s.merge(pin)
            s.commit()

    def get_shape(self, server: str, name: str) -> ToolResponseShape | None:
        with self.session() as s:
            return s.get(ToolResponseShape, (server, name))

    def put_shape(self, shape: ToolResponseShape) -> None:
        with self.session() as s:
            s.merge(shape)
            s.commit()

    def delete_shape(self, server: str, name: str) -> None:
        with self.session() as s:
            row = s.get(ToolResponseShape, (server, name))
            if row is not None:
                s.delete(row)
                s.commit()

    def pins(self, server: str | None = None) -> list[ToolPin]:
        with self.session() as s:
            q = select(ToolPin)
            if server:
                q = q.where(ToolPin.server == server)
            return list(s.exec(q).all())


def _canonical(rec: AuditRecord) -> str:
    body = rec.model_dump(exclude={"record_hash", "seq"})
    body["ts"] = _utc_iso(rec.ts)
    return json.dumps(body, sort_keys=True, default=str)
