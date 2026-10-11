"""Mock SOC service (FastAPI + SQLite). Holds sandbox state only.

    uvicorn services.mock_soc.main:create_app --factory --port 8090

Every endpoint needs the bearer token in MOCK_SOC_TOKEN (a Docker secret held by
the proxy). If no token is configured the service refuses everything.
"""

from __future__ import annotations

import datetime as dt
import os
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel
from sqlalchemy import JSON, Column, Text
from sqlmodel import Field, Session, SQLModel, create_engine, delete, select

from trustgate.config import Settings


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


class Effect(SQLModel, table=True):
    __tablename__ = "mock_soc_effect"
    id: int | None = Field(default=None, primary_key=True)
    ts: dt.datetime = Field(default_factory=_now)
    kind: str = Field(index=True)
    alert_id: str | None = Field(default=None, index=True)
    data: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))


class LogLine(SQLModel, table=True):
    __tablename__ = "mock_soc_log"
    id: int | None = Field(default=None, primary_key=True)
    alert_id: str = Field(index=True)
    line: str = Field(sa_column=Column(Text))


class AlertArgs(BaseModel):
    alert_id: str


class Reason(AlertArgs):
    reason: str = ""


class SeverityArgs(AlertArgs):
    severity: str


class NoteArgs(AlertArgs):
    text: str


class RuleArgs(AlertArgs):
    rule: str
    reason: str = ""
    ttl_hours: float | None = None


class IndicatorArgs(AlertArgs):
    indicator: str
    reason: str = ""
    ttl_hours: float | None = None


def _expires_at(ttl_hours: float | None) -> str | None:
    return None if ttl_hours is None else (_now() + dt.timedelta(hours=ttl_hours)).isoformat()


class IpArgs(AlertArgs):
    ip: str


class HostArgs(AlertArgs):
    host: str


class AccountArgs(AlertArgs):
    account: str


class EmailArgs(AlertArgs):
    to: str
    subject: str = ""
    body: str = ""


class WebhookArgs(AlertArgs):
    url: str
    payload: str = ""


class SeedLogs(AlertArgs):
    lines: list[str]


def create_app(database_url: str | None = None, token: str | None = None) -> FastAPI:
    settings = Settings()
    url = database_url or os.environ.get("MOCK_SOC_DATABASE_URL", "sqlite:///./mock_soc.db")
    engine = create_engine(url, connect_args={"check_same_thread": False} if url.startswith("sqlite") else {})
    SQLModel.metadata.create_all(engine, tables=[Effect.__table__, LogLine.__table__])
    expected = token if token is not None else settings.mock_soc_token

    def require_token(authorization: str = Header(default="")) -> None:
        if not expected:
            raise HTTPException(503, "MOCK_SOC_TOKEN not configured")
        if authorization != f"Bearer {expected}":
            raise HTTPException(401, "invalid token")

    app = FastAPI(title="Mock SOC (sandbox)", dependencies=[Depends(require_token)])

    def record(kind: str, alert_id: str | None, data: dict[str, Any]) -> dict[str, Any]:
        with Session(engine) as s:
            effect = Effect(kind=kind, alert_id=alert_id, data=data)
            s.add(effect)
            s.commit()
            return {"ok": True, "effect_id": effect.id, "kind": kind}

    @app.post("/tickets/close")
    def close(a: Reason):
        return record("ticket.close", a.alert_id, {"reason": a.reason})

    @app.post("/tickets/downgrade")
    def downgrade(a: SeverityArgs):
        return record("ticket.downgrade", a.alert_id, {"severity": a.severity})

    @app.post("/tickets/raise_severity")
    def raise_severity(a: SeverityArgs):
        return record("ticket.raise_severity", a.alert_id, {"severity": a.severity})

    @app.post("/tickets/note")
    def note(a: NoteArgs):
        return record("ticket.note", a.alert_id, {"text": a.text})

    @app.post("/tickets/escalate")
    def escalate(a: Reason):
        return record("ticket.escalate", a.alert_id, {"reason": a.reason})

    @app.post("/rules/suppress")
    def suppress(a: RuleArgs):
        return record("rule.suppress", a.alert_id, {"rule": a.rule, "reason": a.reason,
                                                    "expires_at": _expires_at(a.ttl_hours)})

    @app.post("/whitelist/add")
    def whitelist(a: IndicatorArgs):
        return record("whitelist.add", a.alert_id, {"indicator": a.indicator, "reason": a.reason,
                                                    "expires_at": _expires_at(a.ttl_hours)})

    @app.post("/firewall/block")
    def block(a: IpArgs):
        return record("firewall.block", a.alert_id, {"ip": a.ip})

    @app.post("/edr/isolate")
    def isolate(a: HostArgs):
        return record("edr.isolate", a.alert_id, {"host": a.host})

    @app.post("/iam/disable")
    def disable(a: AccountArgs):
        return record("iam.disable", a.alert_id, {"account": a.account})

    @app.post("/outbox/send")
    def send(a: EmailArgs):
        # Local outbox only: nothing leaves the sandbox.
        return record("outbox.email", a.alert_id, {"to": a.to, "subject": a.subject, "body": a.body})

    @app.post("/webhook/post")
    def webhook(a: WebhookArgs):
        return record("outbox.webhook", a.alert_id, {"url": a.url, "payload": a.payload})

    @app.get("/logs")
    def logs(alert_id: str):
        with Session(engine) as s:
            return {"alert_id": alert_id,
                    "lines": [r.line for r in s.exec(select(LogLine).where(LogLine.alert_id == alert_id)).all()]}

    @app.post("/logs/seed")
    def seed(a: SeedLogs):
        with Session(engine) as s:
            for line in a.lines:
                s.add(LogLine(alert_id=a.alert_id, line=line))
            s.commit()
        return {"ok": True, "count": len(a.lines)}

    @app.get("/state")
    def state(alert_id: str | None = None):
        with Session(engine) as s:
            q = select(Effect).order_by(Effect.id)
            if alert_id:
                q = q.where(Effect.alert_id == alert_id)
            return {"effects": [e.model_dump(mode="json") for e in s.exec(q).all()]}

    @app.post("/reset")
    def reset():
        with Session(engine) as s:
            s.exec(delete(Effect))
            s.exec(delete(LogLine))
            s.commit()
        return {"ok": True}

    return app
