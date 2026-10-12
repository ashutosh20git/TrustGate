"""Ingest service: raw alert in, labelled alert out (blueprint stage 1).

    uvicorn services.ingest.main:create_app --factory --port 8081

Holds the threat-intel API keys; the agent never sees them. Every endpoint but
/healthz needs the ingest bearer token (TRUSTGATE_INGEST_TOKEN or the Docker
secret ingest_token): alerts carry typed facts the gate trusts, and the stored
evidence holds attacker text and personal data.
"""

from __future__ import annotations

import asyncio
import hmac
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.responses import PlainTextResponse
from pydantic import ValidationError

from trustgate.config import Settings
from trustgate.ingest.split import Splitter
from trustgate.render import render_alert
from trustgate.store import Store


def create_app(splitter: Splitter | None = None, store: Store | None = None) -> FastAPI:
    settings = Settings()
    splitter = splitter or Splitter(settings)
    store = store or Store(settings=settings)
    app = FastAPI(title="TrustGate ingest", version="2.0.0")

    def require_token(authorization: str | None = Header(default=None)) -> None:
        if not settings.ingest_token:
            raise HTTPException(503, "ingest authentication not configured; run scripts/init_secrets.py")
        scheme, _, token = (authorization or "").partition(" ")
        if scheme != "Bearer" or not hmac.compare_digest(token.encode(), settings.ingest_token.encode()):
            raise HTTPException(401, "a valid ingest token is required")

    @app.post("/v1/alerts", dependencies=[Depends(require_token)])
    async def post_alert(payload: dict[str, Any]) -> dict[str, Any]:
        try:
            alert = await asyncio.to_thread(splitter.split, payload)
        except ValidationError as exc:
            raise HTTPException(422, f"invalid alert: {exc.error_count()} errors") from None
        store.put_alert(alert)
        return {"alert": alert.model_dump(mode="json"), "notes": splitter.notes}

    @app.get("/v1/alerts/{alert_id}", dependencies=[Depends(require_token)])
    def get_alert(alert_id: str) -> dict[str, Any]:
        alert = store.get_alert(alert_id)
        if alert is None:
            raise HTTPException(404)
        return alert.model_dump(mode="json")

    @app.get("/v1/alerts/{alert_id}/rendered", response_class=PlainTextResponse,
             dependencies=[Depends(require_token)])
    def rendered(alert_id: str) -> str:
        alert = store.get_alert(alert_id)
        if alert is None:
            raise HTTPException(404)
        return render_alert(alert)

    @app.get("/v1/alerts", dependencies=[Depends(require_token)])
    def list_alerts(limit: int = Query(100, ge=1, le=1_000)) -> list[dict[str, Any]]:
        return [{"alert_id": a.alert_id, "source": a.source, "severity": a.severity, "tags": a.tags,
                 "label_coverage": a.label_coverage.ratio} for a in store.list_alerts(limit)]

    @app.get("/healthz")
    def healthz() -> dict[str, Any]:
        return {"ok": True, "mta_authserv_id": bool(settings.mta_authserv_id),
                "auth_configured": bool(settings.ingest_token)}

    return app
