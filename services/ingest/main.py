"""Ingest service: raw alert in, labelled alert out (blueprint stage 1).

    uvicorn services.ingest.main:create_app --factory --port 8081

Holds the threat-intel API keys; the agent never sees them.
"""

from __future__ import annotations

import asyncio
from typing import Any

from fastapi import FastAPI, HTTPException
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

    @app.post("/v1/alerts")
    async def post_alert(payload: dict[str, Any]) -> dict[str, Any]:
        try:
            alert = await asyncio.to_thread(splitter.split, payload)
        except ValidationError as exc:
            raise HTTPException(422, f"invalid alert: {exc.error_count()} errors") from None
        store.put_alert(alert)
        return {"alert": alert.model_dump(mode="json"), "notes": splitter.notes}

    @app.get("/v1/alerts/{alert_id}")
    def get_alert(alert_id: str) -> dict[str, Any]:
        alert = store.get_alert(alert_id)
        if alert is None:
            raise HTTPException(404)
        return alert.model_dump(mode="json")

    @app.get("/v1/alerts/{alert_id}/rendered", response_class=PlainTextResponse)
    def rendered(alert_id: str) -> str:
        alert = store.get_alert(alert_id)
        if alert is None:
            raise HTTPException(404)
        return render_alert(alert)

    @app.get("/v1/alerts")
    def list_alerts(limit: int = 100) -> list[dict[str, Any]]:
        return [{"alert_id": a.alert_id, "source": a.source, "severity": a.severity, "tags": a.tags,
                 "label_coverage": a.label_coverage.ratio} for a in store.list_alerts(limit)]

    @app.get("/healthz")
    def healthz() -> dict[str, Any]:
        return {"ok": True, "mta_authserv_id": bool(settings.mta_authserv_id)}

    return app
