"""Detector container: model-based signals (Prompt Guard 2, LLM Guard), scores only.

    uvicorn services.detector.main:create_app --factory --port 8082

The ingest service runs the regex and stitch checks itself and calls this
service for the model signals (DETECTOR_URL). It holds model weights and no authority.
"""

from __future__ import annotations

import asyncio
import dataclasses
from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel

from trustgate.config import Settings
from trustgate.detector.ensemble import Detector, DetectorResult


class Part(BaseModel):
    evidence_id: str
    text: str


class ScanRequest(BaseModel):
    parts: list[Part]


def create_app() -> FastAPI:
    settings = Settings()
    # This container never calls itself: model signals run in-process here.
    detector = Detector(dataclasses.replace(settings, detector_url=None))
    app = FastAPI(title="TrustGate detector", version="2.0.0")

    @app.post("/v1/scan")
    async def scan(req: ScanRequest) -> dict[str, Any]:
        result = DetectorResult()
        parts = [(p.evidence_id, p.text) for p in req.parts]
        scores = await asyncio.to_thread(detector.local_model_signals, parts, result)
        return {"signals": [s.model_dump() for s in result.signals], "model_scores": scores,
                "detectors_run": result.detectors_run}

    @app.get("/healthz")
    def healthz() -> dict[str, Any]:
        result = DetectorResult()
        detector.local_model_signals([("ev-1", "health check")], result)
        return {"detectors_run": result.detectors_run}

    return app
