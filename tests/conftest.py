"""Shared fixtures: an in-memory store, an OPA-backed gate, and a labelled alert."""

from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

from trustgate.config import Settings
from trustgate.detector import Detector
from trustgate.gate import Gate
from trustgate.ingest.split import Splitter
from trustgate.policy_client import OPACliClient, load_pack
from trustgate.ratelimit import MemoryRateLimiter
from trustgate.store import Store

OPA_BIN = ".tools/opa.exe" if os.name == "nt" else ".tools/opa"


def opa_available() -> bool:
    return Path(OPA_BIN).exists() or shutil.which("opa") is not None


requires_opa = pytest.mark.skipif(not opa_available(), reason="needs the OPA binary (.tools/opa or opa on PATH)")


@pytest.fixture
def settings(monkeypatch) -> Settings:
    monkeypatch.setenv("TRUSTGATE_MTA_AUTHSERV_ID", "mx.corp.example")
    monkeypatch.setenv("TRUSTGATE_RATELIMIT_BACKEND", "memory")
    return Settings()


@pytest.fixture
def store(tmp_path, settings) -> Store:
    return Store(f"sqlite:///{tmp_path}/t.db", settings=settings)


@pytest.fixture
def opa_engine():
    pack = load_pack("packs/soc.rego")
    binary = OPA_BIN if Path(OPA_BIN).exists() else (shutil.which("opa") or OPA_BIN)
    return OPACliClient(binary, pack.packs_dir, "soc")


def facts_recheck(facts):
    """Deterministic facts-only re-check for tests (stands in for the small model)."""
    if facts.dmarc_pass is False or facts.url_reputation == "malicious" or facts.sandbox_verdict == "malicious":
        return "malicious"
    if (facts.ip_abuse_score or 0) >= 50 or facts.attachment_has_macros or facts.attachment_parse_failed:
        return "malicious"
    return "benign"


@pytest.fixture
def gate(settings, store, opa_engine) -> Gate:
    return Gate("packs/soc.rego", recheck=facts_recheck, mode="enforce", settings=settings, store=store,
                policy_engine=opa_engine, limiter=MemoryRateLimiter())


@pytest.fixture
def splitter(settings) -> Splitter:
    return Splitter(settings, detector=Detector(settings, use_models=False), enrich=False)
