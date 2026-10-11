"""Runtime settings from environment variables.

Anything that needs a key, a model or a running service is optional here and
raises NotConfigured at the point of use. In the gate, NotConfigured is an error
like any other, so T1-T3 actions fail closed until the placeholder is filled.
See PLACEHOLDERS.md for the tracking issue behind each one.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field


class NotConfigured(RuntimeError):
    """A placeholder that has not been filled in yet (key, model, service, dataset)."""

    def __init__(self, what: str, hint: str = ""):
        msg = f"{what} is not configured"
        if hint:
            msg += f": {hint}"
        msg += " (see PLACEHOLDERS.md)"
        super().__init__(msg)
        self.what = what


def _env(name: str, default: str | None = None) -> str | None:
    value = os.environ.get(name)
    if value is None or value.strip() == "" or value.strip().startswith("<"):
        return default  # "<placeholder>" values in .env count as unset
    return value.strip()


def _env_float(name: str, default: float) -> float:
    value = _env(name)
    return float(value) if value is not None else default


def _env_int(name: str, default: int) -> int:
    value = _env(name)
    return int(value) if value is not None else default


@dataclass(frozen=True)
class Settings:
    mode: str = field(default_factory=lambda: _env("TRUSTGATE_MODE", "enforce"))
    policy: str = field(default_factory=lambda: _env("TRUSTGATE_POLICY", "packs/soc.rego"))
    # Policy engine: OPA REST sidecar (spec) or the OPA CLI binary for local runs.
    opa_url: str | None = field(default_factory=lambda: _env("OPA_URL"))
    opa_bin: str | None = field(default_factory=lambda: _env("OPA_BIN"))
    # Facts-only re-check
    recheck_backend: str = field(default_factory=lambda: _env("TRUSTGATE_RECHECK_BACKEND", "ollama"))
    ollama_host: str = field(default_factory=lambda: _env("OLLAMA_HOST", "http://localhost:11434"))
    recheck_model: str | None = field(default_factory=lambda: _env("TRUSTGATE_RECHECK_MODEL"))
    xgb_model_path: str = field(default_factory=lambda: _env("TRUSTGATE_XGB_MODEL", "models/recheck_xgb.json"))
    # Rate limits
    redis_url: str | None = field(default_factory=lambda: _env("REDIS_URL"))
    ratelimit_backend: str = field(default_factory=lambda: _env("TRUSTGATE_RATELIMIT_BACKEND", "redis"))
    # Storage and audit
    database_url: str = field(default_factory=lambda: _env("DATABASE_URL", "sqlite:///./trustgate.db"))
    siem_jsonl_path: str | None = field(default_factory=lambda: _env("TRUSTGATE_SIEM_JSONL"))
    splunk_hec_url: str | None = field(default_factory=lambda: _env("SPLUNK_HEC_URL"))
    splunk_hec_token: str | None = field(default_factory=lambda: _env("SPLUNK_HEC_TOKEN"))
    # Watchdog and splitter limits
    check_timeout_s: float = field(default_factory=lambda: _env_float("TRUSTGATE_CHECK_TIMEOUT_S", 10.0))
    max_inflight_checks: int = field(default_factory=lambda: _env_int("TRUSTGATE_MAX_INFLIGHT_CHECKS", 16))
    # Escalations
    escalation_ttl_s: float = field(default_factory=lambda: _env_float("TRUSTGATE_ESCALATION_TTL_S", 4 * 3600.0))
    max_field_chars: int = field(default_factory=lambda: _env_int("TRUSTGATE_MAX_FIELD_CHARS", 4000))
    # Ingest
    mta_authserv_id: str | None = field(default_factory=lambda: _env("TRUSTGATE_MTA_AUTHSERV_ID"))
    ti_cache_dir: str = field(default_factory=lambda: _env("TRUSTGATE_TI_CACHE", "data/cache/ti"))
    virustotal_api_key: str | None = field(default_factory=lambda: _env("VIRUSTOTAL_API_KEY"))
    abuseipdb_api_key: str | None = field(default_factory=lambda: _env("ABUSEIPDB_API_KEY"))
    otx_api_key: str | None = field(default_factory=lambda: _env("OTX_API_KEY"))
    urlhaus_auth_key: str | None = field(default_factory=lambda: _env("URLHAUS_AUTH_KEY"))
    # Detector
    detector_url: str | None = field(default_factory=lambda: _env("DETECTOR_URL"))
    hf_token: str | None = field(default_factory=lambda: _env("HF_TOKEN"))
    prompt_guard_model: str = field(
        default_factory=lambda: _env("TRUSTGATE_PROMPT_GUARD_MODEL", "meta-llama/Llama-Prompt-Guard-2-86M")
    )
    detector_threshold: float = field(default_factory=lambda: _env_float("TRUSTGATE_DETECTOR_THRESHOLD", 0.5))
    # Output scanner
    spacy_model: str = field(default_factory=lambda: _env("TRUSTGATE_SPACY_MODEL", "en_core_web_lg"))
    # Agent and evaluation models (LiteLLM model strings, pinned)
    agent_model: str | None = field(default_factory=lambda: _env("TRUSTGATE_AGENT_MODEL"))
    attacker_model: str | None = field(default_factory=lambda: _env("TRUSTGATE_ATTACKER_MODEL"))
    # Services
    proxy_url: str = field(default_factory=lambda: _env("TRUSTGATE_PROXY_URL", "http://localhost:8080"))
    ingest_url: str = field(default_factory=lambda: _env("TRUSTGATE_INGEST_URL", "http://localhost:8081"))
    mock_soc_url: str = field(default_factory=lambda: _env("MOCK_SOC_URL", "http://localhost:8090"))
    mock_soc_token: str | None = field(default_factory=lambda: _env("MOCK_SOC_TOKEN") or _read_secret("mock_soc_token"))


def _read_secret(name: str) -> str | None:
    """Docker secrets are mounted at /run/secrets/<name>."""
    for path in (f"/run/secrets/{name}", os.path.join("secrets", f"{name}.txt")):
        try:
            with open(path, encoding="utf-8") as fh:
                value = fh.read().strip()
                return value or None
        except OSError:
            continue
    return None


def settings() -> Settings:
    return Settings()
