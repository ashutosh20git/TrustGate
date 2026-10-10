"""Facts-only re-check (v1 component 3).

Before any T1 action the verdict is recomputed from typed facts alone. The
re-check input is TypedFacts.recheck_view(): numbers, booleans and enums, no
identifiers and no evidence. There is nothing attacker-written for a
conditional instruction to key on (the MELON bypass).

Backends, as in the blueprint: Ollama + a small Qwen/Llama model in JSON mode
(default), or an XGBoost classifier over the same typed facts.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Callable, Protocol

import httpx
from jinja2 import Environment, StrictUndefined
from pydantic import BaseModel

from trustgate.config import NotConfigured, Settings
from trustgate.models import TypedFacts, Verdict

RECHECK_TEMPLATE = Environment(undefined=StrictUndefined, autoescape=False).from_string(
    """You are a security triage classifier. You receive only machine-generated facts about a security alert.
Decide whether the alert is malicious, benign or unsure. Answer "benign" only when the facts positively
support it; missing or unknown facts are not evidence of safety.

Facts (JSON):
{{ facts_json }}

Respond with JSON only: {"verdict": "malicious" | "benign" | "unsure"}"""
)

FEATURE_ORDER = (
    "spf_pass", "dkim_pass", "dmarc_pass", "sender_domain_age_days", "url_reputation", "ip_abuse_score",
    "sandbox_verdict", "ioc_ip_count", "ioc_hash_count", "asn_known", "attachment_count",
    "attachment_parse_failed", "attachment_hidden_content", "attachment_has_macros",
)
_ENUMS = {
    "url_reputation": {"unknown": -1, "clean": 0, "suspicious": 1, "malicious": 2},
    "sandbox_verdict": {"not_run": -1, "clean": 0, "suspicious": 1, "malicious": 2},
}
_VERDICTS = ("benign", "unsure", "malicious")


class VerdictOut(BaseModel):
    verdict: Verdict


@dataclass
class RecheckResult:
    verdict: Verdict
    tokens: int = 0
    backend: str = ""


class Recheck(Protocol):
    def __call__(self, facts: TypedFacts) -> RecheckResult: ...


def render_prompt(facts: TypedFacts) -> str:
    return RECHECK_TEMPLATE.render(facts_json=json.dumps(facts.recheck_view(), sort_keys=True))


class OllamaRecheck:
    """Ollama /api/generate, format json, temperature 0."""

    backend = "ollama"

    def __init__(self, settings: Settings, *, client: httpx.Client | None = None):
        if not settings.recheck_model:
            raise NotConfigured("TRUSTGATE_RECHECK_MODEL", "pull a small Qwen/Llama model into Ollama")
        self.model = settings.recheck_model
        self.url = settings.ollama_host.rstrip("/") + "/api/generate"
        self.timeout = settings.check_timeout_s
        self._client = client or httpx.Client(timeout=self.timeout)

    def __call__(self, facts: TypedFacts) -> RecheckResult:
        resp = self._client.post(self.url, json={
            "model": self.model,
            "prompt": render_prompt(facts),
            "format": "json",
            "stream": False,
            "options": {"temperature": 0, "seed": 0},
        })
        resp.raise_for_status()
        body = resp.json()
        verdict = VerdictOut.model_validate_json(body["response"]).verdict
        tokens = int(body.get("prompt_eval_count", 0)) + int(body.get("eval_count", 0))
        return RecheckResult(verdict=verdict, tokens=tokens, backend=f"ollama:{self.model}")


def vectorise(facts: TypedFacts) -> list[float]:
    view = facts.recheck_view()
    row: list[float] = []
    for key in FEATURE_ORDER:
        value = view[key]
        if key in _ENUMS:
            row.append(float(_ENUMS[key][value]))
        elif value is None:
            row.append(float("nan"))  # XGBoost handles missing values natively
        else:
            row.append(float(value))
    return row


class XGBoostRecheck:
    """Alternative backend from the blueprint: a classifier over the same typed facts."""

    backend = "xgboost"

    def __init__(self, settings: Settings):
        try:
            import xgboost
        except ImportError as exc:
            raise NotConfigured("xgboost", "install the 'recheck-xgb' extra") from exc
        self._booster = xgboost.Booster()
        try:
            self._booster.load_model(settings.xgb_model_path)
        except Exception as exc:
            raise NotConfigured(settings.xgb_model_path, "train it with eval/train_recheck.py on labelled datasets") from exc
        self._xgb = xgboost

    def __call__(self, facts: TypedFacts) -> RecheckResult:
        matrix = self._xgb.DMatrix([vectorise(facts)], feature_names=list(FEATURE_ORDER))
        probs = self._booster.predict(matrix)[0]
        verdict = _VERDICTS[int(max(range(len(probs)), key=lambda i: probs[i]))]
        return RecheckResult(verdict=verdict, backend="xgboost")


def facts_only_recheck(settings: Settings | None = None) -> Callable[[TypedFacts], RecheckResult]:
    """The configured re-check hook. Construction errors surface at call time, so the gate fails closed."""
    settings = settings or Settings()
    backend = settings.recheck_backend
    try:
        impl: Recheck = XGBoostRecheck(settings) if backend == "xgboost" else OllamaRecheck(settings)
    except NotConfigured as exc:
        error = exc

        def unavailable(_facts: TypedFacts) -> RecheckResult:
            raise error

        return unavailable
    return impl


def as_recheck(fn: Callable[[TypedFacts], Verdict | RecheckResult]) -> Callable[[TypedFacts], RecheckResult]:
    """Accept a plain function returning a verdict string as a re-check hook."""

    def wrapped(facts: TypedFacts) -> RecheckResult:
        out = fn(facts)
        if isinstance(out, RecheckResult):
            return out
        return RecheckResult(verdict=VerdictOut(verdict=out).verdict, backend=getattr(fn, "__name__", "custom"))

    return wrapped
