"""Facts-only re-check (v1 component 3).

Before any T1 action the verdict is recomputed from typed facts alone. The
re-check input is TypedFacts.recheck_view(): numbers, booleans and enums, no
identifiers and no evidence. There is nothing attacker-written for a
conditional instruction to key on (the MELON bypass).

Backends, as in the blueprint: Ollama + a small Qwen/Llama model in JSON mode
(default), or an XGBoost classifier over the same typed facts.

Reliability (docs/RECHECK.md):
  * The XGBoost model sees every fact in recheck_view(), not a subset.
  * "benign" needs confidence: below TRUSTGATE_RECHECK_MIN_CONFIDENCE (default 0.9)
    the classifier's benign becomes unsure, which escalates.
  * Two judges: the configured backend runs with the rule scorecard
    (trustgate/scorecard.py), and benign needs both (TRUSTGATE_RECHECK_SCORECARD=off
    to disable). Either saying malicious makes it malicious.
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

# A plain-text LLM prompt, never rendered as HTML; its only input is typed facts as JSON.
RECHECK_TEMPLATE = Environment(undefined=StrictUndefined, autoescape=False).from_string(  # nosec B701
    """You are a security triage classifier. You receive only machine-generated facts about a security alert.
Decide whether the alert is malicious, benign or unsure. Answer "benign" only when the facts positively
support it; missing or unknown facts are not evidence of safety.

Facts (JSON):
{{ facts_json }}

Respond with JSON only: {"verdict": "malicious" | "benign" | "unsure"}"""
)

# Every fact the re-check is given, in a fixed order: the model must not be blind to
# any of them (it used to see 14 of 21, missing sender history and compromised-account signs).
FEATURE_ORDER = tuple(TypedFacts().recheck_view())
_ENUMS = {
    "url_reputation": {"unknown": -1, "clean": 0, "suspicious": 1, "malicious": 2},
    "sandbox_verdict": {"not_run": -1, "clean": 0, "suspicious": 1, "malicious": 2},
    "asset_criticality": {"low": 0, "medium": 1, "high": 2, "critical": 3},
}
_VERDICTS = ("benign", "unsure", "malicious")


class VerdictOut(BaseModel):
    verdict: Verdict


@dataclass
class RecheckResult:
    verdict: Verdict
    tokens: int = 0
    backend: str = ""
    confidence: float | None = None  # the backend's probability for its verdict, when it has one
    reasons: tuple[str, ...] = ()


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
            row.append(float("nan") if value is None else float(_ENUMS[key][value]))
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
            raise NotConfigured(settings.xgb_model_path, "train it with scripts/train_recheck.py") from exc
        # A model trained on another feature list would read facts in the wrong columns.
        if list(self._booster.feature_names or []) != list(FEATURE_ORDER):
            raise NotConfigured(settings.xgb_model_path,
                                "trained on a different fact list; retrain with scripts/train_recheck.py")
        self._xgb = xgboost
        self.min_confidence = settings.recheck_min_confidence

    def __call__(self, facts: TypedFacts) -> RecheckResult:
        matrix = self._xgb.DMatrix([vectorise(facts)], feature_names=list(FEATURE_ORDER))
        probs = [float(p) for p in self._booster.predict(matrix)[0]]
        best = max(range(len(probs)), key=lambda i: probs[i])
        verdict, confidence = _VERDICTS[best], probs[best]
        reasons: tuple[str, ...] = ()
        # A confident "benign" only: a 51% benign is not evidence enough to lower security.
        if verdict == "benign" and confidence < self.min_confidence:
            verdict = "unsure"
            reasons = (f"benign probability {confidence:.2f} below {self.min_confidence:.2f}",)
        return RecheckResult(verdict=verdict, backend="xgboost", confidence=round(confidence, 4), reasons=reasons)


class EnsembleRecheck:
    """Two independent judges: the configured backend and the rule scorecard.
    benign only if both say benign; malicious if either does; otherwise unsure."""

    def __init__(self, model: Callable[[TypedFacts], RecheckResult]):
        self.model = model
        self.backend = f"{getattr(model, 'backend', 'model')}+scorecard"

    def __call__(self, facts: TypedFacts) -> RecheckResult:
        from trustgate.scorecard import score

        result = self.model(facts)
        card = score(facts)
        verdicts = {result.verdict, card.verdict}
        if "malicious" in verdicts:
            verdict: Verdict = "malicious"
        elif verdicts == {"benign"}:
            verdict = "benign"
        else:
            verdict = "unsure"
        reasons = tuple(result.reasons) + tuple(f"scorecard: {r}" for r in card.malicious + card.warnings)
        if card.verdict == "unsure" and not card.warnings:
            reasons += ("scorecard: no fact positively supports benign",)
        return RecheckResult(verdict=verdict, tokens=result.tokens, backend=self.backend,
                             confidence=result.confidence, reasons=reasons)


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
    return EnsembleRecheck(impl) if settings.recheck_scorecard else impl


def as_recheck(fn: Callable[[TypedFacts], Verdict | RecheckResult]) -> Callable[[TypedFacts], RecheckResult]:
    """Accept a plain function returning a verdict string as a re-check hook."""

    def wrapped(facts: TypedFacts) -> RecheckResult:
        out = fn(facts)
        if isinstance(out, RecheckResult):
            return out
        return RecheckResult(verdict=VerdictOut(verdict=out).verdict, backend=getattr(fn, "__name__", "custom"))

    return wrapped
