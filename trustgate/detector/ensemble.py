"""Detector ensemble: regex heuristics + stitch check + Prompt Guard 2 + LLM Guard.

Every component outputs scores only. A hit raises severity and tags the alert
"AI-evasion attempt"; the gate never relies on it (silent failure 11).
"""

from __future__ import annotations

from dataclasses import dataclass, field

import httpx

from trustgate.config import NotConfigured, Settings
from trustgate.detector import heuristics
from trustgate.detector.heuristics import AI_DIRECTED_RULES, TOOL_POISONING_RULES, Rule
from trustgate.detector.llm_guard_scan import LLMGuardSignals
from trustgate.detector.prompt_guard import PromptGuard2
from trustgate.detector.stitch import stitched_hits
from trustgate.models import IOCSignal


@dataclass
class DetectorResult:
    score: float = 0.0
    flagged: bool = False
    signals: list[IOCSignal] = field(default_factory=list)
    detectors_run: list[str] = field(default_factory=list)

    @property
    def flagged_evidence(self) -> set[str]:
        return {eid for s in self.signals for eid in s.evidence_ids}


class Detector:
    """Scan untrusted texts given as (evidence_id, scan_text) pairs."""

    def __init__(self, settings: Settings | None = None, *, use_models: bool = True):
        self.settings = settings or Settings()
        self.threshold = self.settings.detector_threshold
        self._use_models = use_models
        self._prompt_guard = PromptGuard2(self.settings)
        self._llm_guard = LLMGuardSignals()

    def scan(self, parts: list[tuple[str, str]], *, rules: tuple[Rule, ...] = AI_DIRECTED_RULES) -> DetectorResult:
        result = DetectorResult(detectors_run=["regex", "stitch"])
        rule_weights: list[float] = []

        for evidence_id, text in parts:
            for hit in heuristics.scan(text, rules):
                rule_weights.append(hit.rule.weight)
                result.signals.append(IOCSignal(
                    source="regex", rule=hit.rule.name, score=hit.rule.weight,
                    evidence_ids=[evidence_id], start=hit.start, end=hit.end, excerpt=hit.excerpt,
                ))
        for stitched in stitched_hits(parts):
            rule_weights.append(stitched.hit.rule.weight)
            result.signals.append(IOCSignal(
                source="stitch", rule=stitched.hit.rule.name, score=stitched.hit.rule.weight,
                evidence_ids=stitched.evidence_ids, excerpt=stitched.hit.excerpt,
            ))
        scores = [heuristics.combine(_distinct(result.signals, rule_weights))]

        if self._use_models:
            scores.extend(self._model_signals(parts, result))

        result.score = round(max(scores), 4)
        result.flagged = result.score >= self.threshold
        return result

    def scan_tool_description(self, evidence_id: str, text: str) -> DetectorResult:
        """MCP tool descriptions: AI-directed rules plus tool-poisoning rules."""
        return self.scan([(evidence_id, text)], rules=AI_DIRECTED_RULES + TOOL_POISONING_RULES)

    def _model_signals(self, parts: list[tuple[str, str]], result: DetectorResult) -> list[float]:
        if self.settings.detector_url:
            try:
                return self._remote(parts, result)
            except (httpx.HTTPError, ValueError) as exc:
                result.detectors_run.append(f"remote: unavailable ({type(exc).__name__})")
                return []
        return self.local_model_signals(parts, result)

    def local_model_signals(self, parts: list[tuple[str, str]], result: DetectorResult) -> list[float]:
        """Prompt Guard 2 and LLM Guard in this process (used by the detector container)."""
        scores: list[float] = []
        assembled = "\n".join(text for _, text in parts)
        all_ids = [eid for eid, _ in parts]
        try:
            pg = self._prompt_guard.score(assembled)
            result.detectors_run.append("prompt_guard_2")
            scores.append(pg)
            if pg >= self.threshold:
                result.signals.append(IOCSignal(source="prompt_guard_2", rule="classifier", score=round(pg, 4),
                                                evidence_ids=all_ids))
        except NotConfigured as exc:
            result.detectors_run.append(f"prompt_guard_2: unavailable ({exc.what})")

        try:
            for scanner, risk in self._llm_guard.scan(assembled).items():
                if scanner == "PromptInjection":
                    scores.append(risk)
                if risk >= self.threshold:
                    result.signals.append(IOCSignal(source=f"llm_guard:{scanner}", rule=scanner, score=round(risk, 4),
                                                    evidence_ids=all_ids))
            result.detectors_run.append("llm_guard")
        except NotConfigured as exc:
            result.detectors_run.append(f"llm_guard: unavailable ({exc.what})")
        return scores

    def _remote(self, parts: list[tuple[str, str]], result: DetectorResult) -> list[float]:
        """Model-based signals from the detector container (services/detector)."""
        resp = httpx.post(f"{self.settings.detector_url}/v1/scan",
                          json={"parts": [{"evidence_id": e, "text": t} for e, t in parts]}, timeout=30)
        resp.raise_for_status()
        body = resp.json()
        result.detectors_run.extend(body.get("detectors_run", []))
        for signal in body.get("signals", []):
            result.signals.append(IOCSignal.model_validate(signal))
        return [float(s) for s in body.get("model_scores", [])]


def _distinct(signals: list[IOCSignal], weights: list[float]) -> list[float]:
    best: dict[str, float] = {}
    for s in signals:
        best[s.rule] = max(best.get(s.rule, 0.0), s.score)
    return list(best.values()) if best else weights
