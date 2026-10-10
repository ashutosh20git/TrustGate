"""Output data-leak scanning (v2): Microsoft Presidio analyzer + anonymizer.

Runs on what leaves: T3 payloads and agent-written text (notes, summaries), not
on evidence. Each entity type is allowed, redacted or blocked per policy pack;
the floor's block list (secrets, card numbers, national IDs) applies to every
pack. LLM Guard's output scanners are the fallback backend. With neither
available, the scanner raises and T3 actions fail closed.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field

from trustgate.config import NotConfigured, Settings
from trustgate.models import OutputFinding
from trustgate.policy_client import PolicyPack

SCORE_THRESHOLD = 0.4

# Supplementary recognizers: secrets Presidio does not ship, plus a generic
# email pattern so reserved TLDs (.example, .test) used in SOC data are caught.
SECRET_PATTERNS: dict[str, list[tuple[str, str, float]]] = {
    "EMAIL_ADDRESS": [
        ("email_generic", r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b", 0.9),
    ],
    "API_KEY": [
        ("aws_access_key", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", 0.9),
        ("github_token", r"\bgh[pousr]_[A-Za-z0-9]{36,}\b", 0.9),
        ("slack_token", r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b", 0.9),
        ("openai_key", r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b", 0.85),
        ("anthropic_key", r"\bsk-ant-[A-Za-z0-9_-]{20,}\b", 0.95),
        ("google_api_key", r"\bAIza[0-9A-Za-z_-]{35}\b", 0.9),
        ("jwt", r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b", 0.8),
    ],
    "PRIVATE_KEY": [
        ("pem_private_key", r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----", 0.99),
    ],
    "PASSWORD": [
        ("password_assignment", r"(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|token)\s*[:=]\s*\S{6,}", 0.7),
    ],
}


@dataclass
class ScanResult:
    findings: list[OutputFinding] = field(default_factory=list)
    redacted: dict[str, str] = field(default_factory=dict)
    backend: str = ""

    @property
    def blocked_entities(self) -> list[str]:
        return sorted({f.entity for f in self.findings if f.action == "block"})

    @property
    def entities(self) -> list[str]:
        return sorted({f.entity for f in self.findings})


class PresidioBackend:
    name = "presidio"

    def __init__(self, spacy_model: str):
        try:
            from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer
            from presidio_analyzer.nlp_engine import NlpEngineProvider
            from presidio_anonymizer import AnonymizerEngine
            from presidio_anonymizer.entities import OperatorConfig
        except ImportError as exc:
            raise NotConfigured("presidio-analyzer", "install the 'output-scan' extra") from exc
        try:
            provider = NlpEngineProvider(nlp_configuration={
                "nlp_engine_name": "spacy",
                "models": [{"lang_code": "en", "model_name": spacy_model}],
            })
            self.analyzer = AnalyzerEngine(nlp_engine=provider.create_engine(), supported_languages=["en"])
        except (OSError, ValueError) as exc:
            raise NotConfigured(f"spaCy model {spacy_model}", f"python -m spacy download {spacy_model}") from exc
        for entity, patterns in SECRET_PATTERNS.items():
            self.analyzer.registry.add_recognizer(PatternRecognizer(
                supported_entity=entity, patterns=[Pattern(name, regex, score) for name, regex, score in patterns]))
        self._add_indian_recognizers()
        self.anonymizer = AnonymizerEngine()
        self._operator = OperatorConfig

    def _add_indian_recognizers(self) -> None:
        loaded = {e for r in self.analyzer.registry.recognizers for e in r.supported_entities}
        try:
            from presidio_analyzer.predefined_recognizers import InAadhaarRecognizer, InPanRecognizer
        except ImportError:
            return
        for recognizer in (InAadhaarRecognizer(), InPanRecognizer()):
            if not set(recognizer.supported_entities) & loaded:
                self.analyzer.registry.add_recognizer(recognizer)

    def analyze(self, text: str):
        return [r for r in self.analyzer.analyze(text=text, language="en") if r.score >= SCORE_THRESHOLD]

    def redact(self, text: str, results) -> str:
        operators = {r.entity_type: self._operator("replace", {"new_value": f"<{r.entity_type}>"}) for r in results}
        return self.anonymizer.anonymize(text=text, analyzer_results=results, operators=operators).text


class LLMGuardBackend:
    """Fallback named in the v2 doc: LLM Guard output scanners (Sensitive)."""

    name = "llm_guard"

    def __init__(self):
        try:
            from llm_guard.output_scanners import Sensitive
        except ImportError as exc:
            raise NotConfigured("llm-guard", "needs Python 3.11/3.12 and the 'detector' extra") from exc
        self._sensitive = Sensitive(redact=True)

    def analyze_and_redact(self, text: str) -> tuple[str, bool, float]:
        sanitized, is_valid, risk = self._sensitive.scan("", text)
        return sanitized, is_valid, float(risk)


class OutputScanner:
    def __init__(self, pack: PolicyPack, settings: Settings | None = None, *, backend=None):
        self.pack = pack
        self.settings = settings or Settings()
        self._backend = backend
        self._error: Exception | None = None
        self._lock = threading.Lock()

    def _load(self):
        if self._backend is not None:
            return self._backend
        with self._lock:
            if self._backend is None:
                errors: list[str] = []
                for factory in (lambda: PresidioBackend(self.settings.spacy_model), LLMGuardBackend):
                    try:
                        self._backend = factory()
                        break
                    except NotConfigured as exc:
                        errors.append(exc.what)
                if self._backend is None:
                    raise NotConfigured("output scanner", "no backend available: " + ", ".join(errors))
        return self._backend

    def action_for(self, entity: str) -> str:
        if entity in self.pack.block_entities:
            return "block"
        if entity in self.pack.allow_entities:
            return "allow"
        return "redact"  # redact unknown entity types by default

    def scan(self, fields: dict[str, str]) -> ScanResult:
        backend = self._load()
        result = ScanResult(backend=backend.name)
        for arg, text in fields.items():
            text = str(text)
            if isinstance(backend, LLMGuardBackend):
                sanitized, is_valid, risk = backend.analyze_and_redact(text)
                if not is_valid:
                    result.findings.append(OutputFinding(entity="SENSITIVE", start=0, end=len(text), score=risk,
                                                         arg=arg, action="redact"))
                result.redacted[arg] = sanitized
                continue
            hits = backend.analyze(text)
            to_redact = []
            for hit in hits:
                action = self.action_for(hit.entity_type)
                result.findings.append(OutputFinding(entity=hit.entity_type, start=hit.start, end=hit.end,
                                                     score=round(float(hit.score), 3), arg=arg, action=action))
                if action != "allow":
                    to_redact.append(hit)
            result.redacted[arg] = backend.redact(text, to_redact) if to_redact else text
        return result
