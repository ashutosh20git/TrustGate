"""Output data-leak scanning (v2): Microsoft Presidio analyzer + anonymizer.

Runs on what leaves: T3 payloads and agent-written text (notes, summaries), not
on evidence. Each entity type is allowed, redacted or blocked per policy pack;
the floor's block list (secrets, card numbers, national IDs) applies to every
pack. LLM Guard's output scanners are the fallback backend. With neither
available, the scanner raises and T3 actions fail closed.
"""

from __future__ import annotations

import re
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


# Floor-blocked identifiers Presidio recognises natively. The LLM Guard fallback
# only says "sensitive", never which entity, so without these it could redact a
# card number but never block it as the floor requires.
FLOOR_PATTERNS: dict[str, list[tuple[str, str, float]]] = {
    "CREDIT_CARD": [("card_number", r"\b(?:\d[ -]?){12,18}\d\b", 0.6)],
    "US_SSN": [("us_ssn", r"\b\d{3}-\d{2}-\d{4}\b", 0.6)],
    "IN_AADHAAR": [("aadhaar", r"\b[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}\b", 0.6)],
    "IN_PAN": [("pan", r"\b[A-Z]{5}\d{4}[A-Z]\b", 0.6)],
    "IBAN_CODE": [("iban", r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b", 0.6)],
    "CRYPTO": [("btc_address", r"\b(?:bc1[a-z0-9]{25,59}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b", 0.6)],
}
_DIGITS = re.compile(r"\D")


def _luhn_ok(number: str) -> bool:
    digits = [int(d) for d in _DIGITS.sub("", number)]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2:
            d *= 2
            d -= 9 if d > 9 else 0
        total += d
    return total % 10 == 0


_VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5], [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7], [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3], [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]
_VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4], [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7], [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]


def _verhoeff_ok(number: str) -> bool:
    check = 0
    for i, d in enumerate(reversed(_DIGITS.sub("", number))):
        check = _VERHOEFF_D[check][_VERHOEFF_P[i % 8][int(d)]]
    return check == 0


_CHECKSUMS = {"CREDIT_CARD": _luhn_ok, "IN_AADHAAR": _verhoeff_ok}


def regex_findings(text: str) -> list[tuple[str, int, int, float]]:
    """(entity, start, end, score) for secrets and floor-blocked identifiers, by regex only."""
    hits: list[tuple[str, int, int, float]] = []
    for entity, patterns in {**SECRET_PATTERNS, **FLOOR_PATTERNS}.items():
        for _name, regex, score in patterns:
            for m in re.finditer(regex, text):
                checksum = _CHECKSUMS.get(entity)
                if checksum is not None and not checksum(m.group(0)):
                    continue
                hits.append((entity, m.start(), m.end(), score))
    return hits


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
                # LLM Guard redacts but does not name entities; a regex pass names the
                # secrets and floor-blocked identifiers so they can still be blocked.
                for entity, start, end, score in regex_findings(text):
                    result.findings.append(OutputFinding(entity=entity, start=start, end=end, score=score,
                                                         arg=arg, action=self.action_for(entity)))
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
