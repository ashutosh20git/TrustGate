"""LLM Guard (Protect AI) input scanners as signals only.

Covers the v2 "broader detector signals" item: prompt injection, secrets,
toxicity and malicious URLs. llm-guard needs Python 3.11/3.12, so on the 3.13
dev machine this is a placeholder (PLACEHOLDERS.md); the containers install it.
"""

from __future__ import annotations

import threading

from trustgate.config import NotConfigured

SCANNERS = ("PromptInjection", "Secrets", "Toxicity", "MaliciousURLs")


class LLMGuardSignals:
    name = "llm_guard"

    def __init__(self, scanners: tuple[str, ...] = SCANNERS):
        self._names = scanners
        self._scanners = None
        self._lock = threading.Lock()

    def _load(self):
        if self._scanners is not None:
            return self._scanners
        with self._lock:
            if self._scanners is None:
                try:
                    from llm_guard import input_scanners
                except ImportError as exc:
                    raise NotConfigured("llm-guard", "needs Python 3.11/3.12 and the 'detector' extra") from exc
                self._scanners = {name: getattr(input_scanners, name)() for name in self._names}
        return self._scanners

    def scan(self, text: str) -> dict[str, float]:
        """Scanner name -> risk score in [0, 1]."""
        out: dict[str, float] = {}
        for name, scanner in self._load().items():
            _sanitized, _is_valid, risk = scanner.scan(text)
            out[name] = max(0.0, min(1.0, float(risk)))
        return out
