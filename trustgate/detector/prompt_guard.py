"""Llama Prompt Guard 2 via Hugging Face transformers.

Placeholder until HF_TOKEN is set and Meta's licence for the gated model is
accepted (PLACEHOLDERS.md). Until then the detector records it as unavailable
and runs on its other signals; it never blocks on its own either way.
"""

from __future__ import annotations

import threading

from trustgate.config import NotConfigured, Settings

_MALICIOUS_LABELS = ("MALICIOUS", "INJECTION", "JAILBREAK", "LABEL_1")
_CHUNK_CHARS = 1800  # Prompt Guard 2 reads 512 tokens; long text is scanned in windows


class PromptGuard2:
    name = "prompt_guard_2"

    def __init__(self, settings: Settings):
        self._settings = settings
        self._pipeline = None
        self._lock = threading.Lock()

    def _load(self):
        if self._pipeline is not None:
            return self._pipeline
        if not self._settings.hf_token:
            raise NotConfigured("HF_TOKEN", "Prompt Guard 2 is a gated model")
        with self._lock:
            if self._pipeline is None:
                try:
                    from transformers import pipeline
                except ImportError as exc:  # detector extra not installed
                    raise NotConfigured("transformers", "install the 'detector' extra") from exc
                self._pipeline = pipeline(
                    "text-classification",
                    model=self._settings.prompt_guard_model,
                    token=self._settings.hf_token,
                    truncation=True,
                    max_length=512,
                    top_k=None,
                )
        return self._pipeline

    def score(self, text: str) -> float:
        pipe = self._load()
        chunks = [text[i : i + _CHUNK_CHARS] for i in range(0, max(len(text), 1), _CHUNK_CHARS)] or [""]
        best = 0.0
        for result in pipe(chunks):
            for label in result:
                if str(label["label"]).upper() in _MALICIOUS_LABELS:
                    best = max(best, float(label["score"]))
        return best
