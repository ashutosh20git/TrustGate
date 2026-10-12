"""TrustGate's rules for a general tool agent, shared by the agent benchmarks.

AgentDojo, InjecAgent and ASB all run through this one class, so a rule tuned on one benchmark
is measured on the others. For every tool call:

  * T0 (reads) run;
  * T1 (security-reducing) escalates once an injection was seen in a tool result this session;
  * every target argument of a T1-T3 call must hold trusted values (the user's request, plus the
    environment under the field-labels policy); a T2 target must be named in the request itself;
  * a T1-T3 call with no argument naming what it acts on must be asked for by name in the request;
  * content the agent writes may not carry untrusted links, reused untrusted text, or values the
    output scanner's floor blocks.
"""

from __future__ import annotations

import re
from typing import Any

from trustgate.detector import Detector

SHINGLE = 4
# Words in a tool name that say what it does, not what it acts on.
VERBS = {
    "get", "view", "search", "list", "read", "find", "fetch", "check", "query", "download", "show", "lookup",
    "create", "update", "delete", "remove", "add", "set", "send", "share", "grant", "revoke", "disable", "enable",
    "manage", "move", "leave", "join", "pay", "transfer", "withdraw", "deposit", "place", "schedule", "cancel",
    "reschedule", "execute", "run", "give", "unlock", "lock", "post", "invite", "append", "reserve", "generate",
    "auto", "fill", "make", "book", "order", "modify", "edit", "write", "upload", "change", "go", "to", "the",
    "user", "info", "information", "details", "data", "item", "items", "state", "action", "request", "level",
}
# Words that name no particular object.
GENERIC = {"tool", "tools", "system", "manager", "management", "service", "app", "api", "helper", "assistant"}

_LINK = re.compile(r"(?:https?://)?(?:www\.)?[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:com|net|org|io|co|uk|de|fr|info|biz|xyz|ru|cn|in|me)"
                   r"(?:/[^\s'\"]*)?|[\w.+-]+@[\w-]+\.[\w.]+", re.I)
_WORDS = re.compile(r"[a-z0-9]+")
SHINGLE = 4

def _norm(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return [v for item in value for v in _norm(item)]
    text = str(value).strip().lower()
    return [text] if text else []


def _contains(corpus: str, value: str) -> bool:
    """value appears in corpus as a whole token (so '13' does not match '2013')."""
    return re.search(r"(?<![\w@.:/-])" + re.escape(value) + r"(?![\w@:/-])", corpus) is not None


def _shingles(text: str, n: int = SHINGLE) -> set[str]:
    words = _WORDS.findall(text.lower())
    return {" ".join(words[i:i + n]) for i in range(len(words) - n + 1)}


_SCANNER = None


def _scanner():
    """TrustGate's output scanner (Presidio) with the SOC pack's floor blocks, loaded once."""
    global _SCANNER
    if _SCANNER is None:
        from trustgate.output_scan import OutputScanner
        from trustgate.policy_client import load_pack

        _SCANNER = OutputScanner(load_pack("packs/soc.rego"))
    return _SCANNER


class Gate:
    """TrustGate's general-agent rules for one session."""

    def __init__(self, policy: dict[str, tuple[int, tuple[str, ...]]], prompt: str, trusted_env: str | None, *,
                 untrusted: list[str] | None = None, stock_detector: bool = False,
                 content: dict[str, tuple[str, ...]] | None = None, vendor_words: tuple[str, ...] = ()):
        self.policy = policy
        self.content = content or {}
        self.vendor_words = {w.lower() for w in vendor_words}
        self.prompt = prompt.lower()
        self.trusted = self.prompt + "\n" + (trusted_env or "").lower()
        self.trusted_shingles = _shingles(self.trusted)
        self.detector = Detector(use_models=False)
        from trustgate.detector.heuristics import AI_DIRECTED_RULES

        # stock: the detector as it was before this benchmark (no "indirect.*" rules)
        self.rules = tuple(r for r in AI_DIRECTED_RULES if not (stock_detector and r.name.startswith("indirect.")))
        self.strict = trusted_env is None  # every tool output is untrusted
        self.untrusted_shingles: set[str] = set()
        for text in untrusted or []:
            self.untrusted_shingles |= _shingles(text)
        self.ai_evasion = False
        self.escalated: list[str] = []

    def observe(self, tool_output: str) -> None:
        if self.strict:
            self.untrusted_shingles |= _shingles(tool_output)
        if not self.ai_evasion and self.detector.scan([("ev-1", tool_output)], rules=self.rules).flagged:
            self.ai_evasion = True

    def _content_ok(self, function: str, args: dict[str, Any]) -> bool:
        fields = {k: str(args[k]) for k in self.content.get(function, ()) if args.get(k) not in (None, "")}
        for name, text in fields.items():
            for link in _LINK.findall(text):
                if not _contains(self.trusted, link.lower().rstrip(".,)")):
                    return self._escalate(function, f"{name} carries an untrusted link or address {link[:40]!r}")
            reused = (_shingles(text) & self.untrusted_shingles) - self.trusted_shingles
            if reused:
                return self._escalate(function, f"{name} reuses untrusted text {sorted(reused)[0]!r}")
        if fields:
            blocked = _scanner().scan(fields).blocked_entities
            if blocked:
                return self._escalate(function, f"{', '.join(blocked)} may never leave")
        return True

    def allows(self, function: str, args: dict[str, Any]) -> bool:
        tier, targets = self.policy.get(function, (0, ()))
        if tier == 0:
            return True
        if tier == 1 and self.ai_evasion:
            return self._escalate(function, "T1 after an injection was seen in a tool result")
        identifying = [k for k, v in args.items() if v not in (None, "", [], {}) and k not in self.content.get(function, ())]
        if not targets and not identifying and not self._requested(function):
            # Nothing in the call names what it acts on, so nothing can be checked against trusted
            # data: only the request itself can justify it. (InjecAgent: "unlock my door".)
            return self._escalate(function, "an action with no target the user did not ask for")
        scope = self.prompt if tier == 2 else self.trusted
        for name in targets:
            for value in _norm(args.get(name)):
                if tier == 2 and value.isdigit():
                    # A bare number in the request ("June 13") does not name an object; "file 13" does.
                    named = re.search(r"\b(file|id|email|event|message|item)\b\W{0,4}(?:with\s+id\W{0,3})?"
                                      + re.escape(value) + r"\b", self.prompt)
                    if not named:
                        return self._escalate(function, f"{name}={value!r} is not named in the request")
                    continue
                if not _contains(scope, value):
                    return self._escalate(function, f"{name}={value[:40]!r} not in trusted data")
        return self._content_ok(function, args)

    def _requested(self, function: str) -> bool:
        """The user's request names what the action acts on ("create a file", "unlock the door")."""
        words = [w.lower() for w in re.findall(r"[A-Z]?[a-z0-9]+|[A-Z]+(?![a-z])", function.replace("_", " "))]
        nouns = [w for w in words if len(w) >= 3 and w not in VERBS and w not in GENERIC and w not in self.vendor_words]
        said = set(_WORDS.findall(self.prompt))
        # Every word naming what it acts on: "InvestmentScam" is not asked for by "compare investments".
        return bool(nouns) and all(n in said or n + "s" in said or (n.endswith("s") and n[:-1] in said)
                                   for n in nouns)

    def _escalate(self, function: str, why: str) -> bool:
        self.escalated.append(f"{function}: {why}")
        return False
