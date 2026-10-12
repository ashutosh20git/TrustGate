"""Regex heuristics for text aimed at an AI.

Covers the v1 attack classes (override, persona, fake verdicts, fake structure,
ADI-style fake metadata, exfiltration requests) and MCP tool-poisoning phrases.
It deliberately has no rules for persuasion without commands or for Hindi and
Hinglish: those are the detector-evasion set the gate has to catch on its own.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_F = re.IGNORECASE | re.MULTILINE


@dataclass(frozen=True)
class Rule:
    name: str
    category: str
    weight: float
    pattern: re.Pattern[str]


def _r(name: str, category: str, weight: float, pattern: str) -> Rule:
    return Rule(name, category, weight, re.compile(pattern, _F))


AI_DIRECTED_RULES: tuple[Rule, ...] = (
    # Direct override
    _r("override.ignore_previous", "override", 0.9,
       r"\b(ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}\b(previous|prior|above|earlier|all|any|your|the)\b"
       r"[^.\n]{0,20}\b(instructions?|rules?|prompts?|guidelines?|directives?|context)\b"),
    _r("override.new_instructions", "override", 0.6, r"\bnew\s+(system\s+)?instructions?\b"),
    _r("override.system_prompt", "override", 0.5, r"\b(system|developer)\s+prompt\b"),
    _r("override.you_must_now", "override", 0.5, r"\byou\s+(must|should|will|are to)\s+now\b"),
    # Addressing an AI
    _r("addressing.note_to_ai", "addressing_ai", 0.85,
       r"\b(note|message|instructions?|memo|attention|reminder)\s+(to|for)\s+(the\s+|any\s+)?(ai|a\.i\.|assistant|llm|"
       r"language\s+model|model|bot|agent|automated\s+(triage|systems?|analy[sz]er|analyst|review(er)?)|"
       r"soc\s+(agent|bot|assistant|automation)|triage\s+(bot|agent|system))\b"),
    _r("addressing.greeting_ai", "addressing_ai", 0.7, r"\b(dear|hey|hello|hi)\s+(ai|assistant|llm|bot|agent|model)\b"),
    _r("addressing.as_an_ai", "addressing_ai", 0.5, r"\bas\s+an\s+(ai|llm|language\s+model)\b"),
    _r("addressing.ai_should", "addressing_ai", 0.7,
       r"\b(ai|llm|automated)[ -](triage|analy[sz]er|analyst|agent|system|reviewer)s?\b[^.\n]{0,60}"
       r"\b(should|must|please|needs?\s+to|are\s+instructed)\b"),
    # Persona hijack
    _r("persona.bracket_role", "persona", 0.8,
       r"\[\s*(soc|security|it|system|sys)?\s*(admin(istrator)?|analyst|supervisor|lead|manager|operator|system|root)\s*\]\s*:?"),
    _r("persona.role_prefix", "persona", 0.6, r"^\s*(system|assistant|admin|soc[_ ]?admin|administrator)\s*:"),
    _r("persona.this_is_admin", "persona", 0.6, r"\bthis\s+is\s+(the\s+)?(soc|security|it)\s+(admin|administrator|team|lead|manager)\b"),
    # Fake verdicts and requested dispositions
    _r("verdict.field", "fake_verdict", 0.85,
       r"\b(final\s+)?(verdict|classification|disposition|determination|triage\s+(result|status))\s*[:=]\s*\"?"
       r"(benign|false[ _-]?positive|safe|clean|no\s+action|resolved|closed)\b"),
    _r("verdict.mark_as", "fake_verdict", 0.8,
       r"\b(mark|classify|label|treat|tag|flag|close|resolve)\b[^.\n]{0,30}\bas\b[^.\n]{0,10}"
       r"\b(benign|false[ _-]?positive|safe|clean|legitimate|resolved)\b"),
    _r("verdict.close_alert", "fake_verdict", 0.7,
       r"\b(close|dismiss|suppress|resolve|ignore)\s+(this|the)\s+(alert|ticket|incident|case|detection)\b"),
    _r("verdict.authorised_test", "fake_verdict", 0.6,
       r"\bauthori[sz]ed\s+(phishing\s+|red[ -]team\s+|security\s+|penetration\s+|pen\s+)?(test|simulation|exercise|assessment)\b"),
    _r("verdict.do_not_escalate", "fake_verdict", 0.75,
       r"\b(do\s+not|don'?t|never)\s+(escalate|flag|alert|report|block|quarantine)\b"),
    _r("verdict.whitelist_this", "fake_verdict", 0.6, r"\b(whitelist|allowlist|allow-list)\s+(this|the|our)\b"),
    # Fake structure: end tags, tool-call blocks (context manipulation, ADI)
    _r("structure.fake_tag", "fake_structure", 0.6,
       r"</?\s*(log|logs|end|system|context|evidence|data|document|tool_?result|function_?results?|assistant|user|"
       r"instructions?|untrusted|trusted)\s*>"),
    _r("structure.end_marker", "fake_structure", 0.55,
       r"(\bend\s+of\s+(log|logs|email|message|context|evidence|data|document)\b|-{3,}\s*end\s*-{3,}|={3,}\s*end\s*={3,})"),
    _r("structure.json_tool_call", "fake_structure", 0.6,
       r"\{\s*\"(tool|tool_?call|function|function_?call|arguments|verdict|action|parameters)\"\s*:"),
    _r("structure.xml_tool_call", "fake_structure", 0.7, r"<\s*(tool_call|function_call|invoke|function_calls|tool_use|parameter)\b"),
    # ADI-style fake metadata
    _r("metadata.auth_pass", "fake_metadata", 0.5, r"\b(spf|dkim|dmarc)\s*[=:]\s*pass\b"),
    _r("metadata.auth_results_header", "fake_metadata", 0.6, r"^\s*authentication-results\s*:"),
    _r("metadata.verified_sender", "fake_metadata", 0.45,
       r"\b(sender|origin|source|domain)\s+(is\s+)?(verified|trusted|authenticated|whitelisted|internal)\b"),
    _r("metadata.x_header", "fake_metadata", 0.5,
       r"\bx-[a-z-]*(verified|trusted|scan|spam|virus)[a-z-]*\s*:\s*(pass|clean|true|yes|0)\b"),
    _r("metadata.trust_label", "fake_metadata", 0.7, r"\btrust[_ ]?(level|label)?\s*[:=]\s*\"?(trusted|high|verified)\b"),
    # Indirect injection framed as the user's own request (AgentDojo "important_instructions"
    # and similar): a detour before the real task, a message "from me to you", pseudo-tags.
    _r("indirect.task_detour", "indirect", 0.75,
       r"\bbefore\s+(you\s+)?(can\s+)?(solve|complete|continue|finish|answer|do|start)\b[^.\n]{0,40}"
       r"\b(task|request|question|job)\b[^.\n]{0,60}\b(do|perform|complete|follow)\b[^.\n]{0,20}\b(first|following)\b"),
    _r("indirect.message_from_user", "indirect", 0.6,
       r"\b(important|urgent)\s+(message|instructions?|note)\s+from\s+me\b[^.\n]{0,60}\bto\s+you\b"),
    _r("indirect.after_you_do_that", "indirect", 0.35,
       r"\bafter\s+you\s+(do|have\s+done|complete)\s+(that|this)\b[^.\n]{0,40}\b(task|request)\b"),
    _r("indirect.info_tag", "indirect", 0.55, r"</?\s*(information|important|instruction|admin|note)\s*>"),
    # Exfiltration requests
    _r("exfil.send_secrets", "exfil", 0.8,
       r"\b(send|forward|email|e-mail|post|upload|transmit|exfiltrate|copy)\b[^.\n]{0,40}"
       r"\b(logs?|credentials?|passwords?|secrets?|keys?|tokens?|api[ _-]?keys?|database|config(uration)?)\b[^.\n]{0,40}"
       r"\b(to|at)\b[^.\n]{0,10}[\w.+-]+@[\w-]+\.[\w.]+"),
    _r("exfil.include_secrets", "exfil", 0.6,
       r"\b(include|attach|append|paste)\b[^.\n]{0,30}\b(credentials?|passwords?|secrets?|api[ _-]?keys?|tokens?|private\s+keys?)\b"),
)

TOOL_POISONING_RULES: tuple[Rule, ...] = (
    _r("tool.important_tag", "tool_poisoning", 0.8, r"<\s*(important|secret|system|hidden|instructions?)\s*>"),
    _r("tool.before_using", "tool_poisoning", 0.7, r"\bbefore\s+(using|calling|you\s+use|you\s+call)\s+(this|the|any)\s+tool\b"),
    _r("tool.hide_from_user", "tool_poisoning", 0.85,
       r"\b(do\s+not|don'?t|never)\s+(tell|mention|inform|reveal|notify|show)\b[^.\n]{0,20}\b(the\s+)?(user|human|operator|analyst)\b"),
    _r("tool.sensitive_paths", "tool_poisoning", 0.8,
       r"((~|%userprofile%|\$home)[\\/]\.(ssh|aws|cursor|config|gnupg)|\bid_rsa\b|\bmcp\.json\b|(?<![\w.])\.env\b|/etc/passwd)"),
    _r("tool.read_and_pass", "tool_poisoning", 0.6,
       r"\b(read|cat|open|load)\b[^.\n]{0,30}\b(file|contents?)\b[^.\n]{0,40}\b(pass|send|include|provide)\b"),
    _r("tool.when_available", "tool_poisoning", 0.6, r"\b(when|if)\s+(this|the)\s+tool\s+is\s+(available|present|loaded|installed)\b"),
    _r("tool.instead_of", "tool_poisoning", 0.3, r"\binstead\s+of\b[^.\n]{0,40}\b(use|call|send)\b"),
    _r("tool.sidenote", "tool_poisoning", 0.4, r"\bside\s?note\b"),
)


@dataclass(frozen=True)
class Hit:
    rule: Rule
    start: int
    end: int
    excerpt: str


def scan(text: str, rules: tuple[Rule, ...] = AI_DIRECTED_RULES) -> list[Hit]:
    hits: list[Hit] = []
    for rule in rules:
        for match in rule.pattern.finditer(text):
            hits.append(Hit(rule, match.start(), match.end(), match.group(0)[:160]))
    return hits


def combine(weights: list[float]) -> float:
    """Noisy-OR over distinct rules: several weak hits add up, none exceeds 1."""
    remaining = 1.0
    for w in weights:
        remaining *= 1.0 - max(0.0, min(1.0, w))
    return round(1.0 - remaining, 4)


def score_hits(hits: list[Hit]) -> float:
    best: dict[str, float] = {}
    for hit in hits:
        best[hit.rule.name] = max(best.get(hit.rule.name, 0.0), hit.rule.weight)
    return combine(list(best.values()))
