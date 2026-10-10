"""Cross-entry stitch check (silent failure 8).

Context stitching splits one payload across several log entries so that no
single entry looks malicious. The detector therefore also scans the assembled
text and reports matches that span more than one evidence item.
"""

from __future__ import annotations

from dataclasses import dataclass

from trustgate.detector.heuristics import AI_DIRECTED_RULES, Hit, scan


@dataclass(frozen=True)
class StitchHit:
    hit: Hit
    evidence_ids: list[str]


def _assemble(parts: list[tuple[str, str]], sep: str) -> tuple[str, list[tuple[int, int, str]]]:
    text_parts: list[str] = []
    spans: list[tuple[int, int, str]] = []
    pos = 0
    for evidence_id, text in parts:
        spans.append((pos, pos + len(text), evidence_id))
        text_parts.append(text)
        pos += len(text) + len(sep)
    return sep.join(text_parts), spans


def stitched_hits(parts: list[tuple[str, str]]) -> list[StitchHit]:
    """parts: (evidence_id, scan_text) in alert order."""
    if len(parts) < 2:
        return []
    found: list[StitchHit] = []
    seen: set[tuple[str, tuple[str, ...]]] = set()
    # Joined with a space (split at word boundaries) and with nothing (split mid-word).
    for sep in (" ", ""):
        assembled, spans = _assemble(parts, sep)
        for hit in scan(assembled, AI_DIRECTED_RULES):
            ids = [eid for start, end, eid in spans if start < hit.end and hit.start < end]
            if len(ids) < 2:
                continue
            key = (hit.rule.name, tuple(ids))
            if key not in seen:
                seen.add(key)
                found.append(StitchHit(hit, ids))
    return found
