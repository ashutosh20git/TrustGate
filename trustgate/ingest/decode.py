"""Decode and sanitise untrusted text before anything reads it (blueprint step 3).

NFKC normalisation, zero-width and bidi stripping, homoglyph detection, base64
and URL decoding, hidden-HTML extraction (BeautifulSoup) and length caps.
Anything hidden, encoded or truncated is flagged, because a human reviewer would
not see it while a model would.
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
import urllib.parse
from dataclasses import dataclass, field

from bs4 import BeautifulSoup, Comment

ZERO_WIDTH = re.compile("[​-‏⁠-⁤﻿­᠎͏]")
BIDI_CONTROLS = re.compile("[‪-‮⁦-⁩]")
B64_BLOB = re.compile(r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/_-]{24,}={0,2}(?![A-Za-z0-9+/=_-])")
URL_ENCODED = re.compile(r"(?:%[0-9A-Fa-f]{2}){3,}")
# Hex: "49676e6f7265...", "49 67 6e 6f ...", "49:67:6e..." and "\x49\x67\x6e..." forms.
HEX_BLOB = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}[ :]?){12,}(?![0-9A-Fa-f])")
HEX_ESCAPED = re.compile(r"(?:\\x[0-9A-Fa-f]{2}){8,}")
_ROT13 = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
                       "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm")
_COMMON_WORDS = frozenset("the and you all this that your with from for are not ignore previous instructions close "
                          "alert send password please now".split())
HTML_HINT = re.compile(r"<\s*(html|body|div|span|p|table|font|br|a|style)\b", re.I)

HIDDEN_STYLE = re.compile(
    r"display\s*:\s*none"
    r"|visibility\s*:\s*hidden"
    r"|font-size\s*:\s*0*(?:\.0+)?(?:px|pt|em|rem|%)?\s*(?:;|!|$)"
    r"|font-size\s*:\s*0*\.?[0-9]?(?:px|pt)\s*(?:;|!|$)"
    r"|opacity\s*:\s*0*(?:\.0+)?\s*(?:;|!|$)"
    r"|max-height\s*:\s*0"
    r"|(?:^|;)\s*height\s*:\s*0(?:px)?\s*(?:;|$)",
    re.I,
)
WHITE_TEXT = re.compile(r"(?:^|;|\s)color\s*:\s*(?:#fff(?:fff)?\b|white\b|rgb\(\s*255\s*,\s*255\s*,\s*255\s*\))", re.I)
BACKGROUND = re.compile(r"background", re.I)

# Cyrillic and Greek letters that render like Latin ones. Used only to build the
# text the detector scans; the evidence shown to analysts keeps the original.
_CONFUSABLES = {
    "а": "a", "в": "b", "е": "e", "к": "k", "м": "m", "н": "h", "о": "o", "р": "p",
    "с": "c", "т": "t", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d",
    "ɡ": "g", "ո": "n", "ս": "u", "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M",
    "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T", "Х": "X", "І": "I", "Ј": "J",
    "Ѕ": "S", "α": "a", "ο": "o", "ρ": "p", "ε": "e", "ι": "i", "κ": "k", "ν": "v",
    "τ": "t", "υ": "u", "χ": "x", "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H",
    "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y",
    "Χ": "X",
}
_CONFUSABLE_TABLE = str.maketrans(_CONFUSABLES)
SCAN_TEXT_LIMIT = 200_000


@dataclass
class Decoded:
    text: str                 # what the evidence item holds (normalised, visible, capped)
    scan_text: str            # everything a model could read: visible + hidden + decoded
    flags: list[str] = field(default_factory=list)
    hidden_text: list[str] = field(default_factory=list)
    decoded_blobs: list[str] = field(default_factory=list)
    raw_length: int = 0


def _add(flags: list[str], flag: str) -> None:
    if flag not in flags:
        flags.append(flag)


def _script_of(ch: str) -> str | None:
    if not ch.isalpha():
        return None
    try:
        name = unicodedata.name(ch)
    except ValueError:
        return None
    for script in ("LATIN", "CYRILLIC", "GREEK"):
        if name.startswith(script):
            return script
    return "OTHER"


def has_mixed_script_word(text: str) -> bool:
    for word in re.findall(r"\w{2,}", text):
        scripts = {s for s in map(_script_of, word) if s in ("LATIN", "CYRILLIC", "GREEK")}
        if "LATIN" in scripts and len(scripts) > 1:
            return True
    return False


def normalise(text: str, flags: list[str]) -> str:
    text = unicodedata.normalize("NFKC", text)
    if ZERO_WIDTH.search(text):
        _add(flags, "zero_width")
        text = ZERO_WIDTH.sub("", text)
    if BIDI_CONTROLS.search(text):
        _add(flags, "bidi_control")
        text = BIDI_CONTROLS.sub("", text)
    if has_mixed_script_word(text):
        _add(flags, "homoglyph")
    return text


def fold_confusables(text: str) -> str:
    return text.translate(_CONFUSABLE_TABLE)


def _is_hidden_element(tag) -> bool:
    if tag.name in ("script", "style", "template", "noscript", "head", "title", "meta"):
        return True
    if tag.has_attr("hidden"):
        return True
    if tag.name == "input" and str(tag.get("type", "")).lower() == "hidden":
        return True
    style = str(tag.get("style", ""))
    if HIDDEN_STYLE.search(style):
        return True
    if WHITE_TEXT.search(style) and not BACKGROUND.search(style):
        return True
    color = str(tag.get("color", "")).lower()  # <font color="#ffffff">
    if tag.name == "font" and color in ("#fff", "#ffffff", "white"):
        return True
    return False


def extract_html(html: str) -> tuple[str, list[str]]:
    """Return (visible text, hidden text pieces)."""
    soup = BeautifulSoup(html, "html.parser")
    hidden: list[str] = []
    for comment in soup.find_all(string=lambda s: isinstance(s, Comment)):
        if comment.strip():
            hidden.append(comment.strip())
        comment.extract()
    for tag in soup.find_all(_is_hidden_element):
        if tag.decomposed:
            continue
        if tag.name == "input":
            value = str(tag.get("value", "")).strip()
            if value:
                hidden.append(value)
        piece = tag.get_text(" ", strip=True)
        if piece and tag.name not in ("style", "head", "meta"):
            hidden.append(piece)
        tag.decompose()
    visible = soup.get_text(" ", strip=True)
    return visible, hidden


def _printable_ratio(s: str) -> float:
    if not s:
        return 0.0
    ok = sum(1 for ch in s if ch.isprintable() or ch in "\n\r\t")
    return ok / len(s)


def decode_blobs(text: str, depth: int = 2) -> list[str]:
    """Base64 and URL-encoded segments that decode to readable text."""
    found: list[str] = []
    for match in B64_BLOB.finditer(text):
        blob = match.group(0)
        padded = blob + "=" * (-len(blob) % 4)
        for decoder in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                raw = decoder(padded)
                candidate = raw.decode("utf-8")
            except (binascii.Error, ValueError, UnicodeDecodeError):
                continue
            if len(candidate) >= 8 and _printable_ratio(candidate) > 0.9 and re.search(r"[A-Za-z]{3}", candidate):
                found.append(candidate)
                if depth > 1:
                    found.extend(decode_blobs(candidate, depth - 1))
                break
    for match in URL_ENCODED.finditer(text):
        decoded = urllib.parse.unquote(match.group(0))
        if decoded != match.group(0) and _printable_ratio(decoded) > 0.9:
            found.append(decoded)
    for match in [*HEX_BLOB.finditer(text), *HEX_ESCAPED.finditer(text)]:
        digits = re.sub(r"[^0-9A-Fa-f]", "", match.group(0).replace("\\x", ""))
        try:
            candidate = bytes.fromhex(digits).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue  # hashes and binary decode to nothing readable
        if len(candidate) >= 8 and _printable_ratio(candidate) > 0.9 and re.search(r"[A-Za-z]{3}", candidate):
            found.append(candidate)
    rot = rot13_if_readable(text)
    if rot:
        found.append(rot)
    return found


def rot13(text: str) -> str:
    return text.translate(_ROT13)


def _common_words(text: str) -> int:
    return sum(1 for w in re.findall(r"[a-z]+", text.lower()) if w in _COMMON_WORDS)


def rot13_if_readable(text: str) -> str | None:
    """The ROT13 reading of text, when it reads as English and the text as written does not."""
    rot = rot13(text)
    gained = _common_words(rot)
    return rot if gained >= 3 and gained > 2 * _common_words(text) else None


def sanitise(raw: str, *, max_chars: int = 4000, is_html: bool | None = None) -> Decoded:
    flags: list[str] = []
    raw = raw or ""
    raw_length = len(raw)
    if raw_length > SCAN_TEXT_LIMIT:
        _add(flags, "oversize")
        raw = raw[:SCAN_TEXT_LIMIT]

    text = normalise(raw, flags)
    hidden: list[str] = []
    if is_html or (is_html is None and HTML_HINT.search(text)):
        visible, hidden = extract_html(text)
        if hidden:
            _add(flags, "hidden_text")
        text = visible

    blobs = decode_blobs(text) + [b for piece in hidden for b in decode_blobs(piece)]
    if blobs:
        _add(flags, "encoded_blob")
    if URL_ENCODED.search(text):
        _add(flags, "url_encoded")

    # The detector scans the full text, not the truncated version (silent failure 10).
    scan_parts = [text, *hidden, *blobs]
    scan_text = fold_confusables("\n".join(p for p in scan_parts if p))

    if len(text) > max_chars:
        _add(flags, "truncated")
        text = text[:max_chars] + " …[truncated]"

    return Decoded(
        text=text,
        scan_text=scan_text,
        flags=flags,
        hidden_text=hidden,
        decoded_blobs=blobs,
        raw_length=raw_length,
    )
