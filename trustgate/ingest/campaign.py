"""Campaign keys: what links alerts an attacker spread across many sender domains.

A per-sender-domain limit is beaten by sending from many domains. Campaigns still
share something: the link they push, the attachment they carry, or a templated
body. These keys let the gate count security-reducing actions per link domain,
per attachment hash and per near-duplicate body, not only per sender domain.

* url_domains: registered domains of links in the email and in QR codes.
* content_bands: MinHash locality-sensitive keys of the body's words. Bodies that
  differ in a few words (names, amounts, ticket numbers) share at least one key.
"""

from __future__ import annotations

import hashlib
import re
from urllib.parse import urlsplit

_WORD = re.compile(r"[^\W_]+")
_HOST = re.compile(r"^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,62})(?:\.[a-z0-9](?:[a-z0-9-]{0,62}))*$")
_extract = None


def registered_domain(host: str) -> str:
    """example.co.in for a.b.example.co.in, from the bundled public-suffix list (no network)."""
    global _extract
    try:
        if _extract is None:
            import tldextract

            _extract = tldextract.TLDExtract(suffix_list_urls=())
        found = _extract(host).top_domain_under_public_suffix
        if found:
            return found.lower()
    except Exception:  # noqa: BLE001 - fall back to the last two labels
        pass
    return ".".join(host.split(".")[-2:])


def url_domains(urls: list[str], limit: int = 20) -> list[str]:
    out: list[str] = []
    for url in urls:
        try:
            host = (urlsplit(url).hostname or "").lower().rstrip(".")
        except ValueError:
            continue
        if not host or not _HOST.match(host):
            continue
        domain = registered_domain(host)
        if domain and _HOST.match(domain) and domain not in out:
            out.append(domain)
        if len(out) >= limit:
            break
    return out


MINHASH_BANDS = 8
MINHASH_ROWS = 2


def minhash_bands(text: str) -> list[str]:
    """Locality-sensitive keys for near-duplicate bodies: MinHash over the body's word set
    (digits folded, so amounts and ticket numbers do not matter), 8 bands of 2 rows. Two
    bodies sharing 60% of their words share a band about 97% of the time; unrelated
    bodies (5% shared) about 2%. Empty for text too short to compare."""
    words = {re.sub(r"\d", "0", w.lower()) for w in _WORD.findall(text)}
    if len(words) < 8:
        return []
    mins = []
    for seed in range(MINHASH_BANDS * MINHASH_ROWS):
        key = seed.to_bytes(2, "big")
        mins.append(min(int.from_bytes(hashlib.blake2b(w.encode(), digest_size=4, key=key).digest(), "big")
                        for w in words))
    return [f"b{b}:" + "".join(f"{m:08x}" for m in mins[b * MINHASH_ROWS:(b + 1) * MINHASH_ROWS])
            for b in range(MINHASH_BANDS)]
