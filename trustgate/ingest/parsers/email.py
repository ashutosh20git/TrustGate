"""Email parsing: mail-parser for content, trusted headers and dkimpy/pyspf/checkdmarc for auth.

Authentication results are trusted only from the topmost Authentication-Results
header whose authserv-id is our own MTA (TRUSTGATE_MTA_AUTHSERV_ID). An attacker
can write their own Authentication-Results header into the message (ADI-style
fake metadata); any header claiming our authserv-id below the top one is flagged
as spoofed and kept as untrusted evidence.
"""

from __future__ import annotations

import base64
import email
import email.policy
import email.utils
import re
from dataclasses import dataclass, field

import mailparser

AUTH_RESULT = re.compile(r"\b(spf|dkim|dmarc|arc|bimi)\s*=\s*([a-z]+)", re.I)
HEADER_DOMAIN = re.compile(r"\bheader\.(?:d|i|from)\s*=\s*@?([A-Za-z0-9.-]+)", re.I)
URL = re.compile(r"\bhttps?://[^\s<>\"')\]]+", re.I)
UNTRUSTED_HEADERS = ("Reply-To", "Return-Path", "Sender", "X-Mailer", "List-Unsubscribe", "Message-ID")


@dataclass
class AuthFacts:
    spf_pass: bool | None = None
    dkim_pass: bool | None = None
    dmarc_pass: bool | None = None
    arc_pass: bool | None = None   # ARC chain (forwarded mail), from the trusted header only
    bimi_pass: bool | None = None  # BIMI needs a verified mark certificate: costly to fake
    source: str = "none"  # "mta_header", "live", "none"


@dataclass
class ParsedEmail:
    from_display: str = ""
    from_address: str = ""
    from_domain: str = ""
    subject: str = ""
    body_text: str = ""
    body_html: str = ""
    untrusted_headers: dict[str, str] = field(default_factory=dict)
    spoofed_auth_headers: list[str] = field(default_factory=list)
    attachments: list[tuple[str, bytes]] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    reply_to_domain: str = ""
    auth: AuthFacts = field(default_factory=AuthFacts)


# Microsoft 365 / Exchange Online writes Authentication-Results without the authserv-id RFC 8601
# requires ("spf=pass (sender IP is ...) ...; dmarc=..."). With TRUSTGATE_MTA_AUTHSERV_ID set to
# this value, the topmost header *without* an authserv-id is the trusted one, and any lower header
# without one is flagged as spoofed, exactly as for a named authserv-id.
MICROSOFT_365 = "microsoft365"


def _authserv_id(header_value: str) -> str:
    first = header_value.split(";", 1)[0].strip().lower()
    return "" if "=" in first else first  # no authserv-id: the first clause is already a result


def _result_to_bool(value: str | None) -> bool | None:
    if value is None:
        return None
    value = value.lower()
    if value == "pass":
        return True
    if value in ("fail", "softfail", "permerror", "hardfail"):
        return False
    return None  # none, neutral, temperror, policy: unknown


def auth_from_headers(headers: list[str], trusted_authserv_id: str | None) -> tuple[AuthFacts, list[str]]:
    """headers: every Authentication-Results value, topmost first."""
    spoofed: list[str] = []
    if not trusted_authserv_id or not headers:
        return AuthFacts(), spoofed
    trusted_id = trusted_authserv_id.strip().lower()
    if trusted_id == MICROSOFT_365:
        trusted_id = ""
    facts = AuthFacts()
    if _authserv_id(headers[0]) == trusted_id:
        results = {m.group(1).lower(): m.group(2) for m in AUTH_RESULT.finditer(headers[0])}
        facts = AuthFacts(
            spf_pass=_result_to_bool(results.get("spf")),
            dkim_pass=_result_to_bool(results.get("dkim")),
            dmarc_pass=_result_to_bool(results.get("dmarc")),
            arc_pass=_result_to_bool(results.get("arc")),
            bimi_pass=_result_to_bool(results.get("bimi")),
            source="mta_header",
        )
    for value in headers[1:]:
        if _authserv_id(value) == trusted_id:
            spoofed.append(value)
    return facts, spoofed


def parse_email(raw: bytes, *, trusted_authserv_id: str | None) -> ParsedEmail:
    msg = email.message_from_bytes(raw, policy=email.policy.default)
    mail = mailparser.parse_from_bytes(raw)

    parsed = ParsedEmail()
    if mail.from_:
        display, address = mail.from_[0]
        parsed.from_display = display or ""
        parsed.from_address = (address or "").strip().lower()
        parsed.from_domain = parsed.from_address.rsplit("@", 1)[-1] if "@" in parsed.from_address else ""
    parsed.subject = mail.subject or ""
    reply_to = email.utils.parseaddr(str(msg.get("Reply-To") or ""))[1].strip().lower()
    parsed.reply_to_domain = reply_to.rsplit("@", 1)[-1] if "@" in reply_to else ""
    parsed.body_text = "\n".join(mail.text_plain or [])
    parsed.body_html = "\n".join(mail.text_html or [])

    ar_headers = [str(v) for v in (msg.get_all("Authentication-Results") or [])]
    parsed.auth, parsed.spoofed_auth_headers = auth_from_headers(ar_headers, trusted_authserv_id)
    # Every non-trusted Authentication-Results header is attacker-writable evidence.
    for i, value in enumerate(ar_headers):
        if (i == 0 and parsed.auth.source == "mta_header") or value in parsed.spoofed_auth_headers:
            continue  # the trusted header is a fact; spoofed ones are added separately, flagged
        parsed.untrusted_headers[f"Authentication-Results[{i}]"] = value
    for name in UNTRUSTED_HEADERS:
        value = msg.get(name)
        if value:
            parsed.untrusted_headers[name] = str(value)
    for name, value in msg.items():
        if name.lower().startswith("x-") and name not in parsed.untrusted_headers:
            parsed.untrusted_headers[name] = str(value)

    for att in mail.attachments or []:
        payload = att.get("payload") or ""
        if att.get("binary"):
            data = base64.b64decode(payload)
        else:
            data = payload.encode("utf-8", errors="replace") if isinstance(payload, str) else bytes(payload)
        parsed.attachments.append((att.get("filename") or "", data))

    parsed.urls = sorted(set(URL.findall(parsed.body_text) + URL.findall(parsed.body_html)))[:50]
    return parsed


# --- Live verification (dkimpy, pyspf, checkdmarc) --------------------------
# Used when the SIEM supplies the envelope (client IP, MAIL FROM, HELO) instead of
# an MTA Authentication-Results header. Needs DNS; any lookup failure -> unknown.

def verify_dkim(raw: bytes) -> tuple[bool | None, str]:
    try:
        import dkim

        signature = email.message_from_bytes(raw).get("DKIM-Signature")
        if not signature:
            return None, ""
        domain = re.search(r"\bd=([^;\s]+)", str(signature))
        return bool(dkim.verify(raw)), (domain.group(1).lower() if domain else "")
    except Exception:
        return None, ""


def check_spf(client_ip: str, mail_from: str, helo: str) -> bool | None:
    try:
        import spf

        result, _explanation = spf.check2(i=client_ip, s=mail_from, h=helo)
        return _result_to_bool(result)
    except Exception:
        return None


def _registered_domain(domain: str) -> str:
    import tldextract

    return tldextract.extract(domain).top_domain_under_public_suffix.lower()


def check_dmarc(from_domain: str, *, spf_ok: bool | None, spf_domain: str,
                dkim_ok: bool | None, dkim_domain: str) -> bool | None:
    """Relaxed alignment: a passing SPF or DKIM domain must share the From's registered domain."""
    if not from_domain:
        return None
    try:
        import checkdmarc

        checkdmarc.get_dmarc_record(from_domain)  # raises if there is no DMARC record
    except Exception:
        return None
    org = _registered_domain(from_domain)
    aligned_spf = bool(spf_ok) and spf_domain and _registered_domain(spf_domain) == org
    aligned_dkim = bool(dkim_ok) and dkim_domain and _registered_domain(dkim_domain) == org
    if aligned_spf or aligned_dkim:
        return True
    if spf_ok is None and dkim_ok is None:
        return None
    return False


def live_auth(raw: bytes, from_domain: str, envelope: dict) -> AuthFacts:
    dkim_ok, dkim_domain = verify_dkim(raw)
    mail_from = str(envelope.get("mail_from") or "")
    spf_ok = None
    if envelope.get("client_ip") and mail_from:
        spf_ok = check_spf(str(envelope["client_ip"]), mail_from, str(envelope.get("helo") or ""))
    spf_domain = mail_from.rsplit("@", 1)[-1] if "@" in mail_from else ""
    dmarc_ok = check_dmarc(from_domain, spf_ok=spf_ok, spf_domain=spf_domain, dkim_ok=dkim_ok, dkim_domain=dkim_domain)
    return AuthFacts(spf_pass=spf_ok, dkim_pass=dkim_ok, dmarc_pass=dmarc_ok, source="live")
