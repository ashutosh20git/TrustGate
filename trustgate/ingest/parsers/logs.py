"""Network, endpoint and auth log fields.

The attacker controls much of a log line: User-Agent, URI, request payload, DNS
query names, attempted usernames, file names. These map to untrusted evidence
fields; the SIEM's structured fields (IPs, ports, rule, asset IDs) map to facts.
"""

from __future__ import annotations

# Field name (dotted, OCSF-style) -> label. Any field not listed is untrusted.
ATTACKER_CONTROLLED_LOG_FIELDS = {
    "http.user_agent",
    "http.uri",
    "http.referrer",
    "http.request_body",
    "http.cookie",
    "dns.query",
    "auth.attempted_username",
    "auth.failure_reason",
    "file.name",
    "file.path",
    "process.command_line",
    "email.subject",
    "email.body",
    "email.from_display",
    "cti.description",
    "document.metadata",
}
