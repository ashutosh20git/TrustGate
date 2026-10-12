"""Threat-intel enrichment: httpx + tenacity retries + diskcache.

Only scores and enums leave this module. Feed descriptions are attacker-
writable (silent failure 15) and are never read. A missing API key is a
placeholder: that lookup is skipped and the fact stays unknown, which can only
make the facts-only re-check less willing to say "benign".
"""

from __future__ import annotations

import base64
import datetime as dt
from dataclasses import dataclass, field

import httpx
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from trustgate.config import Settings

_REPUTATION_ORDER = {"unknown": 0, "clean": 1, "suspicious": 2, "malicious": 3}
# Across several links: one link nobody could vouch for outweighs another link's clean result.
_ACROSS_URLS = {"clean": 0, "unknown": 1, "suspicious": 2, "malicious": 3}


def url_verdict(answers: list[str], quorum: int) -> str:
    """One URL's reputation from the sources that answered. Any bad answer wins (sources
    disagreeing is itself a warning); "clean" needs at least quorum sources saying clean."""
    known = [a for a in answers if a != "unknown"]
    bad = [a for a in known if a != "clean"]
    if bad:
        return max(bad, key=_REPUTATION_ORDER.__getitem__)
    return "clean" if len(known) >= max(1, quorum) else "unknown"
MALICIOUS_ABUSE = 50  # an IP's own AbuseIPDB confidence at which it counts as malicious
_SANDBOX_ORDER = {"not_run": 0, "clean": 1, "suspicious": 2, "malicious": 3}


@dataclass
class EnrichmentReport:
    ip_abuse_score: int | None = None
    asn: int | None = None
    url_reputation: str = "unknown"
    sandbox_verdict: str = "not_run"
    sender_domain_age_days: int | None = None
    malicious_ips: list[str] = field(default_factory=list)  # IPs whose own abuse score is high
    sources: list[str] = field(default_factory=list)  # "abuseipdb", "virustotal: not configured", ...
    failed: list[str] = field(default_factory=list)   # lookups that errored: their facts are missing, not clean


def _worse(a: str, b: str, order: dict[str, int]) -> str:
    return a if order[a] >= order[b] else b


def _stats_to_verdict(stats: dict) -> str:
    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    if malicious >= 2:
        return "malicious"
    if malicious == 1 or suspicious >= 1:
        return "suspicious"
    return "clean"


class ThreatIntel:
    def __init__(self, settings: Settings, *, client: httpx.Client | None = None, cache=None):
        self.s = settings
        self._client = client or httpx.Client(timeout=10)
        if cache is None:
            import diskcache

            cache = diskcache.Cache(settings.ti_cache_dir)
        self._cache = cache

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=0.5, max=4),
           retry=retry_if_exception_type((httpx.TransportError, httpx.HTTPStatusError)), reraise=True)
    def _request(self, method: str, url: str, **kwargs) -> httpx.Response:
        resp = self._client.request(method, url, **kwargs)
        # Rate limits, outages and rejected keys are failures, not "no data":
        # swallowing them would leave a fact unknown with nothing to show why.
        if resp.status_code in (401, 403, 429) or resp.status_code >= 500:
            resp.raise_for_status()
        return resp

    def _cached(self, key: str, fetch):
        if key in self._cache:
            return self._cache[key]
        value = fetch()
        self._cache.set(key, value, expire=7 * 24 * 3600)
        return value

    # --- individual lookups -------------------------------------------------

    def abuseipdb_score(self, ip: str) -> int | None:
        if not self.s.abuseipdb_api_key:
            return None

        def fetch():
            r = self._request("GET", "https://api.abuseipdb.com/api/v2/check",
                              params={"ipAddress": ip, "maxAgeInDays": 90},
                              headers={"Key": self.s.abuseipdb_api_key, "Accept": "application/json"})
            if r.status_code != 200:
                return None
            score = r.json().get("data", {}).get("abuseConfidenceScore")
            return int(score) if isinstance(score, int) else None

        return self._cached(f"abuseipdb:{ip}", fetch)

    def otx_asn(self, ip: str) -> int | None:
        if not self.s.otx_api_key:
            return None

        def fetch():
            r = self._request("GET", f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
                              headers={"X-OTX-API-KEY": self.s.otx_api_key})
            if r.status_code != 200:
                return None
            asn = str(r.json().get("asn") or "")
            digits = asn.upper().removeprefix("AS").split(" ", 1)[0]
            return int(digits) if digits.isdigit() else None

        return self._cached(f"otx:asn:{ip}", fetch)

    def virustotal_url(self, url: str) -> str:
        if not self.s.virustotal_api_key:
            return "unknown"
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

        def fetch():
            r = self._request("GET", f"https://www.virustotal.com/api/v3/urls/{url_id}",
                              headers={"x-apikey": self.s.virustotal_api_key})
            if r.status_code != 200:
                return "unknown"
            stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return _stats_to_verdict(stats)

        return self._cached(f"vt:url:{url}", fetch)

    def virustotal_file(self, sha256: str) -> str:
        if not self.s.virustotal_api_key:
            return "not_run"

        def fetch():
            r = self._request("GET", f"https://www.virustotal.com/api/v3/files/{sha256}",
                              headers={"x-apikey": self.s.virustotal_api_key})
            if r.status_code != 200:
                return "not_run"
            stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return _stats_to_verdict(stats)

        return self._cached(f"vt:file:{sha256}", fetch)

    def urlhaus(self, url: str) -> str:
        if not self.s.urlhaus_auth_key:
            return "unknown"

        def fetch():
            r = self._request("POST", "https://urlhaus-api.abuse.ch/v1/url/", data={"url": url},
                              headers={"Auth-Key": self.s.urlhaus_auth_key})
            if r.status_code != 200:
                return "unknown"
            body = r.json()
            if body.get("query_status") == "ok":
                return "malicious"
            return "clean" if body.get("query_status") == "no_results" else "unknown"

        return self._cached(f"urlhaus:{url}", fetch)

    def domain_age_days(self, domain: str) -> int | None:
        if not domain:
            return None

        def fetch():
            try:
                import whois

                created = whois.whois(domain).creation_date
            except Exception:
                return None
            if isinstance(created, list):
                created = min((c for c in created if isinstance(c, dt.datetime)), default=None)
            if not isinstance(created, dt.datetime):
                return None
            now = dt.datetime.now(created.tzinfo) if created.tzinfo else dt.datetime.now()
            return max(0, (now - created).days)

        return self._cached(f"whois:{domain}", fetch)

    # --- combined -----------------------------------------------------------

    def enrich(self, *, ips: list[str], urls: list[str], file_hashes: list[str], sender_domain: str) -> EnrichmentReport:
        report = EnrichmentReport()
        for name, key in (("abuseipdb", self.s.abuseipdb_api_key), ("otx", self.s.otx_api_key),
                          ("virustotal", self.s.virustotal_api_key), ("urlhaus", self.s.urlhaus_auth_key)):
            report.sources.append(name if key else f"{name}: not configured")

        def safe(fn, arg):
            return self._safe(fn, arg, report)

        per_ip = {ip: safe(self.abuseipdb_score, ip) for ip in ips}
        scores = [s for s in per_ip.values() if s is not None]
        report.ip_abuse_score = max(scores) if scores else None
        report.malicious_ips = [ip for ip, score in per_ip.items() if score is not None and score >= MALICIOUS_ABUSE]
        for ip in ips[:5]:
            report.asn = report.asn or safe(self.otx_asn, ip)

        if urls:
            per_url = [url_verdict([safe(lookup, url) or "unknown" for lookup in (self.virustotal_url, self.urlhaus)],
                                   self.s.ti_quorum) for url in urls[:10]]
            report.url_reputation = max(per_url, key=_ACROSS_URLS.__getitem__)
        else:
            report.url_reputation = "clean"  # nothing to look up, nothing bad

        sandbox = "not_run"
        for sha in file_hashes[:10]:
            verdict = safe(self.virustotal_file, sha) or "not_run"
            sandbox = _worse(sandbox, verdict, _SANDBOX_ORDER)
        report.sandbox_verdict = sandbox

        report.sender_domain_age_days = safe(self.domain_age_days, sender_domain)
        return report

    @staticmethod
    def _safe(fn, arg, report: EnrichmentReport):
        try:
            return fn(arg)
        except Exception as exc:
            # A failed lookup leaves the fact unknown, and says so: the gate
            # will not let a T1 action rest on a lookup that never happened.
            report.failed.append(f"{getattr(fn, '__name__', 'lookup')}: {type(exc).__name__}")
            return None
