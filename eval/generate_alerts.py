"""Generate labelled SOC alerts for the evaluation.

Real datasets (CIC-IDS2017, UNSW-NB15, Splunk BOTS, phishing corpora, Enron)
need registration/downloads and are not bundled, so this produces synthetic
alerts with the same shape and ground-truth labels: a mix of genuinely benign
and genuinely malicious email, network, endpoint and auth alerts. Drop a real
dataset loader in eval/datasets/ and point --source at it to replace this.
See PLACEHOLDERS.md (tg: datasets issue).

Each alert is a raw-alert dict (the shape services/ingest accepts), plus a
"ground_truth" field used only by the metrics, never shown to the agent.
"""

from __future__ import annotations

import base64
import random
from typing import Any

BENIGN_SENDERS = [
    ("Acme Payments", "billing@acme-pay.example", "acme-pay.example", 4200),
    ("HR Team", "people@corp.example", "corp.example", 3600),
    ("GitHub", "noreply@github.example", "github.example", 5000),
]
PHISH_SENDERS = [
    ("PayPal Billing", "billing@paypa1-billing.example", "paypa1-billing.example", 3),
    ("IT Helpdesk", "support@corp-secure-login.example", "corp-secure-login.example", 1),
    ("Docu Sign", "no-reply@docusign-verify.example", "docusign-verify.example", 9),
]
BENIGN_SUBJECTS = ["Your October invoice", "Benefits enrolment reminder", "Pull request merged"]
PHISH_SUBJECTS = ["Account suspended - verify now", "Unusual sign-in, confirm identity", "Payment overdue"]
MALICIOUS_IPS = ["203.0.113.9", "198.51.100.23", "203.0.113.77"]
BENIGN_IPS = ["93.184.216.34", "140.82.112.3"]
INTERNAL_HOSTS = ["ws-014.corp.example", "ws-233.corp.example", "laptop-55.corp.example"]
ACCOUNTS = ["j.doe", "a.kumar", "s.patel"]


def _email_bytes(display: str, addr: str, subject: str, body_html: str, *, authserv: str,
                 spf: str, dkim: str, dmarc: str, header_from_domain: str) -> bytes:
    raw = (
        f"Authentication-Results: {authserv}; spf={spf} smtp.mailfrom={addr}; dkim={dkim}; "
        f"dmarc={dmarc} header.from={header_from_domain}\r\n"
        f"From: \"{display}\" <{addr}>\r\n"
        f"To: soc@corp.example\r\n"
        f"Subject: {subject}\r\n"
        f"Content-Type: text/html; charset=utf-8\r\n\r\n"
        f"<html><body>{body_html}</body></html>\r\n"
    )
    return raw.encode("utf-8")


def _email_alert(i: int, rng: random.Random, malicious: bool, authserv: str) -> dict[str, Any]:
    if malicious:
        display, addr, domain, age = rng.choice(PHISH_SENDERS)
        subject = rng.choice(PHISH_SUBJECTS)
        body = '<p>Please verify your account at <a href="http://login-verify.example/secure">this link</a>.</p>'
        spf, dkim, dmarc = "fail", "none", "fail"
        ioc_ips = [rng.choice(MALICIOUS_IPS)]
    else:
        display, addr, domain, age = rng.choice(BENIGN_SENDERS)
        subject = rng.choice(BENIGN_SUBJECTS)
        body = "<p>Here is your monthly summary. No action needed.</p>"
        spf, dkim, dmarc = "pass", "pass", "pass"
        ioc_ips = []
    raw = _email_bytes(display, addr, subject, body, authserv=authserv, spf=spf, dkim=dkim, dmarc=dmarc,
                       header_from_domain=domain)
    return {
        "alert_id": f"E-{i:04d}",
        "source": "email",
        "severity": "high" if malicious else "low",
        "rule_name": "phishing_reported" if malicious else "mail_flagged",
        # MTA history: established senders have delivered mail before; phishing senders have not.
        "observed": {"ioc_ips": ioc_ips, "sender_prior_messages": 0 if malicious else rng.randint(5, 400)},
        "enrichment": {"sender_domain_age_days": age,
                       "url_reputation": "malicious" if malicious else "clean",
                       "sandbox_verdict": "not_run"},
        "email": {"raw_b64": base64.b64encode(raw).decode(), "envelope": {}},
        "ground_truth": {"label": "malicious" if malicious else "benign", "scenario": "phishing"},
    }


def _network_alert(i: int, rng: random.Random, malicious: bool) -> dict[str, Any]:
    ip = rng.choice(MALICIOUS_IPS if malicious else BENIGN_IPS)
    ua = "sqlmap/1.7 (http://sqlmap.org)" if malicious else "Mozilla/5.0 (Windows NT 10.0)"
    return {
        "alert_id": f"N-{i:04d}",
        "source": "network",
        "severity": "high" if malicious else "low",
        "rule_name": "ids_signature" if malicious else "flow_anomaly",
        "observed": {"ioc_ips": [ip]},
        "enrichment": {"ip_abuse_score": 92 if malicious else 2, "asn": 64500,
                       "url_reputation": "unknown", "sandbox_verdict": "not_run"},
        "fields": {"http.user_agent": ua, "http.uri": "/admin/login.php", "dns.query": "c2.example" if malicious else "cdn.example"},
        "ground_truth": {"label": "malicious" if malicious else "benign", "scenario": "network"},
    }


def _endpoint_alert(i: int, rng: random.Random, malicious: bool) -> dict[str, Any]:
    host = rng.choice(INTERNAL_HOSTS)
    sha = ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" if malicious
           else "da39a3ee5e6b4b0d3255bfef95601890afd80709da39a3ee5e6b4b0d32558000")
    return {
        "alert_id": f"P-{i:04d}",
        "source": "endpoint",
        "severity": "critical" if malicious else "low",
        "rule_name": "edr_detection" if malicious else "edr_info",
        "observed": {"hosts": [host], "ioc_hashes": [sha]},
        "enrichment": {"sandbox_verdict": "malicious" if malicious else "clean", "url_reputation": "unknown"},
        "fields": {"process.command_line": "powershell -enc <...>" if malicious else "explorer.exe",
                   "file.name": "invoice.exe" if malicious else "report.pdf"},
        "ground_truth": {"label": "malicious" if malicious else "benign", "scenario": "endpoint", "host": host},
    }


def _auth_alert(i: int, rng: random.Random, malicious: bool) -> dict[str, Any]:
    account = rng.choice(ACCOUNTS)
    return {
        "alert_id": f"A-{i:04d}",
        "source": "auth",
        "severity": "high" if malicious else "low",
        "rule_name": "impossible_travel" if malicious else "login_info",
        "observed": {"accounts": [account], "ioc_ips": [rng.choice(MALICIOUS_IPS)] if malicious else []},
        "enrichment": {"ip_abuse_score": 80 if malicious else 1, "url_reputation": "unknown", "sandbox_verdict": "not_run"},
        "fields": {"auth.attempted_username": account, "auth.failure_reason": "bad_password" if malicious else "none"},
        "ground_truth": {"label": "malicious" if malicious else "benign", "scenario": "auth", "account": account},
    }


def generate(n: int = 200, *, malicious_ratio: float = 0.5, seed: int = 7,
             authserv_id: str = "mx.corp.example") -> list[dict[str, Any]]:
    rng = random.Random(seed)
    builders = (_email_alert, _network_alert, _endpoint_alert, _auth_alert)
    alerts: list[dict[str, Any]] = []
    for i in range(n):
        malicious = rng.random() < malicious_ratio
        builder = builders[i % len(builders)]
        alert = builder(i, rng, malicious, authserv_id) if builder is _email_alert else builder(i, rng, malicious)
        alerts.append(alert)
    return alerts


if __name__ == "__main__":
    import argparse
    import json

    parser = argparse.ArgumentParser()
    parser.add_argument("-n", type=int, default=200)
    parser.add_argument("-o", default="eval/datasets/alerts.jsonl")
    args = parser.parse_args()
    import os

    os.makedirs(os.path.dirname(args.o), exist_ok=True)
    with open(args.o, "w", encoding="utf-8") as fh:
        for alert in generate(args.n):
            fh.write(json.dumps(alert) + "\n")
    print(f"wrote {args.n} alerts to {args.o}")
