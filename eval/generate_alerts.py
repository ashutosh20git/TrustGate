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
        "observed": {"ioc_ips": ioc_ips, "malicious_ips": ioc_ips,
                     "sender_prior_messages": 0 if malicious else rng.randint(5, 400),
                     # The SIEM's behaviour signals for this sender (both quiet here).
                     "sender_first_link": False, "sender_new_sending_ip": False},
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
        "observed": {"ioc_ips": [ip], "malicious_ips": [ip] if malicious else []},
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
    ip = rng.choice(MALICIOUS_IPS) if malicious else None
    return {
        "alert_id": f"A-{i:04d}",
        "source": "auth",
        "severity": "high" if malicious else "low",
        "rule_name": "impossible_travel" if malicious else "login_info",
        "observed": {"accounts": [account], "ioc_ips": [ip] if ip else [], "malicious_ips": [ip] if ip else []},
        "enrichment": {"ip_abuse_score": 80 if malicious else 1, "url_reputation": "unknown", "sandbox_verdict": "not_run"},
        "fields": {"auth.attempted_username": account, "auth.failure_reason": "bad_password" if malicious else "none"},
        "ground_truth": {"label": "malicious" if malicious else "benign", "scenario": "auth", "account": account},
    }


def _hard_email(i: int, rng: random.Random, authserv: str) -> dict[str, Any]:
    """Malicious emails whose cheap facts look clean (training only). Either an attacker who
    owns the domain (SPF/DKIM/DMARC pass, aged domain, clean file-host link, no history with
    us), or a compromised real account (history, but behaving unusually)."""
    compromised = rng.random() < 0.5
    domain = "corp-partner.example" if compromised else "acme-billing-portal.example"
    addr = f"accounts@{domain}"
    raw = _email_bytes("Accounts", addr, rng.choice(BENIGN_SUBJECTS), "<p>Invoice attached, please review.</p>",
                       authserv=authserv, spf="pass", dkim="pass", dmarc="pass", header_from_domain=domain)
    observed: dict[str, Any] = {"ioc_ips": [], "sender_prior_messages": 0, "org_replied_to_sender": False,
                                "org_url_domain_first_seen": True}
    if compromised:
        anomaly = rng.choice(("sender_first_link", "sender_first_attachment", "reply_to_mismatch",
                              "sender_new_sending_ip", "org_url_domain_first_seen"))
        observed = {"ioc_ips": [], "sender_prior_messages": rng.randint(20, 400), "org_replied_to_sender": True,
                    "org_url_domain_first_seen": False, anomaly: True}
    return {
        "alert_id": f"H-{i:04d}", "source": "email", "severity": "medium", "rule_name": "mail_flagged",
        "observed": observed,
        "enrichment": {"sender_domain_age_days": rng.randint(400, 4000), "url_reputation": "clean",
                       "sandbox_verdict": "not_run", "cert_age_days": rng.randint(1, 20)},
        "email": {"raw_b64": base64.b64encode(raw).decode(), "envelope": {}},
        "ground_truth": {"label": "malicious", "scenario": "compromised_account" if compromised else "owned_domain"},
    }


# Optional facts a deployment may or may not supply. During training each is dropped at
# random with the same probability for every label, so "missing" never predicts the label
# (otherwise the model learns "no cert age = malicious" instead of judging the facts).
_OPTIONAL = ("org_replied_to_sender", "org_url_domain_first_seen", "org_sender_domain_messages", "cert_age_days",
             "domain_first_seen_days", "process_signed", "asset_criticality", "sender_domain_age_days",
             "sender_first_link", "sender_first_attachment", "sender_new_sending_ip")
_ANOMALIES = ("sender_first_link", "sender_first_attachment", "sender_new_sending_ip", "org_url_domain_first_seen")
_CORE = {"email": ("observed", "dmarc_pass"), "network": ("enrichment", "ip_abuse_score"),
         "auth": ("enrichment", "ip_abuse_score"), "endpoint": ("enrichment", "sandbox_verdict")}


def _enrich_for_training(alert: dict[str, Any], rng: random.Random, malicious: bool) -> None:
    """Organisation-history and infrastructure facts, so the model learns to use them."""
    obs, enr = alert.setdefault("observed", {}), alert.setdefault("enrichment", {})
    if alert["source"] == "email":
        # Legitimate senders and attacker-bought aged domains share one wide age range, so the
        # model cannot memorise a few fixed ages; only fresh phishing domains are young.
        if not malicious or alert["alert_id"].startswith("H-"):
            enr["sender_domain_age_days"] = rng.randint(200, 8000)
        obs.setdefault("org_url_domain_first_seen", malicious and rng.random() < 0.8)
        for flag in _ANOMALIES:  # MTA history reports "no" as well as "yes"
            obs.setdefault(flag, False)
        obs.setdefault("org_replied_to_sender", (not malicious) and rng.random() < 0.8)
        obs.setdefault("org_sender_domain_messages", rng.randint(0, 3) if malicious else rng.randint(10, 5000))
        enr.setdefault("cert_age_days", rng.randint(1, 60) if malicious else rng.randint(30, 900))
        enr.setdefault("domain_first_seen_days", rng.randint(1, 60) if malicious else rng.randint(200, 6000))
    if alert["source"] in ("network", "auth"):
        enr["ip_abuse_score"] = rng.randint(30, 100) if malicious else rng.randint(0, 20)
    if alert["source"] == "endpoint":
        obs.setdefault("process_signed", (not malicious) or rng.random() < 0.3)
        obs.setdefault("asset_criticality", rng.choice(("low", "medium", "high")))
    for name in _OPTIONAL:
        if obs.get(name) is True and name in _ANOMALIES:
            continue  # never hide the warning sign that makes a compromised-account example malicious
        if rng.random() < 0.35:
            obs.pop(name, None)
            enr.pop(name, None)


def _unresolved(alert: dict[str, Any]) -> dict[str, Any]:
    """The same alert with its core fact unknown, labelled "unsure": unknown is not benign."""
    where, name = _CORE[alert["source"]]
    alert.setdefault(where, {})[name] = None if name != "sandbox_verdict" else "not_run"
    if alert["source"] == "email":  # the trusted header would supply DMARC: strip it from the message too
        raw = base64.b64decode(alert["email"]["raw_b64"]).decode("utf-8", errors="replace")
        raw = "\r\n".join(line for line in raw.split("\r\n") if not line.startswith("Authentication-Results:"))
        alert["email"]["raw_b64"] = base64.b64encode(raw.encode()).decode()
        alert["observed"].pop("dmarc_pass", None)
    alert["ground_truth"] = {**alert["ground_truth"], "label": "unsure"}
    return alert


def generate(n: int = 200, *, malicious_ratio: float = 0.5, seed: int = 7,
             authserv_id: str = "mx.corp.example", training: bool = False) -> list[dict[str, Any]]:
    """training=True adds organisation-history facts and hard negatives (malicious alerts whose
    cheap facts look clean). The evaluation uses the default, so its numbers do not move."""
    rng = random.Random(seed)
    builders = (_email_alert, _network_alert, _endpoint_alert, _auth_alert)
    alerts: list[dict[str, Any]] = []
    for i in range(n):
        malicious = rng.random() < malicious_ratio
        builder = builders[i % len(builders)]
        if training and builder is _email_alert and malicious and rng.random() < 0.7:
            alert = _hard_email(i, rng, authserv_id)
            _enrich_for_training(alert, rng, malicious)
        else:
            alert = builder(i, rng, malicious, authserv_id) if builder is _email_alert else builder(i, rng, malicious)
            if training:
                _enrich_for_training(alert, rng, malicious)
                roll = rng.random()
                if roll < 0.15:
                    alert = _unresolved(alert)
                elif roll < 0.22:  # a lookup failed: the facts are missing, not clean
                    alert["observed"]["enrichment_failed"] = True
                    alert["ground_truth"] = {**alert["ground_truth"], "label": "unsure"}
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
