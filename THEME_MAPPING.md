# TrustGate: features mapped to the CyberForge themes

Theme: **AI & Cybersecurity**. Every implemented feature appears once, under the theme it fits best. Features that fit no theme are listed under [Extras](#extras-features-that-dont-fit-a-theme).

Fit: 🟢 core of the project · 🟡 real supporting features · 🔴 thin; don't claim it as a theme

| Theme | Fit | Number of features |
|---|---|---|
| [AI Security](#1-ai-security--core) | 🟢 | 16 |
| [AI-Assisted Security Operations](#2-ai-assisted-security-operations--core) | 🟢 | 14 |
| [Phishing Detection](#3-phishing-detection) | 🟡 | 10 |
| [Compliance Automation](#4-compliance-automation) | 🟡 | 6 |
| [Threat Detection](#5-threat-detection) | 🟡 | 6 |
| [Fraud Detection](#6-fraud-detection) | 🔴 | 3 |
| [Security Awareness](#7-security-awareness) | 🔴 | 3 |
| [Vulnerability Detection](#8-vulnerability-detection) | 🔴 | 2 |
| [Extras](#extras-features-that-dont-fit-a-theme) | — | 14 |

---

## 1. AI Security 🟢 core

*Detect prompt injection, prevent AI misuse, strengthen LLM security.*

| # | Feature | Where |
|---|---|---|
| 1 | **Deterministic action gate.** Sits between the AI agent and its tools; a risky action runs only when facts the attacker can't forge support it | `trustgate/gate.py` |
| 2 | **Static tier map (T0–T3).** No model writes policy | `trustgate/tiers.py` |
| 3 | **Evidence splitter.** Trusted typed facts are kept apart from quarantined untrusted text, which is wrapped in random delimiters | `trustgate/ingest/` |
| 4 | **Facts-only re-check.** Recomputes the verdict without the attacker's text, with two judges (XGBoost at confidence ≥ 0.9 plus a rule scorecard) | `recheck.py`, `scorecard.py` |
| 5 | **Attacker-cost evidence floor.** A close also needs a fact the attacker can't buy (sender history ≥ 3 messages) | `evidence_floor.py` |
| 6 | **Injection detector ensemble.** Regex, Prompt Guard 2 and LLM Guard; a hit raises severity and can never lower it | `trustgate/detector/` |
| 7 | **Hidden-text decoding.** NFKC, zero-width characters, base64, hex, ROT13, URL encoding, hidden HTML | `ingest/decode` |
| 8 | **Multilingual payloads.** Hindi, Hinglish, Tamil, Bengali, Telugu, Marathi | `eval/` attack suite |
| 9 | **MCP tool pinning.** A SHA-256 hash of each tool description; the description is also scanned, and a changed hash disables the tool | `trustgate/mcp/` |
| 10 | **MCP result handling.** Results are wrapped as untrusted; if the response shape drifts, the result is withheld, the tool disabled and the call rolled back | `trustgate/mcp/gateway` |
| 11 | **Outbound leak scanning.** Presidio PII/secret scan on decoded text, every 40-character window, with reversed/split/encoded secret detection (Luhn checks for cards, Verhoeff for Aadhaar) | `output_scan.py`, `value_match.py` |
| 12 | **Reasons hidden from the agent.** Callers see only the outcome, so the agent can't learn how to bypass the gate | `gate.py` |
| 13 | **Approvals need an analyst token.** A hijacked agent can't approve its own escalation; only token hashes are stored | `services/proxy` |
| 14 | **Sequence policy.** Only one security-reducing action per alert runs automatically | `gate.py` |
| 15 | **Cross-agent provenance.** Signed stamps on outbound text from manipulated alerts | `provenance.py` |
| 16 | **OWASP LLM Top 10 + Agentic mapping.** 20 covered, 4 partial, 2 not applicable, each mapped to tests | `docs/BENCHMARKS.md` |

**Proof:**
- **AgentDojo:** 0.00 attack success (undefended: 0.56).
- **InjecAgent:** 0.00.
- **ASB:** 0.0044.
- **Adaptive red-team:** failed at every goal.

---

## 2. AI-Assisted Security Operations 🟢 core

*Improve alert analysis, incident prioritisation and response workflows.*

| # | Feature | Where |
|---|---|---|
| 1 | **AI SOC agent.** LangGraph + LiteLLM; proposes a verdict, a tool and arguments, citing evidence IDs | `services/agent` |
| 2 | **Tiered response actions.** T0 read, T1 close/whitelist/suppress, T2 block_ip/isolate_host/disable_account, T3 send_email/webhook | `tiers.py` |
| 3 | **Disruptive-action checks.** The target must be in the typed facts with its own evidence against it, and must not be a critical asset | `gate.py`, `packs/soc.*` |
| 4 | **Schema-constrained verdicts.** Each one has an audit record | `models.py` |
| 5 | **Analyst dashboard (Streamlit).** Approve, reject or undo escalations | `services/dashboard` |
| 6 | **Action ledger + rollback.** One-click undo, and automatic rollback when an injection is found later | `store.py`, `gate.py` |
| 7 | **Counterfactual explanations.** For example, "would be allowed if `facts.dmarc_pass` were True"; they name the real cause in 14/14 cases | `counterfactual.py` |
| 8 | **Monitor mode + rollout report.** Logs "would block" without blocking; `GET /v1/rollout` shows when enforcing is safe | `gate.py`, proxy |
| 9 | **Approval re-checks.** Approvals expire after 4 h; tier and pin are checked again; T2/T3 need a second analyst | `services/proxy` |
| 10 | **Executor-failure handling.** A crash is closed as `failed`, audited and returned as a 502 | proxy |
| 11 | **TTL on suppressions and allowlists.** At most 24 h | `packs/` |
| 12 | **Rate limits (Redis).** Per tool and per sender-domain campaign | `ratelimit.py` |
| 13 | **SIEM export.** JSON lines / Splunk HEC | `store.py` |
| 14 | **Untrusted-provenance prefix.** Added to agent notes on flagged alerts | `gate.py` |

**Proof:**
- **OTRF real Windows ATT&CK telemetry:**
  - Legitimate host isolation allowed in 117/117.
  - Spoofed targets stopped in 115/115 and 86/86.
  - Close-as-benign stopped in 117/117.

---

## 3. Phishing Detection 🟡

*Detect phishing attempts and AI-generated social engineering attacks.*

| # | Feature | Where |
|---|---|---|
| 1 | **Email authentication parsing.** SPF, DKIM, DMARC, ARC, BIMI | `ingest/parsers/email` |
| 2 | **Domain and certificate age, passive DNS** | `ingest/enrich` |
| 3 | **Threat-intel enrichment.** VirusTotal, AbuseIPDB, OTX, URLhaus; failed lookups are recorded (`enrichment_failed`) | `ingest/enrich` |
| 4 | **Threat-intel quorum.** A link is clean only when enough sources agree | `ingest/enrich` |
| 5 | **Attachment parsing.** PDF, Word, Excel, PowerPoint | `ingest/attachments` |
| 6 | **Quishing detection.** QR codes (OpenCV) and OCR (Tesseract) in images and PDFs | `ingest/attachments` |
| 7 | **"AI-evasion attempt" tag.** Applied to emails that address the AI; this covers AI-generated social engineering | `detector/` |
| 8 | **Campaign linking.** Across sender domains, by link domain, attachment hash and MinHash near-duplicate bodies | `ingest/campaign` |
| 9 | **Unusual-known-sender check.** Reply-To on another domain, first link, first attachment, new IP | `evidence_floor.py` |
| 10 | **Demo scenario.** A phishing email with a hidden "close this as benign" note | `scripts/seed_demo.py` |

**Proof:**
- **phishing_pot:** 0 false benign on 12,271 real phishing emails, including 2,397 that passed DMARC.
- **Enron:** 0 false escalations on 8,245 legitimate emails.

---

## 4. Compliance Automation 🟡

*Simplify security audits and compliance evidence collection.*

| # | Feature | Where |
|---|---|---|
| 1 | **Compliance evidence packs.** CERT-In, DPDP Act 2023, ISO 27001:2022, NIST 800-53 AU | `compliance.py`, `scripts/compliance_report.py` |
| 2 | **Hash-chained audit log.** Every decision is logged | `store.py` |
| 3 | **Audit-tamper verification.** `verify_audit_export()` against the SIEM copy catches all six tamper cases | `store.py` |
| 4 | **Single audit chain across replicas.** A Postgres advisory lock stops multiple proxies forking the chain | `store.py` |
| 5 | **Policy as code.** OPA/Rego packs (`soc`, `generic`, `floor`) | `packs/` |
| 6 | **Policy regression tests.** `opa test`; CI fails if attack success rises for any attack class or language | `packs/policy_test`, `scripts/ci_eval_guard.py` |

---

## 5. Threat Detection 🟡

*Identify suspicious activity, anomalies, and potential threats.*

| # | Feature | Where |
|---|---|---|
| 1 | **Injection treated as an IOC.** It raises severity | `detector/` |
| 2 | **Behaviour-anomaly signals for known senders.** See Phishing #9; it is used here too | `evidence_floor.py` |
| 3 | **Log parsing for alerts** | `ingest/parsers/logs` |
| 4 | **Threat-intel typed facts.** IP/URL/domain reputation | `ingest/enrich` |
| 5 | **Organisation history and asset criticality facts** | `ingest/` |
| 6 | **Campaign-level rate limiting.** Spots bursts from one sender or campaign | `ratelimit.py` |

> **Caveat:** TrustGate judges whether an *action* is justified. It is not a general anomaly detector over logs.

---

## 6. Fraud Detection 🔴

*Identify suspicious transactions, account takeovers, and bot activity.*

| # | Feature | Where |
|---|---|---|
| 1 | **Account-takeover defence.** Phishing from a trusted, compromised mailbox: 75% got through before the fix, 0% after | `evidence_floor.py` |
| 2 | **AgentDojo banking suite.** 0.00 attack success across 5 attack wordings, so the agent can't be tricked into fraudulent transfers | `eval/` |
| 3 | **Payment-card and Aadhaar leak detection.** Luhn and Verhoeff checks | `output_scan.py` |

> **Gap:** no transaction scoring and no bot detection. A hijacked mailbox that behaves normally still gets through 96% of the time.

---

## 7. Security Awareness 🔴

*AI-powered security training and awareness.*

| # | Feature | Where |
|---|---|---|
| 1 | **Canary escalations.** Fake escalations that catch analysts who approve everything without looking | `analysts.py` |
| 2 | **Analyst trust scores.** Approval rate, canaries approved, decision speed | `analysts.py` |
| 3 | **Plain-language explanations.** Show an analyst why something was blocked, which teaches as it goes | `counterfactual.py` |

> **Gap:** no training content or user-facing awareness module.

---

## 8. Vulnerability Detection 🔴

*Identify security weaknesses and assist with secure coding.*

| # | Feature | Where |
|---|---|---|
| 1 | **Security CI pipeline.** Bandit, pip-audit, CodeQL, Trivy, fuzzing | `.github/workflows/security.yml` |
| 2 | **Fuzzing + API testing.** 15,000 mutated inputs across 5 parsers, plus Schemathesis. Found and fixed an RCE (CVE-2025-69872), a zip-header ingest block, an invalid tool name and a limit overflow | `eval/fuzz_ingest.py` |

> **Gap:** these harden *our own* code. TrustGate does not scan other people's code.

---

## Extras: features that don't fit a theme

Engineering, deployment and developer experience. They are worth showing as maturity, but they aren't theme features.

**Deployment and self-hosting**

| # | Feature | Where |
|---|---|---|
| 1 | **Hardened Docker Compose stack.** Isolated networks (agent, core, analyst, egress), localhost-only ports, healthchecks, non-root containers | `docker-compose*.yml` |
| 2 | **Helm chart.** NetworkPolicies, read-only root filesystems | `deploy/helm/` |
| 3 | **Published image.** `ghcr.io/ashutosh20git/trustgate` | `.github/workflows/publish.yml` |
| 4 | **One-shot installer.** No clone needed; secrets come from `init_secrets.py` | `deploy-trustgate.sh` |
| 5 | **Multi-stage Dockerfiles** | `docker/` |

**Developer integration**

| # | Feature | Where |
|---|---|---|
| 6 | **Library API.** `@gate.tool(tier=...)` | `trustgate/` |
| 7 | **LangGraph and OpenAI tool-calling adapters** | `trustgate/adapters/` |
| 8 | **Second protected example.** An email assistant protected in a few lines | `examples/email_assistant.py` |
| 9 | **Pluggable SOC connector** (`TRUSTGATE_SOC_CLIENT`) and mock SOC service | `services/mock_soc` |
| 10 | **Ollama LLM option for the re-check**, plus `train_recheck.py` (trains on labelled data and analyst feedback) | `scripts/` |

**Reliability and engineering**

| # | Feature | Where |
|---|---|---|
| 11 | **Fail-closed watchdog + bounded in-flight checks.** Any error, timeout or saturation escalates | `gate.py` |
| 12 | **217 tests,** each mapped to a fix or feature; CI workflow | `tests/`, `.github/workflows/ci.yml` |
| 13 | **Benchmark harness.** AgentDojo, InjecAgent, ASB, BIPIA, OTRF, Enron, phishing_pot, adaptive attacker; results in `eval/results/` | `eval/` |
| 14 | **Model-pin check + placeholder tracking.** Missing keys fail closed | `scripts/check_model_pins.py`, `PLACEHOLDERS.md` |

---

## Pitch order suggestion

1. **AI Security:** the problem and the gate.
2. **AI-Assisted SecOps:** tiers, dashboard, rollback.
3. **Phishing:** the live demo with a poisoned email.
4. **Compliance:** evidence packs and the tamper-evident audit log.
5. **Extras:** "deployable today" with Docker, Helm and the library API.
6. Mention Threat, Fraud, Awareness and Vulnerability work only if asked.
