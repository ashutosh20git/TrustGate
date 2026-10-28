# TrustGate v2

**A deterministic action gate for AI SOC agents.** TrustGate sits between an AI agent and its tools and only lets a security-reducing action through when evidence the attacker cannot write supports it.

> "Untrusted text can raise suspicion but never lower it. TrustGate makes every security-reducing action prove itself on evidence the attacker can't write."

Mitigata CyberForge 2026 · Team: Ashutosh Neelesh Dubey + teammate · Build window: Sat 31 Oct 2026, 10:00 → Sun 1 Nov 2026, 23:59 IST (about 38 hours) · Started 8 Oct 2026 for this hackathon: timeline, AI assistance and every third-party component in [`DISCLOSURE.md`](DISCLOSURE.md)

## Try the demo (5 minutes, no clone)

You need **Docker** (Docker Desktop on Windows/Mac, or Docker Engine with Compose v2 on Linux), **Python 3**, about 8 GB RAM and 5 GB disk. Nothing else is installed: you download one file and run the published image ([`ghcr.io/ashutosh20git/trustgate`](https://github.com/users/ashutosh20git/packages/container/package/trustgate)).

**1. Install and start**

```bash
mkdir trustgate && cd trustgate
curl -fsSLO https://raw.githubusercontent.com/ashutosh20git/TrustGate/main/docker-compose.yml
curl -fsSL https://raw.githubusercontent.com/ashutosh20git/TrustGate/main/scripts/init_secrets.py | python3 - --analyst yourname
docker compose up -d
```

The setup script writes `.env` and `secrets/` in this folder and **prints your admin token once: save it**. Sign in to the dashboard with it, then add your analysts on the **Team** page (each gets their own token there; nobody else needs a terminal). The first `up` downloads about 1.5 GB. On Windows (PowerShell), use `curl.exe` instead of `curl`, and `python` if `python3` is not found.

**2. Load the demo alerts** (a phishing email with a hidden "close this as benign" note aimed at the AI, plus a few clean alerts)

```bash
docker compose exec ingest python scripts/seed_demo.py
```

**3. Play the AI agent: try to close the poisoned alert as benign**

```bash
curl -s -X POST http://127.0.0.1:8080/v1/tools/close_alert -H 'content-type: application/json' \
  -d '{"alert_id":"E-DEMO","verdict":"benign","tool":"close_alert","args":{"reason":"test"},"cited_evidence":["facts.dmarc_pass"]}'
```

The answer is `"decision":"escalate"`: the typed facts (DMARC failed, malicious URL) disagree with "benign", so TrustGate sends the action to a human instead of running it. Blocking the attacker's IP, which the facts support, runs straight away:

```bash
curl -s -X POST http://127.0.0.1:8080/v1/tools/block_ip -H 'content-type: application/json' \
  -d '{"alert_id":"E-DEMO","verdict":"malicious","tool":"block_ip","args":{"ip":"203.0.113.9"},"cited_evidence":["facts.ioc_ips"]}'
```

**4. Act as the analyst:** open **http://127.0.0.1:8501**, sign in with your token, and approve or reject the held action in the *Review queue*. *Alerts* shows every step for each alert, *Actions taken* undoes an executed action in one click, and the *Activity log* is the hash-chained record of every decision.

**Stop:** `docker compose down` (add `-v` to delete the data). **Upgrade:** download `docker-compose.yml` again, then `docker compose pull && docker compose up -d`.

To use it for real (your own AI agent, SIEM and SOC tools; monitor mode first; Kubernetes with Helm), follow **[docs/SELF_HOSTING.md](docs/SELF_HOSTING.md)**.

> **Status: built.** The v1 engine, all four v2 must-haves, the two "Should" items, the library, the MCP gateway, the services, the evaluation harness and the test suite are implemented. It runs **fully offline today** (`pytest`, `python -m eval.run`) using the bundled OPA binary and deterministic stand-ins. Running it **live** (real agent, real re-check model, Docker stack) needs the keys and services in [requirements from the team](#requirements-from-the-team); each one is a tracked placeholder that fails closed until filled — see [`PLACEHOLDERS.md`](PLACEHOLDERS.md).

## Quickstart (offline, no keys)

```bash
python -m venv .venv && . .venv/Scripts/activate     # Windows; use bin/activate on POSIX
pip install -e ".[ingest,attachments,output-scan,recheck-xgb,mcp,server,agent,eval,dev]"
python -m spacy download en_core_web_lg
# OPA binary (needed for the gate): downloaded to .tools/ during the build, or:
#   curl -L -o .tools/opa.exe https://github.com/open-policy-agent/opa/releases/latest/download/opa_windows_amd64.exe

pytest                                   # 217 tests, each mapped to a silent-failure fix or feature
python -m eval.run --configs A,B,C,D     # attack suite A-D + the gate-only-catches headline
python scripts/seed_demo.py --local      # show the poisoned email being split and flagged
```

---

## Contents

- [Try the demo](#try-the-demo-5-minutes-no-clone)
- [Positioning](#positioning-the-action-layer-detectors-lack)
- [What is in v2](#what-is-in-v2)
- [Architecture](#architecture)
- [Packaging](#packaging)
- [Quickstart (offline)](#quickstart-offline-no-keys)
- [Requirements from the team](#requirements-from-the-team)
- [Configuration (.env)](#configuration-env)
- [Repository layout](#repository-layout)
- [Running it live](#running-it-live-docker-stack)
- [Evaluation v2](#evaluation-v2)
- [Build plan and cut order](#build-plan-and-cut-order)
- [What we deliberately do not build](#what-we-deliberately-do-not-build)
- [Honest limits](#honest-limits)
- [Disclosure](#disclosure)
- [Sources](#sources)

---

## Positioning: the action layer detectors lack

Detectors ask whether text looks malicious. TrustGate asks whether an action is justified by evidence the attacker cannot write. The two stack: a detector score is one input to the gate, never the boundary.

| | Text detectors (Lakera Guard, Model Armor, Prompt Guard 2) | TrustGate |
|---|---|---|
| What it checks | Text going in and out of the model | Each tool call, and where its justification came from |
| How it fails | Adaptive rephrasing: 12 published defences were bypassed, most at over 90% | Attacks that stay inside authorised actions; a compromised account whose facts look clean |
| Where it is stronger | Breadth (PII, toxicity, URLs), 100+ languages, under 50 ms claimed, 80M+ attack prompts | Deterministic decisions, SOC-aware policy, every block explained with the text that caused it |
| Role in TrustGate | One input signal (the IOC detector) | The security boundary |

Two attacks a detector can miss and the gate still stops:

- **Fake trusted data.** Spoofed metadata or fake tool-call blocks contain no instruction-like words. Llama Prompt Guard 2 caught none of 108 such payloads in the Agent Data Injection study.
- **Persuasion without commands.** An email that simply argues it is harmless looks clean to a classifier. The facts-only re-check still disagrees with a "benign" verdict when DMARC fails or the sandbox flags the attachment.

---

## What is in v2

### The v1 engine (unchanged)

1. **Evidence splitter.** Deterministic parsers turn each alert into typed facts (enums, numbers, booleans) and quarantined free text. Anything unlabelled counts as untrusted.
2. **Action tiers.** A static map: T0 always allowed, T1 security-reducing, T2 disruptive, T3 outbound. No model writes policy at runtime.
3. **Facts-only re-check.** Before any T1 action, the verdict is recomputed from typed facts alone. Disagreement means the attacker's text tipped the decision, so the action escalates.
4. **Injection-as-IOC.** Text aimed at an AI raises severity and is tagged "AI-evasion attempt". It is a signal, not the boundary.
5. **Safe output and audit.** Schema-constrained verdicts that must cite evidence IDs, quarantined attacker text in the UI, and an audit record for every decision.
6. **Fail-closed watchdog.** Any error or timeout blocks T1–T3 actions and escalates them.

The 24 silent-failure fixes from the project dossier (section 11) carry over unchanged. v2.1 to v2.3 add seventeen more, found in TrustGate's own code ([below](#v21-silent-failures-fixed-in-trustgate-itself)).

| Tier | Tools | Checks before the action runs |
|---|---|---|
| T0 | `get_alert`, `query_logs`, `lookup_ioc`, `add_note`, `escalate`, `raise_severity`, `enrich` | Rate limit; floods become an IOC |
| T1 | `close_alert`, `downgrade_severity`, `whitelist_indicator`, `suppress_rule` | Facts-only re-check agrees, cites typed facts, evidence floor met (core facts known, no failed lookup, a fact the attacker cannot buy), bounded expiry for suppressions and allowlist entries, per-sender campaign limit, OPA allows |
| T2 | `block_ip`, `isolate_host`, `disable_account` | Target is in the typed facts *and* has evidence of its own (malicious IP; endpoint/auth alert showing compromise), not a critical asset, rate limit |
| T3 | `send_email`, `post_webhook` | Recipient or URL on the allowlist, no raw evidence, output scan, no secret from the alert even transformed or split across messages |

### v2.1: silent failures fixed in TrustGate itself

Each was a way for an attack to get through, or for the gate to stop working, without anything flagging it. Tests: `tests/test_silent_failures_v21.py`.

| # | Silent failure | Fix | Where |
|---|---|---|---|
| 1 | An attacker who owns a domain passes SPF/DKIM/DMARC, buys an aged domain and links to a clean file-sharing site; the facts-only re-check says benign and a T1 close runs | **Attacker-cost evidence floor.** For email, a T1 action also needs a fact a fresh campaign cannot buy: the sender has delivered mail before (`facts.sender_prior_messages >= 3`, from MTA/SIEM history) | `trustgate/evidence_floor.py`, `packs/floor.json`, `packs/floor.rego` |
| 2 | A failed threat-intel lookup (429, outage, rejected key) was swallowed; facts stayed "unknown" and only the re-check prompt stood between that and "benign" | Failed lookups are recorded (`facts.enrichment_failed`); T1 needs no failed lookup and its core facts known per source, enforced in code and in Rego | `trustgate/ingest/enrich.py`, `trustgate/evidence_floor.py` |
| 3 | An analyst approval ran the original arguments with no re-check and no time limit | Approvals are re-checked when used: expiry (`TRUSTGATE_ESCALATION_TTL_S`, default 4 h), tool tier and MCP pin unchanged, a second, different analyst for T2/T3, and T3 payloads re-scanned (floor-blocked data never leaves; redactions apply) | `Gate.resolve_escalation` |
| 4 | MCP tool *results* reached the agent unlabelled and unscanned | The gateway wraps every text result in a random delimiter as untrusted data and scans it; a hit warns the agent, audits `mcp_output` and tags the alert as an AI-evasion attempt, which blocks T1 on it | `trustgate/mcp/gateway.py` |
| 5 | A pinned MCP server could change what it returns while keeping its description | The first successful response sets a baseline shape; new content types or structured keys withhold the response and disable the tool until re-pinned | `trustgate/mcp/pinning.py` |
| 6 | Timed-out checks kept running and could fill the worker pool, after which every decision waited out its own timeout | Bounded in-flight checks: a saturated gate fails closed at once ("GateSaturated"); `health()` and `/healthz` report in-flight and abandoned checks | `Gate._run_with_watchdog` |
| 7 | `suppress_rule` and `whitelist_indicator` change every future alert, justified by one alert's facts | They need `ttl_hours` in (0, 24]; the mock SOC records `expires_at`. Floor rule: a persistent T1 change needs a bounded expiry | `packs/*.json` `expiring_tools`, `Gate._expiry_scope` |
| 8 | Rate limits were per tool, so a campaign of individually clean-looking emails was judged one at a time | T1 actions are also limited per sender domain (10 per hour by default). Shared mail providers (gmail.com, outlook.com, ...) are exempt; fresh senders there are caught per address by fix 1 | `packs/*.json` `campaign_rate_limits` |
| 9 | Notes the agent wrote after reading manipulated evidence were stored as plain text | Agent-written notes on a flagged alert are stored with an untrusted-provenance prefix naming the flagged evidence | `Gate._t0` |
| 10 | Monitor mode logged "would block" but gave no way to tell when enforcing was safe | Per-tool rollout report: decisions, would-block rate, fail-closed count, top reasons, ready flag (`GET /v1/rollout`, dashboard Insights page) | `Store.rollout_report` |

### v2.2: three more, found while checking the v2.1 fixes

Tests: `tests/test_silent_failures_v22.py`.

| # | Silent failure | Fix | Where |
|---|---|---|---|
| 11 | The approve and re-pin endpoints had no authentication, and analyst names were request text. The proxy shares agent-net with the agent and is published on 8080, so a hijacked agent could approve its own escalation with two made-up names, defeating fix 3 | Approvals, rejections and re-pins need an analyst bearer token; the identity comes from the token (`Authorization`, plus `X-Second-Analyst-Token` for T2/T3). The proxy holds only SHA-256 hashes (Docker secret `analyst_tokens`, from `scripts/init_secrets.py`); with none configured, approvals are refused | `trustgate/analysts.py`, `services/proxy/main.py` |
| 12 | A T1 action only had to cite some `facts.*` name, even one unrelated to "benign" such as `facts.ioc_ips` | At least one cited typed fact must meet a `benign_support` condition (DMARC pass, clean URL or sandbox, low abuse score, known sender, ...), in code and in the Rego floor | `trustgate/evidence_floor.py`, `packs/floor.json`, `packs/floor.rego` |
| 13 | If an approved action's tool raised, the escalation stayed open, nothing was audited and the proxy returned a bare 500 | The escalation is closed as `failed` (the tool may have partly run, so no silent retry), an `execution_failed` audit record is written, and the proxy returns 502 with the error type only | `Gate.resolve_escalation` |

### v2.3: what leaves the system

Tests: `tests/test_silent_failures_v23.py`.

| # | Silent failure | Fix | Where |
|---|---|---|---|
| 14 | Outbound checks ran on the raw text. Zero-width characters or base64 let an agent send evidence or an API key to an allowlisted recipient unseen | Outbound text is checked as decoded (the same normaliser and decoder as ingest). A quote of evidence anywhere in the decoded text escalates; a secret or identifier found only after decoding escalates too, since encoded data cannot be redacted in place. Applies to T3 decisions and to analyst approvals | `trustgate/value_match.py`, `Gate._outbound_scan` |
| 15 | The evidence check sampled a 40-character window every 20 characters, so a verbatim quote of up to 58 characters could slip between samples; inserted punctuation also hid a quote | Every 40-letter-and-digit window of the evidence is checked, ignoring punctuation and spacing. Payloads over the 200,000-character scan limit escalate instead of being partly scanned | `trustgate/value_match.py`, `Gate._t3` |
| 16 | The proxy returned the gate's full decision (reasons, re-check verdict, tainted spans) to tool callers, and the escalation queue, audit trail, alerts and metrics were readable without a token from agent-net | Tool callers get only the outcome (`decision`, `tier`, `mode`, `escalation_id`). The analyst views need an analyst token; the dashboard asks for one at sign-in and keeps it in an httpOnly cookie | `services/proxy/main.py` |
| 17 | The LLM Guard fallback scanner only redacted; it never named an entity, so floor-blocked items (card numbers, national IDs, keys) could never be blocked when it was in use | A regex pass names secrets and floor-blocked identifiers (with Luhn and Verhoeff checksums for cards and Aadhaar) so the floor blocks them | `trustgate/output_scan.py` |

### What v2 adds

| Feature | Gap it closes | How (libraries) | Effort (h) | Owner | Priority |
|---|---|---|---|---|---|
| Monitor-only mode | No gradual rollout; Model Armor has an inspect-only mode | Config flag: the gate logs "would block" decisions without blocking | 2 | B | **Must** |
| MCP tool pinning + description scan | No supply-chain checks (tool poisoning, rug pulls, shadowing) | SHA-256 of each tool description at registration (`hashlib`); descriptions scanned by the IOC detector; a changed hash disables the tool | 3 | A | **Must** |
| Output data-leak scanning | No output scanning; Lakera and Model Armor redact sensitive data | Microsoft Presidio analyzer + anonymizer on agent text and T3 payloads (LLM Guard output scanners as fallback) | 3 | B | **Must** |
| PDF and Office attachments | Text only; Model Armor screens PDF, Word, Excel, PowerPoint | PyMuPDF, python-docx, openpyxl, python-pptx → evidence items through the same splitter | 3 | A | **Must** |
| Per-app policy packs | One policy; Model Armor has per-app templates and floor settings | One OPA data document per app; SOC pack + one generic pack; shared floor rules | 3 | B | Should |
| Broader detector signals | Narrow threat coverage | LLM Guard input scanners for secrets, toxicity, URLs, as signals only | 2 | B | Should |
| Hindi and Hinglish payloads | Languages untested | 20+ payloads in the attack suite; a multilingual classifier if time allows | 2 | A | Should |
| SIEM export | No SIEM feed | JSON-lines audit stream to Wazuh or Splunk HTTP Event Collector | 1 | B | Could |
| Lakera as a baseline | Comparison credibility | Add as a configuration if API access is available | 2 | A | Could |
| Image OCR | Images unscreened | Tesseract via pytesseract → evidence items, plus QR decoding (OpenCV) | 3 | A | **Built** (Part 2) |

Owners: **A** = agent and evaluation, **B** = gate and UI.

---

## Architecture

Attachments and MCP tool descriptions enter through the same trust labels as alert text. Monitor-only mode and policy packs change how the gate is deployed, not what it decides; the output scanner checks what leaves. New v2 parts are highlighted.

```mermaid
flowchart TB
    alerts["Alerts and emails<br/>SIEM alerts · phishing emails"]
    attach["PDF and Office attachments<br/>PyMuPDF · python-docx · openpyxl · python-pptx"]:::new
    mcpdesc["MCP tool descriptions<br/>from connected MCP servers"]

    splitter["Evidence splitter<br/>typed facts (trusted) · quarantined text (untrusted)"]
    pinning["Tool pinning + scan<br/>SHA-256 pins · description scan"]:::new
    detector["Detector signals<br/>Prompt Guard 2 · LLM Guard · regex → severity only"]
    agent["SOC agent (LLM)<br/>LangGraph · LiteLLM · proposes verdict + action"]

    subgraph gate["TrustGate gate: deterministic code"]
        direction LR
        tiers["Tiers T0–T3<br/>static tool map"] --> recheck["Facts re-check<br/>typed facts only"]
        recheck --> vmatch["Value-match<br/>T2 and T3 targets"]
        vmatch --> packs["Policy packs<br/>OPA · SOC + generic"]:::new
        monitor["Monitor-only mode<br/>logs would-block decisions"]:::new
        watchdog["Fail-closed watchdog<br/>any error or timeout escalates"]
    end

    outscan["Output scanner<br/>Presidio on agent text and outbound payloads"]:::new
    execute["Execute<br/>allowed · mock SOC tools"]
    escalate["Escalate<br/>analyst queue with spans"]
    audit["Audit + SIEM export<br/>SQLModel · JSON lines"]

    alerts --> splitter
    attach --> splitter
    mcpdesc --> pinning
    splitter --> detector --> agent
    agent -- "proposed action" --> gate
    pinning -- "pinned tools only" --> gate
    gate --> outscan
    outscan --> execute
    outscan --> escalate
    outscan --> audit

    classDef new fill:#e3ecfa,stroke:#2f6fd6,stroke-width:2px;
```

### One request, ten steps

| Step | What happens | Tech |
|---|---|---|
| 1. Alert in | Raw alert posted to the ingest API | FastAPI `POST /v1/alerts` |
| 2. Decode | NFKC, zero-width strip, base64/URL decode, hidden-HTML extraction, length caps | `unicodedata`, `base64`, `urllib.parse`, BeautifulSoup4 |
| 3. Parse | Email auth results, domain facts, attachments | mail-parser, dkimpy, pyspf, checkdmarc, tldextract, python-whois, PyMuPDF, python-docx, openpyxl, python-pptx |
| 4. Enrich | Threat-intel scores and enums only, cached | httpx, tenacity, SQLite (JSON only) |
| 5. Split + label | Typed facts vs quarantined text with random per-request delimiters | Pydantic v2, `secrets.token_hex` |
| 6. IOC scan | Whole assembled text, including stitched fragments | Prompt Guard 2, LLM Guard, regex |
| 7. Agent proposes | Verdict, tool, args, cited evidence IDs, rationale (JSON) | LangGraph, LiteLLM |
| 8. Tier + checks | Re-check, value-match, MCP pin check | Ollama (Qwen/Llama, JSON mode) |
| 9. Policy | Per-app pack plus floor rules; rate limit | OPA (Rego), Redis |
| 10. Allow / escalate | Output scan, execute or queue, audit | Presidio, mock SOC, SQLModel |

---

## Part 2: gaps the big vendors leave open

Built on top of the gate. Tests: `tests/test_part2_features.py`, `packs/policy_test.rego`.

| Gap | What TrustGate does | Where |
|---|---|---|
| **No undo for agent actions** | Every executed T1/T2 action is ledgered with its reverse (reopen, unblock, release, re-enable, remove from allowlist). An analyst reverts it in one click; when a later signal shows the alert was manipulated (an injection in a tool result), its security-reducing actions are rolled back automatically. Reverse actions are never agent tools | `Gate.revert`, `Gate.revert_alert`, `GET /v1/actions`, `POST /v1/actions/{id}/revert` |
| **Single-step judgement** | Sequence policy: one security-reducing action per alert runs automatically; a chain (whitelist, then close, then suppress) needs a human. Enforced in code and in the Rego floor over the action ledger | `packs/floor.json` `sequence`, `packs/floor.rego` |
| **Rubber-stamped escalations** | Analyst trust scores: approval rate, canaries approved, median decision time; flags with reasons for review | `Store.analyst_scores`, `GET /v1/analysts`, dashboard Insights page |
| **No "why not"** | Counterfactual explanations: the smallest change in typed facts that would let the action run ("would allow if facts.dmarc_pass were True"), and what never runs automatically. Canaries are explained like any item | `trustgate/counterfactual.py`, `GET /v1/escalations/{id}/explain` |
| **Provenance lost between agents** | Outbound text from a manipulated alert carries a signed provenance stamp; a receiving TrustGate turns it into an IOC (and an AI-evasion tag). Stamps can only raise suspicion; with `TRUSTGATE_PROVENANCE_KEY` shared, signatures are checked | `trustgate/provenance.py`, `Splitter._upstream_provenance` |
| **Policies not tested against attacks** | Rego unit tests for every floor and pack rule (`opa test packs/`), and the CI eval guard now fails if attack success rises for any attack class or language, not only overall | `packs/policy_test.rego`, `scripts/ci_eval_guard.py` |
| **Indian languages unmeasured** | Tamil, Bengali, Telugu and Marathi payloads beside Hindi and Hinglish, with per-language results (offline simulator: config B passes all 20 new ones, config C stops all 20). Translations are the team's own, not reviewed by native speakers | `eval/payloads.py`, `per_language` in `eval/results/summary.json` |
| **Compliance evidence** | Evidence packs from the hash-chained audit trail for CERT-In (6-hour reporting, 180-day logs), the DPDP Act 2023 (s.8(5), s.8(6)), ISO/IEC 27001:2022 (A.5.24-5.28, A.8.15-8.16) and NIST SP 800-53 AU (AU-2 to AU-12, checked against the SIEM export). Evidence for a review, not a compliance determination | `trustgate/compliance.py`, `GET /v1/compliance/{framework}`, `scripts/compliance_report.py` |
| **Quishing and text in images** | QR codes in attached images and in PDF pages are decoded (OpenCV) into untrusted evidence, their links go to URL reputation, and `facts.attachment_has_qr` is set; image text is read with Tesseract OCR and scanned like any evidence | `trustgate/ingest/attachments.py` |

## v2.4: the stated limits, closed or narrowed

Tests: `tests/test_limits_v24.py`.

| Limit | Now | Where |
|---|---|---|
| Hex, ROT13 and paraphrased leaks | Hex (plain, spaced, `\x` escapes) and ROT13 are decoded at ingest and on outbound text; secrets hidden in ROT13 are caught by pattern. Light paraphrase (most of an evidence item's distinctive words reappearing, in any order) escalates. **Still open:** a full rewrite in other words needs a semantic model | `trustgate/ingest/decode.py`, `value_match.restated_evidence_in` |
| An MCP tool's changed response caught only after it ran | The response is still withheld and the tool disabled, and now the action that call performed is rolled back. **Still open:** the change is seen only after the call, by nature of a response | `trustgate/mcp/gateway.py` |
| A campaign spread across sender domains | T1 actions are also counted per link domain, per attachment hash and per near-duplicate body (MinHash bands; bodies differing in names and amounts share a key). Shared providers are exempt. **Still open:** a campaign that varies sender, link, attachment and wording at once | `trustgate/ingest/campaign.py`, `Gate._campaign_keys` |
| A compromised account with real history | A known sender behaving unusually (Reply-To on another domain, parsed from headers; first link, first attachment or new sending IP, from MTA/SIEM history) no longer counts as costly support, and history counts only when those signals are supplied at all. **Still open:** a hijacked mailbox that behaves exactly as usual | `evidence_floor.py`, `packs/floor.json` `costly_negated_by` |
| Standalone gateway rollback | Reverse actions run on the upstream MCP server (never listed to or callable by the agent); the mock SOC MCP server exposes them | `Gateway._undo_executor`, `services/mock_soc/mcp_server.py` |

Also fixed: the mock SOC MCP server's `whitelist_indicator` and `suppress_rule` lacked the `ttl_hours` argument the gate requires, so through the gateway they could never pass.

## Packaging

One engine ships in three forms. The hackathon builds the first two and pitches the third.

| Form | What it is | Who uses it | Hackathon scope |
|---|---|---|---|
| `trustgate-core` (pip library) | The engine: trust labels, tiers, re-check hook, policy client, audit | Developers wrapping their own agent's tools | Built: all engine code lives here |
| Adapters | LangGraph, plus OpenAI and Anthropic tool calling | Developers | LangGraph + one tool-calling adapter |
| MCP gateway (Docker) | A proxy in front of any MCP server, with tool pinning | Security teams; no change to the agent's code | Built: used in the demo |
| Cloud control plane | Policy packs, escalation queue, dashboards, multi-tenant accounts | Enterprises and MSSPs such as Mitigata | Roadmap slide only |

The library call developers will write:

```python
from trustgate import Gate, Tier

gate = Gate(policy="packs/soc.rego", recheck=facts_only_recheck,
            mode="enforce")  # or "monitor"

@gate.tool(tier=Tier.SECURITY_REDUCING)        # T1
def close_alert(alert_id: str, reason: str): ...

@gate.tool(tier=Tier.DISRUPTIVE, target="ip")  # T2
def block_ip(ip: str): ...
```

Demo add-on: after the SOC demo, protect a second agent (a simple email assistant) in three lines with the generic pack, to show the engine generalises.

---

## Requirements from the team

The code is built. These are the resources it cannot provide itself; each is a
tracked placeholder (`bd list -l placeholder`) that fails closed until filled.
Full detail and wiring: [`PLACEHOLDERS.md`](PLACEHOLDERS.md).

### 1. Keys and accounts

| Requirement | Used for | Until filled | Issue |
|---|---|---|---|
| [ ] LLM API key + pinned agent & attacker models | SOC agent and adaptive attacker via LiteLLM | Offline susceptible-agent simulator stands in | `tg-ej5` |
| [ ] Hugging Face token + Prompt Guard 2 licence | Prompt Guard 2 detector signal | Detector runs on regex + stitch only | `tg-xeq` |
| [ ] Ollama + a small re-check model | Facts-only re-check (default backend) | **T1 actions fail closed** (or train XGBoost) | `tg-8wu` |
| [ ] VirusTotal / AbuseIPDB / OTX / URLhaus keys | Threat-intel → typed facts | Lookup skipped; fact stays unknown | `tg-8t2` |
| [x] GitHub repository | CI, versioned policies | Done: [ashutosh20git/TrustGate](https://github.com/ashutosh20git/TrustGate) | — |

The agent and the attacker must be different models (dossier 13.3). The attack
suite is sized with `--attempts` and `--clean`; set these to fit your LLM budget.

### 2. Machine setup

Measured on the build laptop: 11.7 GB RAM, 12 logical CPUs, NVIDIA GeForce RTX 2050 (4 GB VRAM), 160 GB free on C:, WSL with the `docker-desktop` distribution present.

| Requirement | Why | Notes |
|---|---|---|
| [ ] Start Docker Desktop and set Resources → Memory to about 6 GB | The whole stack runs under Docker Compose | Installed, but the engine was not running when checked |
| [ ] Install Ollama natively on Windows (not in Docker) | Facts-only re-check model on the GPU | Keeps the model off Docker's RAM budget |
| [ ] `ollama pull qwen2.5:3b` (or another small model the team picks) | Re-check model | A 3B model fits the RTX 2050's 4 GB VRAM |
| [ ] Install Python 3.11 | Running tests outside Docker | Containers use `python:3.11-slim`; the ML stack (LLM Guard in particular) is safest on 3.11. Local Python is 3.13 |
| [ ] Close heavy apps while the stack runs | RAM headroom | Prompt Guard 2, LLM Guard, the Presidio spaCy model, Postgres, Redis and the dashboard together are tight on 11.7 GB |
| [x] Node.js 22 | promptfoo regression suite | Already installed |
| [x] Git | Version control | Already installed |
| [ ] Tesseract OCR | Text in image attachments (built; flagged `ocr_unavailable` without it) | `apt install tesseract-ocr` / Windows installer; CI installs it |

### 3. Datasets

| Dataset | Role | Notes |
|---|---|---|
| [ ] CIC-IDS2017 | Network alerts | Requires a registration form on the University of New Brunswick site |
| [ ] UNSW-NB15 | Network alerts | Multi-GB |
| [ ] Splunk BOTS | Realistic SOC scenarios | |
| [ ] A public phishing corpus | Malicious email alerts | |
| [ ] Enron email dataset | Benign baseline | About 1.7 GB |

The team decides which of these to use and whether a subset is enough.

### 4. Decisions only the team can make

- [ ] **Hackathon rules (most important).** The blueprint allows code preparation before 31 Oct only if the organisers permit it, and the rules prohibit pre-existing solutions. TrustGate is not pre-existing: it was started on 8 Oct 2026 for this hackathon ([timeline](DISCLOSURE.md#project-timeline)). Get Mitigata's written confirmation (pratyasha.m@mitigata.com) that the preparation is allowed before relying on it at the event. Issue `tg-e5d`.
- [ ] **Pinned models** for the agent, the re-check and the adaptive attacker.
- [ ] **Audit store:** SQLite (default) or PostgreSQL (`DATABASE_URL`; Compose uses Postgres). Both work.
- [ ] **Policy-pack values:** replace the example critical assets / allowlists in `packs/*.json` with the real environment's. Issue `tg-981`.
- [ ] **Optional scope.** The two "Should" items (per-app packs, broader detector signals) are built. The Could/Stretch items each need a resource: Lakera key, Splunk HEC / Wazuh, or Tesseract. Issue `tg-0gx`.

What was implemented for each half: **A** (agent, mock SOC, attack suite, metrics) and **B** (ingest/splitter, gate, re-check, detector, MCP pinning, output scanner, dashboard, audit) are both done.

---

## Configuration (.env)

Planned variable names. Copy into `.env` (never commit it); tool credentials live only in the proxy container as Docker secrets.

```dotenv
# LLMs (via LiteLLM)
ANTHROPIC_API_KEY=
OPENAI_API_KEY=
GEMINI_API_KEY=
TRUSTGATE_AGENT_MODEL=        # pinned model ID for the SOC agent
TRUSTGATE_ATTACKER_MODEL=     # must differ from the agent model
TRUSTGATE_RECHECK_MODEL=qwen2.5:3b

# Detector models
HF_TOKEN=

# Threat intelligence (ingest only; responses cached)
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=
OTX_API_KEY=
URLHAUS_AUTH_KEY=

# Gate
TRUSTGATE_MODE=enforce        # enforce | monitor
TRUSTGATE_MAX_INFLIGHT_CHECKS=16
TRUSTGATE_ESCALATION_TTL_S=14400
TRUSTGATE_POLICY=packs/soc.rego
OLLAMA_HOST=http://host.docker.internal:11434
OPA_URL=http://opa:8181
DATABASE_URL=postgresql://trustgate:trustgate@postgres:5432/trustgate
REDIS_URL=redis://redis:6379/0

# Optional
LAKERA_API_KEY=
SPLUNK_HEC_URL=
SPLUNK_HEC_TOKEN=
```

---

## Repository layout

All engine code lives in the `trustgate` library; the services are thin wrappers around it.

```text
TrustGate/
├── docker-compose.yml · docker/Dockerfile · docker/Dockerfile.mcp-gateway
├── .github/workflows/ci.yml
├── pyproject.toml                 # trustgate-core + extras
├── trustgate/                     # the library (trustgate-core)
│   ├── models.py                  # shared Pydantic contracts
│   ├── gate.py                    # Gate, @gate.tool, monitor mode, fail-closed watchdog
│   ├── tiers.py · recheck.py · value_match.py · ratelimit.py · render.py
│   ├── policy_client.py           # OPA client, per-app packs + floor rules
│   ├── store.py                   # SQLModel audit (hash-chained) + JSON-lines/HEC SIEM export
│   ├── output_scan.py             # v2: Presidio analyzer + anonymizer (LLM Guard fallback)
│   ├── ingest/                    # decode, parsers/{email,logs}, enrich, split
│   │   └── attachments.py         # v2: PDF, DOCX, XLSX, PPTX
│   ├── detector/                  # heuristics, stitch, prompt_guard, llm_guard_scan, ensemble
│   ├── mcp/                       # v2: pinning + gateway
│   └── adapters/                  # langgraph, openai_tools
├── services/
│   ├── proxy/ · ingest/ · detector/   # FastAPI services
│   ├── agent/                     # LangGraph + LiteLLM SOC agent, tool stubs → proxy
│   ├── mock_soc/                  # sandbox tools (FastAPI) + MCP server + client
│   └── soc_tools.py               # the tool catalogue bound to the gate
├── dashboard/                     # analyst dashboard: Next.js + shadcn/ui, its own image
├── packs/                         # soc.{rego,json}, generic.{rego,json}, floor.{rego,json}
├── examples/email_assistant.py    # second agent protected in a few lines
├── eval/                          # payloads, inject, build_attachments, generate_alerts, configs, sim, metrics, run
├── scripts/                       # init_secrets, seed_demo, train_recheck, check_model_pins, ci_eval_guard
├── tests/                         # 217 tests, each mapped to a silent-failure fix or feature
├── .tools/opa.exe                 # OPA binary (git-ignored)
├── DISCLOSURE.md · PLACEHOLDERS.md · README.md
```

---

## Running it live (Docker stack)

Offline is the [quickstart](#quickstart-offline-no-keys) above. To run TrustGate in your own network
(Docker Compose on a VM, or the Helm chart on Kubernetes), follow **[docs/SELF_HOSTING.md](docs/SELF_HOSTING.md)**:
setup, connecting your real SOC tools (`TRUSTGATE_SOC_CLIENT`), going live in monitor mode, and operations.

```bash
python3 scripts/init_secrets.py --analyst alice  # standard library only; creates .env (random
                                                 # POSTGRES_PASSWORD) and secrets/; prints alice's admin token once
docker compose up -d            # pulls ghcr.io/ashutosh20git/trustgate; --build to build from this checkout
#   dashboard:  http://127.0.0.1:8501   (paste your token; add analysts on the Team page)
#   proxy:      http://127.0.0.1:8080   (agent tool calls)
#   ingest:     http://127.0.0.1:8081   (SIEM posts alerts with secrets/ingest_token.txt)

docker compose exec ingest python scripts/seed_demo.py   # seed the poisoned email + clean alerts
docker compose --profile tools run --rm agent --alert-id E-DEMO   # triage it through the gate

# Kubernetes:
helm install trustgate deploy/helm/trustgate -n trustgate --create-namespace -f my-values.yaml

# MCP gateway in front of the mock SOC (tool pinning, no agent-code change):
python -m trustgate.mcp.gateway --server-name mock-soc --policy packs/soc.rego \
    -- python -m services.mock_soc.mcp_server
```

The facts-only re-check defaults to the starter XGBoost model baked into the image, so the stack runs without
a GPU. For an LLM re-check, `ollama pull qwen2.5:3b` on the host and set `TRUSTGATE_RECHECK_BACKEND=ollama`.

| Service | Network | Holds |
|---|---|---|
| agent | agent-net | LLM API key only; egress limited to the proxy and the LLM API |
| ingest | core-net + egress-net, port 8081 | Threat-intel API keys; the ingest token (only the SIEM may post alerts) |
| trustgate-proxy | agent-net + analyst-net + core-net, port 8080 | Tool credentials and analyst token hashes (Docker secrets); the only bridge between agent and tools |
| mcp-gateway | agent-net + core-net | Tool pins; proxies MCP servers |
| opa | core-net | Rego policies and pack data |
| detector | core-net + egress-net | Prompt Guard 2 and LLM Guard weights; scores only |
| redis / postgres | core-net | Rate limits, queue, audit |
| mock-soc | core-net | Sandbox state; email goes to a local outbox only |
| dashboard | analyst-net + core-net, port 8501 | Read access to the audit DB |

Published ports bind to `127.0.0.1` unless `TRUSTGATE_BIND_ADDR` says otherwise.

---

## Evaluation v2

**Benchmark results**, what they broke and how it was fixed: [docs/BENCHMARKS.md](docs/BENCHMARKS.md). Round 1: adaptive red-team, AgentDojo, real phishing mail. Round 2: legitimate mail (Enron), account takeover, InjecAgent, ASB, BIPIA, real ATT&CK telemetry (OTRF), fuzzing, Bandit/pip-audit/CodeQL/Trivy, API fuzzing, audit tampering, OWASP LLM + agentic coverage, explanation accuracy.

The headline changes: not only how many attacks TrustGate stops, but **how many got past the detector and were stopped by the gate**. That number is what makes the "use both" pitch credible.

### Configurations (same alerts, same agent model)

| Config | What runs | Why |
|---|---|---|
| A. Undefended | Agent alone | Baseline attack surface |
| B. Detector only | Prompt Guard 2 + LLM Guard (Lakera if API access is available) | Stands in for today's detector products |
| C. TrustGate | Full gate, with the detector as one input | Our system |
| D. TrustGate, monitor mode | Same as C, logging instead of blocking | Shows what would be blocked during a safe rollout |

### Attack sets

The seven v1 classes:

1. Direct override.
2. Persona hijack.
3. Context manipulation.
4. Obfuscation.
5. Context stitching.
6. ADI-style fake metadata.
7. Volume padding.

Plus four new ones:

- **Detector-evasion set:** fake metadata, persuasion with no commands, Hindi and Hinglish payloads.
- **Attachment-borne:** payloads hidden inside PDF and Office files.
- **MCP tool poisoning:** instructions inside a tool description, and a tool whose description changes after install.
- **Exfiltration attempts:** prompts that push secrets or PII into outgoing emails or summaries.

### Metrics

- **Gate-only catches** (the headline): attacks that pass config B but are stopped by C.
- **Attack success:** ASR@1, @10 and @100 per class.
- **Triage accuracy and escalation rate**, always reported together.
- **Data-leak rate:** sensitive values that reach an outbound action or summary.
- **Overhead:** added latency and tokens per decision.
- Carried over from v1: label coverage (target 100%), fail-closed count, canary catch rate.

---

## Build plan and cut order

| Milestone | Hour | Proof |
|---|---|---|
| M1 core loop | 11 | One poisoned email: agent proposes close → proxy escalates with spans |
| M2 suite runs | 23 | The attack suite runs on all configurations |
| M3 numbers | 30 | Numbers on the dashboard |
| M4 demo locked | 35 | Rehearsed; backup video recorded |

Guardrails against scope creep:

- Monitor-only mode is built right after M1; it is two hours and makes every later test safer.
- No other v2 feature starts before M1 is green.
- Every feature is time-boxed; at its box's end it ships as-is or is dropped.
- If M2 slips past hour 25, all Should, Could and Stretch items are cut.

Cut order when time runs short (first to go at the top):

1. Image OCR
2. Lakera as a baseline
3. SIEM export
4. Hindi and Hinglish classifier (keep the payloads)
5. Broader detector signals
6. Per-app policy packs (keep the SOC pack only)
7. **Never cut:** the core loop, monitor-only mode, the detector-only baseline

---

## What we deliberately do not build

| Gap | Why not | What we say instead |
|---|---|---|
| Attack data at Lakera's scale (80M+ prompts) | Years of crowd-sourced data | A focused, labelled SOC suite plus an adaptive attacker |
| 100+ languages | Cannot validate them | We list the languages we actually tested |
| Sub-50 ms at production scale | Prototype hardware and code | We report our measured latency per decision |
| SSO, RBAC, multi-tenancy, certifications | Enterprise work with no demo value | Roadmap slide for the cloud control plane |
| CaMeL-style data-flow tracking inside the agent's plan | Requires rewriting the agent | Value-matching at the tool boundary, stated as a limit |
| Track record and customers | Only time fixes this | The core is open source, so anyone can audit it; pilots after the hackathon |

---

## Honest limits

- TrustGate does not "solve" prompt injection. It claims containment: injections may land, but they cannot cause damage through gated actions.
- A compromised real account can pass every hard check (valid DMARC, clean reputation). The floor now catches one that behaves unusually (v2.4); one that behaves exactly as usual is a detection problem, not injection, and out of scope.
- The facts-only verdict is less accurate than the full-context one, so expect more escalations. The escalation rate is always reported next to accuracy.
- A tool-boundary gate cannot see how the model turned untrusted text into an innocent-looking argument; value-matching on T2 and T3 targets is the mitigation, stated as a limit.
- Never quote a language count, latency or accuracy figure that has not been measured.
- The attacker-cost floor needs sender history (`sender_prior_messages`) from the MTA or SIEM. Without it, every email T1 action escalates; a compromised account with real history still passes it (the detection problem above).

---

## Disclosure

The hackathon rules require disclosing every third-party tool, API, dataset and open-source component. [`DISCLOSURE.md`](DISCLOSURE.md) is the complete list: the project timeline, the AI coding assistant (Claude Code), every library, model, external service and benchmark dataset, and the CI and infrastructure tools. It is kept up to date as each one is added.

---

## Sources

- TrustGate v2: the updated approach (8 Oct 2026)
- TrustGate project dossier and TrustGate implementation blueprint (8 Oct 2026)
- Lakera Guard feature summary (AppSec Santa)
- Introducing mcp-scan (Invariant Labs): tool poisoning, rug pulls, tool shadowing
- Model Armor overview (Google Cloud): DLP, document and image screening, templates, inspect-only mode
- Adaptive Evaluation of Out-of-Band Defenses (arXiv 2606.26479)
- Agent Data Injection Attacks (arXiv 2607.05120)
