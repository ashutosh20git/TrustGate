# Third-party disclosure

The hackathon rules require disclosing every third-party tool, API, dataset and
open-source component. This list is kept current as the build adds each one.

## Project timeline

TrustGate was started for Mitigata CyberForge 2026. No TrustGate code predates it.

| Date (2026) | What happened |
|---|---|
| 8 Oct | Design documents: project dossier, implementation blueprint, "TrustGate v2: the updated approach" |
| 10 Oct | GitHub repository created |
| 10-11 Oct | First code commit (v1 engine and the v2 must-haves), then iterations v2.1 to v2.4 |
| 11 Oct | Packaging: Docker image, Compose stack, Helm chart, image published to GHCR |
| 12 Oct | Benchmark rounds 1 and 2 (datasets below) |
| 13 Oct | Deploy script, CI fixes |

Version numbers count iterations of this project, not earlier releases: v1 and v2 are
revisions of the design, v2.1 to v2.4 are revisions of the code. The full history is
in the public git log. Preparing code before the 31 Oct build window is subject to the
organisers' confirmation (issue `tg-e5d`).

## AI assistance

| Tool | Role |
|---|---|
| Claude Code (Anthropic) | AI coding assistant. Wrote and revised code, tests, benchmarks and documentation at the team's direction. Its commits show `Claude` as the author or carry a `Co-Authored-By: Claude` trailer |

## Python libraries (from pyproject.toml)

| Component | Role |
|---|---|
| Pydantic v2 | Data contracts, validation |
| FastAPI, Uvicorn | Proxy, ingest, detector, mock-SOC services |
| httpx, tenacity | HTTP clients, retries |
| Jinja2 | Declared dependency; no longer imported (prompts are plain strings) |
| SQLModel, SQLAlchemy | Audit store, escalation queue, tool pins |
| psycopg | PostgreSQL driver |
| redis, fakeredis | Rate limiter (fakeredis for tests) |
| structlog, OpenTelemetry API and SDK | Logging and tracing (SDK in tests) |
| BeautifulSoup4 | Hidden-HTML extraction in the decoder |
| mail-parser, dkimpy, pyspf, checkdmarc, dnspython, tldextract, python-whois | Email parsing and SPF/DKIM/DMARC |
| PyMuPDF, python-docx, openpyxl, python-pptx | PDF and Office attachment parsing (v2) |
| Microsoft Presidio (analyzer, anonymizer), spaCy | Output data-leak scanning (v2) |
| Hugging Face transformers, PyTorch | Llama Prompt Guard 2 (detector) |
| LLM Guard (Protect AI) | Input and output scanners (detector signals, scanner fallback) |
| xgboost, scikit-learn | Optional facts-only re-check classifier |
| Model Context Protocol SDK (`mcp`) | MCP gateway and the mock-SOC MCP server |
| LangGraph, langchain-core | SOC agent graph and tool adapter |
| LiteLLM | Model-agnostic LLM calls (agent, attacker) |
| Next.js, React, shadcn/ui, Radix UI, Tailwind CSS, SWR, Recharts, lucide-react, sonner, next-themes | Analyst dashboard |
| OpenCV (opencv-python-headless), Pillow | QR-code decoding and image handling in attachments (Part 2) |
| pytesseract + Tesseract OCR (binary) | Text in image attachments (Part 2) |
| segno | QR codes generated for tests |
| pytest | Tests |
| Schemathesis, Hypothesis | API fuzz tests (`tests/test_api_fuzz.py`) |
| AgentDojo (`agentdojo`) | Benchmark harness, eval only (`bench` extra) |

## Models

| Model | Role | Notes |
|---|---|---|
| Llama Prompt Guard 2 86M (Meta) | Detector signal | Gated on Hugging Face; Llama licence |
| spaCy `en_core_web_lg` | Presidio named-entity recognition | `en_core_web_sm` is a build option |
| A small Qwen or Llama model via Ollama (`qwen2.5:3b` suggested) | Facts-only re-check (local) | Team's choice; optional |
| Agent and attacker LLMs (Anthropic / OpenAI / Google Gemini) | SOC agent, adaptive attacker | Via LiteLLM; keys required |

The starter XGBoost re-check model is our own, trained at build time on synthetic alerts
from `eval/generate_alerts.py`.

## External services / APIs

| Service | Role | Notes |
|---|---|---|
| Anthropic / OpenAI / Google Gemini | Agent and adaptive-attacker models (via LiteLLM) | Keys required |
| Ollama | Runs the facts-only re-check model locally | No data leaves the machine |
| Hugging Face Hub | Prompt Guard 2 weights | Gated model; access request required |
| VirusTotal, AbuseIPDB, AlienVault OTX, URLhaus (abuse.ch) | Threat-intel enrichment → typed facts | Scores and enums only |
| Open Policy Agent | Policy engine (Rego) | Binary / sidecar |
| Lakera Guard | Optional detector baseline (config B) | Optional |
| Splunk HEC / Wazuh | Optional SIEM export | Optional |

## Datasets

None is stored in this repository; each is downloaded when its benchmark runs
([docs/BENCHMARKS.md](docs/BENCHMARKS.md#reproduce)). Only our results are committed
(`eval/results/`).

| Dataset | Role | Source |
|---|---|---|
| Synthetic SOC alerts | Tests, demo, starter re-check model | Our own generator, `eval/generate_alerts.py` |
| AgentDojo v1.2 (ETH Zurich) | Prompt-injection benchmark, 4 suites | `agentdojo` package |
| InjecAgent | Prompt-injection benchmark | github.com/uiuc-kang-lab/InjecAgent |
| ASB (Agent Security Bench) | Prompt-injection benchmark | github.com/agiresearch/ASB |
| BIPIA (Microsoft) | Indirect prompt-injection benchmark (detector) | github.com/microsoft/BIPIA |
| phishing_pot | Real phishing emails with full headers; ingest fuzzing seeds | github.com/rf-peixoto/phishing_pot |
| Enron-Spam | Legitimate business mail (and spam) | github.com/MWiechmann/enron_spam_data |
| OTRF Security-Datasets | Windows telemetry of ATT&CK techniques | github.com/OTRF/Security-Datasets |

Considered but not used: CIC-IDS2017, UNSW-NB15, Splunk BOTS, SpamAssassin, Nazario
phishing, CERT insider threat, LANL auth logs, PhishTank, OpenPhish, Tranco.

## Development, CI and infrastructure

| Tool | Role |
|---|---|
| Git, GitHub, GitHub Actions | Version control and CI |
| Docker, Docker Compose, Docker Buildx, Helm | Packaging and deployment |
| GitHub Container Registry (GHCR) | Hosts the published image |
| Container images: `python:3.11-slim`, `postgres:16-alpine`, `redis:7-alpine`, `openpolicyagent/opa:1.21.1`, `ollama/ollama:0.12.3` | Base image and the Compose / Helm stack |
| Bandit, pip-audit, CodeQL, Trivy | Security scanning in CI |
| Beads (`bd`) with Dolt | Issue tracking |

## Reused design (written fresh)

The design builds on published out-of-band defences (CaMeL, Progent, FORGE) and
the SOC-specific research cited in the dossier. No third-party defence code is
reused; the TrustGate engine is original work for this hackathon. The earlier
email-interception-proxy project contributed the proxy pattern as background
experience only.
