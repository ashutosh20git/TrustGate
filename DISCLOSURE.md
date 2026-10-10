# Third-party disclosure

The hackathon rules require disclosing every third-party tool, API, dataset and
open-source component. This list is kept current as the build adds each one.

## Python libraries (from pyproject.toml)

| Component | Role |
|---|---|
| Pydantic v2 | Data contracts, validation |
| FastAPI, Uvicorn | Proxy, ingest, detector, mock-SOC services |
| httpx, tenacity | HTTP clients, retries |
| Jinja2 | System prompt and re-check prompt templates |
| SQLModel, SQLAlchemy | Audit store, escalation queue, tool pins |
| psycopg | PostgreSQL driver |
| redis, fakeredis | Rate limiter (fakeredis for tests) |
| diskcache | Threat-intel response cache |
| structlog, OpenTelemetry API | Logging and tracing |
| BeautifulSoup4 | Hidden-HTML extraction in the decoder |
| mail-parser, dkimpy, pyspf, checkdmarc, dnspython, tldextract, python-whois | Email parsing and SPF/DKIM/DMARC |
| PyMuPDF, python-docx, openpyxl, python-pptx | PDF and Office attachment parsing (v2) |
| Microsoft Presidio (analyzer, anonymizer), spaCy (en_core_web_lg) | Output data-leak scanning (v2) |
| Hugging Face transformers, PyTorch | Llama Prompt Guard 2 (detector) |
| LLM Guard (Protect AI) | Input and output scanners (detector signals, scanner fallback) |
| xgboost, scikit-learn | Optional facts-only re-check classifier |
| Model Context Protocol SDK (`mcp`) | MCP gateway and the mock-SOC MCP server |
| LangGraph, langchain-core | SOC agent graph and tool adapter |
| LiteLLM | Model-agnostic LLM calls (agent, attacker) |
| Streamlit, Plotly, pandas, numpy | Dashboard and metrics |
| pytest | Tests |

## External services / APIs

| Service | Role | Notes |
|---|---|---|
| Anthropic / OpenAI / Google Gemini | Agent and adaptive-attacker models (via LiteLLM) | Keys required |
| Ollama + Qwen/Llama | Facts-only re-check (local) | No data leaves the machine |
| Hugging Face Hub | Prompt Guard 2 weights | Gated model; access request required |
| VirusTotal, AbuseIPDB, AlienVault OTX, URLhaus (abuse.ch) | Threat-intel enrichment → typed facts | Scores and enums only |
| Open Policy Agent | Policy engine (Rego) | Binary / sidecar |
| Lakera Guard | Optional detector baseline (config B) | Optional |
| Splunk HEC / Wazuh | Optional SIEM export | Optional |

## Datasets

| Dataset | Role | Status |
|---|---|---|
| CIC-IDS2017, UNSW-NB15, Splunk BOTS, phishing corpora, Enron | Realistic alerts | Not bundled; a synthetic generator (`eval/generate_alerts.py`) stands in until a real loader is added |

## Infrastructure

Docker, Docker Compose, GitHub Actions, Git/GitHub.

## Reused design (written fresh)

The design builds on published out-of-band defences (CaMeL, Progent, FORGE) and
the SOC-specific research cited in the dossier. No third-party defence code is
reused; the TrustGate engine is original work for this hackathon. The earlier
email-interception-proxy project contributed the proxy pattern as background
experience only.
