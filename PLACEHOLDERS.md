# Placeholders and what they need

Everything here is a resource the build cannot provide itself (a key, a gated
model, a running service, a dataset, a rules decision). Each one fails **closed**
or runs **degraded** — never silently open — and has a tracking issue in `bd`
(run `bd show <id>` for detail, `bd list -l placeholder` for all of them).

| # | Placeholder | Behaviour until filled | How to fill | Issue |
|---|---|---|---|---|
| 1 | LLM API key + pinned agent/attacker models | `services/agent` and real-agent eval fall back to the offline simulator (`eval/sim.py`); LiteLLM raises `NotConfigured` | Set a provider key, pin `TRUSTGATE_AGENT_MODEL` and a different `TRUSTGATE_ATTACKER_MODEL` | `tg-ej5` |
| 2 | Hugging Face token + Prompt Guard 2 access | Detector runs on regex + stitch only; `prompt_guard_2` logged "unavailable" | Request gated-model access, set `HF_TOKEN` | `tg-xeq` |
| 3 | Ollama + re-check model | **Every T1 action fails closed (escalates)** | Install Ollama, `ollama pull qwen2.5:3b`, set `TRUSTGATE_RECHECK_MODEL` — or train XGBoost (`scripts/train_recheck.py`) and set `TRUSTGATE_RECHECK_BACKEND=xgboost` | `tg-8wu` |
| 4 | Threat-intel API keys | That lookup is skipped; the fact stays `unknown` (never falsely benign) | Set `VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`, `OTX_API_KEY`, `URLHAUS_AUTH_KEY` | `tg-8t2` |
| 5 | Real datasets | Synthetic generator (`eval/generate_alerts.py`) stands in | Add a loader under `eval/datasets/`; CIC-IDS2017 needs UNB registration | `tg-8os` |
| 6 | Docker running + memory | `docker compose up` cannot start the stack | Start Docker Desktop, set memory ~6 GB, keep Ollama native | `tg-lm9` |
| 7 | llm-guard on Python 3.13 | LLM Guard scanners unavailable on the dev machine (fine in containers) | Use Python 3.11 locally, or rely on Presidio + regex (both work on 3.13) | `tg-hwm` |
| 8 | Policy-pack values | Example critical assets / allowlists / entity lists | Replace in `packs/soc.json`, `packs/generic.json` with the real environment's | `tg-981` |
| 9 | Hackathon rules decision | — | Confirm pre-build is allowed with Mitigata | `tg-e5d` |
| 10 | Optional (Lakera, SIEM, OCR) | Off by default; first in the cut order | Lakera key / Splunk HEC / Tesseract as needed | `tg-0gx` |
| 11 | Sender history from the MTA / SIEM | **Every email T1 action escalates** (attacker-cost floor: no fact a fresh campaign cannot buy) | Post `observed.sender_prior_messages` (messages this exact sender delivered before) with each email alert, from mail-gateway logs or a SIEM lookup | — (needs a `bd` issue) |
| 12 | Analyst tokens | **Every approval, rejection and MCP re-pin is refused** (503): no identity, no approval | `python scripts/init_secrets.py --analyst <name>` per analyst; hand each printed token to that analyst only, never to the agent | — (needs a `bd` issue) |

## How "fails closed" is wired

- `trustgate/config.py` defines `NotConfigured`. Reading a missing key/model/service raises it.
- In the gate (`trustgate/gate.py`), `NotConfigured` is caught by the fail-closed watchdog like any other error, so a T1–T3 action **escalates** instead of running.
- `MTA_AUTHSERV_ID` unset → SPF/DKIM/DMARC facts stay `None` (unknown), which the re-check treats as not-benign.
- A missing output-scanner backend makes **T3 fail closed** (no outbound without a leak scan).
- A threat-intel lookup that errors (rate limit, outage, rejected key) sets `facts.enrichment_failed`, and T1 escalates until it succeeds. An unconfigured key only leaves that fact unknown.
- Degraded-but-safe placeholders (detector models, threat intel) only ever *remove* evidence for "benign", so they cannot weaken the gate.

## Offline mode (no keys at all)

The test suite and `python -m eval.run` run fully offline: the OPA binary in
`.tools/`, an in-memory rate limiter, a deterministic facts-only re-check
(`sim_recheck`) and the susceptible-agent simulator. Every such stand-in is
labelled in the eval's `meta` block so results are never mistaken for measured
numbers from a real model.
