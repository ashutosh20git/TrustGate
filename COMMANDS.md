# TrustGate commands

Every command you need, in one place. Run them from the repo root unless a step says otherwise.
Windows: use Git Bash, or swap `python3` for `python`.

## 1. First-time setup (Docker)

```bash
python3 scripts/init_secrets.py    # makes .env + secrets/, prints the ADMIN token ONCE
docker compose up -d --build        # build from this checkout and start everything
docker compose ps                   # proxy and ingest should say (healthy)
```

Save the printed token. Sign in to the dashboard with it (the **token**, not the hash in
`secrets/analyst_tokens.txt`), open **Team**, and add your analysts. Each one gets a token
shown once; send it to them privately. That's the only time anyone needs this script.

## 2. Use it

```bash
docker compose exec ingest python scripts/seed_demo.py          # load the poisoned email + 5 clean alerts
docker compose --profile tools run --rm agent --alert-id E-DEMO # let the AI agent triage an alert through the gate
```

Dashboard: http://127.0.0.1:8501. Proxy API: http://127.0.0.1:8080.

## 3. Day to day

```bash
docker compose logs -f trustgate-proxy      # watch gate decisions
docker compose restart trustgate-proxy      # needed after re-running init_secrets.py (Team page changes need no restart)
docker compose up -d --build dashboard      # rebuild only the dashboard
docker compose down                         # stop everything (data kept)
docker compose down -v                      # stop and DELETE all data
git pull && docker compose up -d --build    # upgrade
```

## 4. Dashboard development (Next.js)

```bash
cd dashboard
npm ci
TRUSTGATE_PROXY_URL=http://127.0.0.1:8080 npm run dev   # http://localhost:3000, needs the proxy running
npm run lint
npm run build && npm start                              # production build
npm audit --omit=dev --audit-level=high
```

## 5. Python development (no Docker)

```bash
python -m venv .venv && . .venv/Scripts/activate        # Windows; .venv/bin/activate on Mac/Linux
pip install -e ".[dev,ingest,attachments,images,output-scan,recheck-xgb,mcp,server,agent,eval]"
python -m spacy download en_core_web_lg

pytest -q                                               # full test suite
pytest tests/test_tool_args.py -q                       # one file
opa test packs/                                         # Rego policy tests (.tools/opa.exe on Windows)
python scripts/seed_demo.py --local                     # split the poisoned email in-process and print it
python -m services.agent --alert-id E-DEMO              # run the agent against a running proxy
```

## 6. Scripts in `scripts/`

| Script | What it does | Example |
|---|---|---|
| `init_secrets.py` | Creates `.env`, the Postgres password and the first admin token(s) | `python3 scripts/init_secrets.py --analyst alice` |
| `seed_demo.py` | Posts the demo phishing email and clean alerts | `python scripts/seed_demo.py -n 10` / `--local` |
| `train_recheck.py` | Trains the XGBoost re-check model | `python scripts/train_recheck.py --data tickets.jsonl --feedback` |
| `compliance_report.py` | Writes an evidence pack from the audit trail | `python scripts/compliance_report.py --framework cert-in --format md > cert-in.md` |
| `check_model_pins.py` | CI check: every model name is pinned | `python scripts/check_model_pins.py` |
| `ci_eval_guard.py` | CI check: attack success did not go up | `python scripts/ci_eval_guard.py` |

Compliance frameworks: `cert-in`, `dpdp`, `iso27001`.

## 7. Evaluation

```bash
python -m eval.run --configs A,B,C,D                 # attack suite A-D, results in eval/results/
python -m eval.run --configs C --attempts 100        # ASR@100 for the gate
python -m eval.recheck_bench                         # how often the re-check wrongly says "benign"
```

## 8. MCP gateway

```bash
python -m trustgate.mcp.gateway --server-name mock-soc --policy packs/soc.rego \
    -- python -m services.mock_soc.mcp_server
```

## 9. Deploy

```bash
bash deploy-trustgate.sh [folder] [analyst]         # one-shot: download compose, make secrets, start (no checkout needed)
helm lint deploy/helm/trustgate
helm install trustgate deploy/helm/trustgate
```

## Troubleshooting

| Problem | Fix |
|---|---|
| Dashboard says the token is wrong | Use the token, not the hash. Admin token regenerated? `docker compose restart trustgate-proxy`. Analyst lost theirs? An admin clicks **New token** on the Team page |
| No Team link in the sidebar | Only admins see it; sign in with the admin token |
| `POSTGRES_PASSWORD` missing | Run `python3 scripts/init_secrets.py` first |
| Port 8501 shows the old Streamlit page | `docker compose up -d --build dashboard` |
| Agent actions time out (fail closed) | The re-check model is slow; give Ollama more memory or use `TRUSTGATE_RECHECK_BACKEND=xgboost` |
