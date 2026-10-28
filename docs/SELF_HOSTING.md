# Self-hosting TrustGate

TrustGate runs inside your own network. Alerts, evidence and decisions never
leave it. There are two supported ways to run it:

| | Docker Compose | Helm (Kubernetes) |
|---|---|---|
| Good for | One VM, a pilot, a small SOC | Production, high availability |
| Proxy replicas | 1 | 2+ (the audit chain is safe across replicas) |
| Database | Bundled Postgres | Bundled Postgres, or your managed one (recommended) |
| Files | `docker-compose.yml` | `deploy/helm/trustgate/` |

## What runs

| Component | Port | Who talks to it |
|---|---|---|
| **proxy** (the gate) | 8080 | Your AI agent (tool calls), analysts (approvals), the dashboard |
| **ingest** | 8081 | Your SIEM or mail gateway (posts alerts, with the ingest token) |
| **dashboard** | 8501 | Analysts (each with their own token) |
| detector | 8082 | ingest only |
| OPA | 8181 | proxy only |
| Postgres, Redis | 5432, 6379 | TrustGate components only |
| mock-soc | 8090 | proxy only. A stand-in for your tools; replace it ([below](#connecting-your-soc-tools)) |

Every call from your agent goes to the proxy, never directly to your tools. The
agent never holds a tool credential.

## Requirements

- **Compose:** a Linux VM with Docker 24+ and Compose v2, 4 vCPU, 8 GB RAM, 30 GB disk.
- **Helm:** Kubernetes 1.27+ with a CNI that enforces NetworkPolicy (Calico, Cilium, ...),
  and a registry your cluster can pull from.
- Outbound HTTPS from ingest, if you use threat-intel lookups (VirusTotal, AbuseIPDB,
  OTX, URLhaus) or DNS-based email authentication. Behind an egress proxy, set
  `HTTPS_PROXY` in `.env` (Compose) or `env:` (Helm).

## Try it in five minutes (no clone)

You need Docker (with Compose v2) and Python 3. Nothing is cloned or installed:
you download one file, and the setup script runs straight from GitHub using only
Python's standard library.

```bash
mkdir trustgate && cd trustgate
curl -fsSLO https://raw.githubusercontent.com/ashutosh20git/TrustGate/main/docker-compose.yml
curl -fsSL https://raw.githubusercontent.com/ashutosh20git/TrustGate/main/scripts/init_secrets.py \
  | python3 - --analyst alice       # writes .env and secrets/ here; prints alice's token once: keep it
docker compose up -d                # pulls the published image (~1.5 GB) and starts everything
docker compose exec ingest python scripts/seed_demo.py   # load a poisoned phishing email + clean alerts

# Play the agent: try to close the poisoned alert as benign. TrustGate escalates it.
curl -s -X POST http://127.0.0.1:8080/v1/tools/close_alert -H 'content-type: application/json' \
  -d '{"alert_id":"E-DEMO","verdict":"benign","tool":"close_alert","args":{"reason":"test"},"cited_evidence":["facts.dmarc_pass"]}'
```

Open http://127.0.0.1:8501, paste alice's token, and approve or reject the
escalation. `docker compose down` stops everything; add `-v` to delete the data.
To upgrade: download `docker-compose.yml` again, then `docker compose pull && docker compose up -d`.

On Windows, run the same commands in PowerShell with `curl.exe` instead of `curl`,
and `python` if `python3` is not on your PATH.

**From a clone** (to change the code or build the image yourself): `git clone`
the repo, run `python3 scripts/init_secrets.py --analyst alice`, then
`docker compose up -d --build`. The `docker-compose.override.yml` in the repo adds
the local build.

## Docker Compose

```bash
git clone https://github.com/ashutosh20git/TrustGate.git && cd TrustGate
python3 scripts/init_secrets.py --analyst alice --analyst bob
#   creates .env (with a random POSTGRES_PASSWORD) and secrets/:
#   mock_soc_token, ingest_token (give it to your SIEM), analyst_tokens (hashes only).
#   alice and bob are admins. Each token is printed once: keep it, never give it to the agent.
#   Admins add the rest of the team in the dashboard (Team page), no script needed.
$EDITOR .env          # TRUSTGATE_MTA_AUTHSERV_ID, threat-intel keys, TRUSTGATE_MODE
docker compose up -d      # pulls the published image; or: up -d --build
docker compose ps     # proxy and ingest report (healthy)
```

Ports bind to `127.0.0.1` by default (`TRUSTGATE_BIND_ADDR`). To reach them from
other machines, put a TLS reverse proxy (nginx, Caddy, Traefik) in front rather
than binding to `0.0.0.0`.

Compose keeps components apart with four networks: the agent can reach only the
proxy; the databases, OPA and your tools sit on an internal network with no
internet; only ingest and the detector get outbound access.

Optional: `TRUSTGATE_EXTRAS=full` adds Prompt Guard 2 and LLM Guard to the image
(torch, several GB; set `HF_TOKEN`). `--profile ollama-in-docker` runs Ollama for
the re-check model in a container.

## Helm

1. **Pick the image.** The chart defaults to the published
   `ghcr.io/ashutosh20git/trustgate:2.4`. Air-gapped, or with your own connectors,
   build and push your own:

   ```bash
   docker build -f docker/Dockerfile -t registry.corp.example/trustgate:2.4 .
   docker push registry.corp.example/trustgate:2.4
   ```

2. **Generate secrets** with `python scripts/init_secrets.py --analyst alice`, then
   write a values file. Keep it out of git, or use `secrets.existingSecret` with your
   secret manager (keys: `ingest_token`, `analyst_tokens`, `mock_soc_token`,
   `provenance_key`):

   ```yaml
   image: {repository: registry.corp.example/trustgate, tag: "2.4"}
   gate: {mode: monitor, mtaAuthservId: mx.corp.example}
   postgresql: {enabled: false, externalUrl: "postgresql+psycopg://tg:...@db.corp:5432/trustgate"}
   secrets:
     ingestToken: "<secrets/ingest_token.txt>"
     analystTokens: |
       alice:<hash from secrets/analyst_tokens.txt>
     mockSocToken: "<secrets/mock_soc_token.txt>"
     env: {VIRUSTOTAL_API_KEY: "..."}
   networkPolicy:
     proxyFrom: [{namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: soc-agent}}}]
   ingress: {enabled: true, className: nginx, dashboardHost: trustgate.corp.example}
   ```

3. **Install:**

   ```bash
   helm install trustgate deploy/helm/trustgate -n trustgate --create-namespace -f my-values.yaml
   ```

What the chart does for you:

- Every TrustGate container runs as a non-root user with a read-only root
  filesystem and all Linux capabilities dropped.
- NetworkPolicies let only the components that need a backend reach it: Postgres,
  Redis, OPA, the detector and the SOC tools are closed to everything else.
  `proxyFrom` and `ingestFrom` limit who can call the two front doors.
- OPA loads the policy packs from the same image as the proxy, so the two never
  drift. For your own packs, set `opa.packsConfigMap`.
- The proxy's readiness probe fails while the gate is failing closed (OPA or Redis
  down, saturated), so traffic moves to a healthy replica.
- Required values (database password, tokens) fail the install with a message
  instead of deploying an open gate.

## Connecting your SOC tools

The bundled mock SOC records what would have happened. To act on your real
tools, write a connector: a class with the same methods as
`services/mock_soc/client.py` (`MockSOCClient`).

| Methods | What they do in your environment |
|---|---|
| `close_alert`, `downgrade_severity`, `raise_severity`, `add_note`, `escalate` | Ticketing / SIEM case (ServiceNow, Jira, Sentinel, Splunk SOAR, ...) |
| `block_ip`, `isolate_host`, `disable_account` | Firewall, EDR, identity provider |
| `whitelist_indicator`, `suppress_rule` | Allowlists and detection rules (must honour `ttl_hours`) |
| `send_email`, `post_webhook` | Outbound messages |
| `reopen_alert`, `restore_severity`, `unblock_ip`, `release_host`, `enable_account`, `remove_whitelist`, `unsuppress_rule` | Reverse actions, used for one-click undo. Never exposed to the agent |
| `query_logs` | Log lines for an alert (treated as untrusted text) |

Package it into an image built on TrustGate's and point the proxy at it:

```dockerfile
FROM registry.corp.example/trustgate:2.4
COPY corp_connectors /app/corp_connectors
```

```bash
TRUSTGATE_SOC_CLIENT=corp_connectors.soar:SoarClient   # .env, or Helm env:
```

The class is built as `Class(MOCK_SOC_URL, mock_soc_token)`; read anything else it
needs from its own environment variables. If it cannot start, raise
`trustgate.config.NotConfigured`: decisions keep working and every allowed action
fails closed. Then set `mockSoc.enabled: false` (Helm) or remove the `mock-soc`
service (Compose).

## Going live safely

1. **Start in monitor mode** (`TRUSTGATE_MODE=monitor`). The gate logs what it
   would block and blocks nothing.
2. **Feed sender history.** Post `observed.sender_prior_messages` with each email
   alert from your mail gateway or SIEM; without it, every email T1 action escalates.
3. **Retrain the re-check model** on your own labelled alerts and analyst decisions
   (`scripts/train_recheck.py --data tickets.jsonl --feedback`) and check its holdout
   false-benign rate. The image's starter model was trained on synthetic alerts. Or run
   Ollama and set `TRUSTGATE_RECHECK_BACKEND=ollama`. Both run beside the rule scorecard.
   Measure with `python -m eval.recheck_bench`, and watch `recheck_analyst_agreement` in
   `/v1/metrics` for drift. Details: [RECHECK.md](RECHECK.md).
4. **Replace the example policy values** (critical assets, allowlists) in
   `packs/soc.json` with yours. The proxy and OPA both read the packs from the
   image, so ship yours in an image built on TrustGate's and set `TRUSTGATE_IMAGE`
   (Compose) or `image:` (Helm; or `opa.packsConfigMap`, mounted into both):

   ```dockerfile
   FROM ghcr.io/ashutosh20git/trustgate:2.4
   COPY packs /app/packs
   ```
5. **Watch the rollout report** (dashboard Insights page, `GET /v1/rollout`). When a
   tool shows enough decisions, no fail-closed errors and would-block reasons you
   agree with, switch to `enforce`.
6. **Ship the audit trail** to your SIEM (`TRUSTGATE_SIEM_JSONL` or Splunk HEC). The
   hash chain alone cannot show that its newest records were deleted or that the whole
   chain was rewritten; the SIEM's copy can (`Store.verify_audit_export`, and AU-9 in
   `GET /v1/compliance/nist-800-53`).
7. **Send the sender behaviour signals** with every email alert: `sender_first_link` and
   `sender_new_sending_ip` (yes or no) from the mail gateway or SIEM. Without them, sender
   history does not count and every email close goes to a human.

## Operations

- **Backups:** Postgres holds alerts, escalations, the action ledger and the
  hash-chained audit trail. Back it up like any security log; `GET /v1/metrics`
  reports `audit_chain_ok`.
- **Upgrades:** `git pull && docker compose pull && docker compose up -d`, or
  `helm upgrade` with the new image tag. Pods roll automatically when config or secrets change.
- **Team:** admins add, remove and re-issue tokens for analysts on the dashboard's
  Team page. It works at once, with no restart, and every change is in the audit trail.
  Members added there live in the database as token hashes.
- **Rotating tokens:** for team members, use **New token** on the Team page. For the
  admins in `secrets/analyst_tokens.txt`, delete the line, re-run
  `init_secrets.py --analyst <name>`, and restart the proxy (Compose:
  `docker compose restart trustgate-proxy`; Helm: update the secret).
- **Health:** `GET /healthz` on the proxy returns 503 while the gate fails closed;
  alert on it.

## Known limits

- One ingest and one dashboard replica in the chart. Ingest is stateless and can
  scale; the dashboard is stateless (each analyst's token is in their own cookie) and can scale too.
- The bundled Postgres and Redis are single instances without backups. Use managed
  services for production.
- No SSO yet: analysts authenticate with individual bearer tokens.
- The chart's NetworkPolicies restrict traffic *into* each component, not traffic out of it.
