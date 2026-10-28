# TrustGate dashboard

The analyst dashboard: what the AI agent tried, what TrustGate decided, and what needs a human.
Next.js 16 (App Router) with shadcn/ui, Tailwind CSS 4, SWR and Recharts.

## How it talks to TrustGate

The browser never calls the TrustGate proxy directly.

- **Sign-in** (`app/api/session`) checks the analyst token against the proxy and stores it in an
  httpOnly, SameSite=Strict cookie. Page scripts never see it.
- **Data** (`app/api/tg/[...path]`) forwards an allow-list of analyst reads and decisions to the
  proxy with that token (`lib/server/trustgate.ts`). Agent tool calls (`/v1/tools/...`) are not on
  the list, so the dashboard can never act as the agent. Writes also need an `x-tg-request` header.
- **Pages** (`app/(app)/...`) are client components that refresh every 10 seconds (`lib/api.ts`).
  `proxy.ts` sends anyone without a session to `/login`. Lists load 50 rows at a time with
  **Load more** (`usePaged`), following the proxy's `X-Next-Cursor` header.
- Attacker-written alert content is rendered only as plain text (`Quarantined` in
  `components/tg/bits.tsx`), never as markup.

## Run it

```bash
npm ci
TRUSTGATE_PROXY_URL=http://127.0.0.1:8080 npm run dev      # http://localhost:3000
npm run build && npm start                                 # production
npx eslint .
```

In Docker Compose it runs as the `dashboard` service on http://127.0.0.1:8501 (`Dockerfile` here).
The first sign-in uses the admin token `scripts/init_secrets.py` printed; that admin adds everyone else on
the Team page.

## Pages

| Page | What it shows |
|---|---|
| Overview | Totals, what needs you, recent activity, decisions by kind of action |
| Alerts | Every alert with its status; each alert's every step, trusted facts and untrusted content, and a Review now button when something is held |
| Review queue | Held actions in plain words, what would let them run; approve or reject with a reason. `?alert=ID` shows one alert's items; the Decided tab keeps every past decision |
| Actions taken | Everything that ran, with one-click undo |
| Activity log | The hash-chained audit trail, filterable, with the exact record and a JSON download |
| Insights | Monitor-mode rollout readiness and analyst rubber-stamp checks |
| Compliance & tools | CERT-In, DPDP, ISO 27001 and NIST 800-53 evidence packs; MCP tool re-approval |
| Team (admins only) | Add analysts or admins (each token is shown once), give someone a new token, remove access |
