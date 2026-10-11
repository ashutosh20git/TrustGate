# The deciding layer: the facts-only judgement, and how to make it reliable

Before any security-reducing (T1) action, such as closing an alert as benign, TrustGate
recomputes the verdict from **typed facts alone**: values from systems the attacker cannot
write to, never the email, logs or any other text. If the agent says "benign" and the facts do
not, the attacker's text must have tipped the agent, so the action goes to a human.

This page explains how that judgement is made and what keeps it reliable. Reliability here
means **few wrong "benign" verdicts, and an honest "unsure" otherwise**. No judgement is
perfect when the facts genuinely cannot tell, so the design makes uncertainty escalate.

## How a verdict is made

```
typed facts ──► model (XGBoost or Ollama) ──┐
          └──► rule scorecard ──────────────┤──► both benign? ──► evidence floor ──► OPA ──► allow
                                            └──► otherwise: unsure / malicious ──► escalate
```

1. **The facts** come from trusted sources: your mail server's Authentication-Results header
   (SPF, DKIM, DMARC, ARC, BIMI), threat intel (VirusTotal, URLhaus, AbuseIPDB, OTX, WHOIS),
   TrustGate's own parsers (attachments, QR codes), and your SIEM / mail gateway / CMDB
   (sender history, organisation history, asset criticality).
2. **Two independent judges** (`trustgate/recheck.py` `EnsembleRecheck`):
   - the **model**: an XGBoost classifier (the Docker default) or a small LLM through Ollama;
   - the **rule scorecard** (`trustgate/scorecard.py`): fixed, explainable rules.
   The verdict is **benign only if both say benign**, malicious if either says malicious,
   otherwise unsure. A blind spot in one judge cannot open the gate on its own.
3. **The evidence floor** (`trustgate/evidence_floor.py`, `packs/floor.json`) then applies hard
   rules whatever the judges said: no failed lookup, core facts known, a fact the attacker cannot
   buy, and a cited fact that supports benign.

When the action escalates, the judges' reasons go to the analyst (for example
`re-check: scorecard: Reply-To is on another domain` or
`re-check: benign probability 0.78 below 0.90`). The agent never sees them.

## What makes it reliable

### 1. The model sees every fact

`FEATURE_ORDER` is derived from `TypedFacts.recheck_view()`, so the classifier sees all 31
re-check facts. It used to see 14, missing sender history and every compromised-account
signal. A model trained on a different fact list is **refused** at start-up (and T1 fails closed)
instead of silently reading facts in the wrong columns: retrain it.

### 2. "Benign" needs confidence

`TRUSTGATE_RECHECK_MIN_CONFIDENCE` (default **0.9**): the classifier's "benign" counts only at
that probability or above. A 51% benign is not enough to lower security; below the bar it
becomes unsure and escalates.

### 3. Two judges must agree

`TRUSTGATE_RECHECK_SCORECARD=on` (default). The scorecard answers:

| Verdict | When |
|---|---|
| malicious | DMARC failed, a malicious URL, file or IP (abuse score ≥ 75) |
| unsure | **any** warning sign (suspicious reputation, failed lookup, hidden or macro attachment, QR code, Reply-To elsewhere, a known sender's first link or attachment or new IP, a link domain nobody here has seen, a fresh domain or certificate, an unsigned process, a critical asset, unknown DMARC on an email), **or** no strong support |
| benign | no warning sign and at least one **strong** fact: sender history (≥ 3 messages), someone here replied to the sender, a clean sandbox, a low IP abuse score, BIMI |

SPF, DKIM and DMARC passing are deliberately **not** strong. An attacker who owns a domain
passes all three for free.

### 4. Train on your own data

```bash
python scripts/train_recheck.py --data tickets.jsonl                 # your SOC's labelled alerts
python scripts/train_recheck.py --data tickets.jsonl --feedback      # + analyst decisions
```

`--data` takes JSON lines, either a raw alert (as ingest accepts it) with
`{"ground_truth": {"label": "benign" | "malicious"}}`, or `{"facts": {...}, "label": ...}`.
Export past tickets with their final analyst disposition. `"unsure"` is accepted for alerts
whose facts cannot decide.

Every run holds out 20% (stratified) and reports the **false-benign rate**: alerts not labelled
benign that the model calls benign at the configured confidence. Metrics and sources are
written to `<model>.meta.json`; `synthetic_only: true` means the model has never seen your data.

The starter model (built into the Docker image) is trained on synthetic alerts that include
**hard negatives**: attacker-owned domains passing SPF/DKIM/DMARC with aged domains and clean
links, compromised accounts with real history behaving unusually, and alerts whose core fact is
unknown (labelled unsure). Optional facts are dropped at random for every label alike, so the
model judges the facts, not their absence.

### 5. Learn from analysts, watch for drift

`--feedback` adds what analysts decided, from the store (`Store.feedback_examples`):

- an approved T1 escalation where the agent said benign → **benign**;
- a rejected one → **malicious**;
- an executed T1 action later reverted (by an analyst, or automatically when the alert turned
  out to be manipulated) → **malicious**, overriding an earlier approval.

Canaries are excluded. `GET /v1/metrics` reports `recheck_analyst_agreement`: how often the
facts-only verdict matched the analyst's final call. A falling rate means it is time to retrain.

### 6. Threat-intel quorum

`TRUSTGATE_TI_QUORUM` (default 1; **2 recommended** with both VirusTotal and URLhaus keys): a
link counts as clean only when that many sources independently said clean and none flagged it.
Sources disagreeing makes it suspicious. Across several links, a link no source could vouch for
outweighs another link's clean result.

### 7-9. Facts the attacker cannot buy

New typed facts, supplied by your SIEM / mail gateway / CMDB in the alert's `observed` or
`enrichment` block (TrustGate cannot see organisation-wide mail by itself):

| Fact | Meaning | Used as |
|---|---|---|
| `org_replied_to_sender` | Someone in the organisation has replied to this sender | **Costly support** (an attacker can send mail, not make staff answer); strong support in the scorecard |
| `org_sender_domain_messages` | Messages from this domain to anyone here before | Model feature |
| `org_url_domain_first_seen` | Nobody here has received or clicked this link domain | **Cancels all history** (a compromised account's new link); scorecard warning |
| `org_attachment_prevalence` | Times this attachment hash was seen here | Model feature |
| `arc_pass`, `bimi_pass` | ARC chain and BIMI, **only** from your MTA's trusted header | Benign support; BIMI is strong (it needs a verified mark certificate) |
| `cert_age_days`, `domain_first_seen_days` | TLS certificate age and passive-DNS first resolution of the link host | Scorecard warning when under 30 days |
| `asset_criticality`, `process_signed` | CMDB criticality and the flagged process's signature | Scorecard: critical asset or unsigned process is a warning |

History (the sender's and the organisation's) stops counting as support whenever a known
sender behaves unusually, because history is exactly what a hijacked mailbox has.

### 10. Measure it

```bash
python -m eval.recheck_bench          # writes eval/results/recheck_bench.json
python -m eval.recheck_bench --check  # CI: fail on any regression
```

The benchmark feeds the judges **fact combinations an attacker can afford** (17 cases:
attacker-owned domains, compromised accounts, failed lookups, unknown core facts, ambiguous
endpoints) and genuinely benign controls, and measures each judge separately:

| Judge | False-benign (attacks let through) | Benign pass |
|---|---|---|
| Scorecard alone | 0% | 100% |
| Model alone (starter model) | 18% | 100% |
| **Ensemble (both agree)** | **0%** | **100%** |
| **Full T1 (ensemble + evidence floor)** | **0%** | **100%** |

The model alone misses three ambiguous cases (unknown DMARC with otherwise perfect facts, an
unsigned process with a clean hash, a critical asset). The scorecard catches them. That is why
the two judges must agree. CI fails if the full T1 judgement lets any case through, or if any
judge's false-benign rate rises above `eval/results/recheck_baseline.json` (the retrained model
gets one case of slack).

The benchmark's controls are realistic: a known sender as a mail gateway reports it, with "no"
for each unusual-behaviour flag. With those flags unknown, the model rightly says unsure,
because compromise cannot be ruled out. That is the price of strictness, and supplying the
flags from your mail gateway is how you avoid paying it.

## Settings

| Variable | Default | Effect |
|---|---|---|
| `TRUSTGATE_RECHECK_BACKEND` | `ollama` (Docker: `xgboost`) | Model backend |
| `TRUSTGATE_RECHECK_MIN_CONFIDENCE` | 0.9 | Minimum probability for the classifier's benign |
| `TRUSTGATE_RECHECK_SCORECARD` | `on` | Second judge; `off` to run the model alone |
| `TRUSTGATE_TI_QUORUM` | 1 | Sources that must call a link clean |
| `TRUSTGATE_XGB_MODEL` | `models/recheck_xgb.json` | Trained model (metadata in `.meta.json`) |
