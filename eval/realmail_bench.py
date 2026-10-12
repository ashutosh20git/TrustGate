"""The deciding layer on real phishing mail.

    git clone --depth 1 https://github.com/rf-peixoto/phishing_pot.git /tmp/phishing_pot
    python -m eval.realmail_bench /tmp/phishing_pot/email          # writes eval/results/realmail.json

phishing_pot is a public corpus of real phishing emails caught by honeypot inboxes, with full
headers (license and collection details in the repository's DATASET_CARD.md). Every email goes
through TrustGate's real ingest (parser, trusted Authentication-Results handling, decoding,
detector) and then through each judge, as if the honeypot's own mail server were ours:

  * the trusted authserv-id is the one most common in the corpus's topmost headers (the
    honeypot provider's MTA): only its results become SPF/DKIM/DMARC facts;
  * senders have no history with a honeypot inbox: sender_prior_messages = 0, which is true;
  * no threat-intel keys offline: URL reputation stays unknown, as it would without keys.

Every email is phishing, so any "benign" is a false benign. Reported: false-benign rate per
judge (scorecard, model, ensemble, full T1 = ensemble + evidence floor), separately for the hard
subset whose DMARC *passed* (attacker-owned or compromised domains), plus how often the detector
saw text aimed at an AI. There is no matching corpus of real benign mail with full headers here,
so the price of strictness on real mail is not measured: see docs/BENCHMARKS.md.
"""

from __future__ import annotations

import argparse
import base64
import collections
import dataclasses
import email
import email.policy
import json
import os
import random
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


def _top_authserv(paths: list[Path], sample: int = 2000) -> str:
    counts: collections.Counter[str] = collections.Counter()
    for p in paths[:sample]:
        try:
            msg = email.message_from_bytes(p.read_bytes(), policy=email.policy.default)
            headers = msg.get_all("Authentication-Results") or []
        except Exception:  # noqa: BLE001
            continue
        if headers:
            first = str(headers[0]).split(";", 1)[0].strip().lower()
            counts["" if "=" in first else first] += 1
    top = counts.most_common(1)[0][0] if counts else ""
    return top if top else "microsoft365"  # headers without an authserv-id: Microsoft 365 / Exchange Online


def run(folder: str, limit: int | None = None, seed: int = 7) -> dict[str, Any]:
    paths = sorted(Path(folder).glob("*.eml"))
    if limit and len(paths) > limit:
        paths = random.Random(seed).sample(paths, limit)
    authserv = _top_authserv(paths)
    os.environ["TRUSTGATE_MTA_AUTHSERV_ID"] = authserv

    from trustgate.config import Settings
    from trustgate.detector import Detector
    from trustgate.evidence_floor import t1_evidence
    from trustgate.ingest.split import Splitter
    from trustgate.models import TypedFacts
    from trustgate.policy_client import load_pack
    from trustgate.recheck import EnsembleRecheck, XGBoostRecheck
    from trustgate.scorecard import score

    settings = Settings()
    model_path = settings.xgb_model_path
    if not Path(model_path).exists():
        model_path = os.path.join(tempfile.mkdtemp(prefix="tg-real-"), "recheck_xgb.json")
        subprocess.run([sys.executable, "scripts/train_recheck.py", "--out", model_path], check=True, capture_output=True)
    model = XGBoostRecheck(dataclasses.replace(settings, xgb_model_path=model_path))
    ensemble = EnsembleRecheck(model)
    floor = load_pack("packs/soc.rego").floor["t1_evidence"]
    splitter = Splitter(settings, detector=Detector(settings, use_models=False), enrich=False)

    judged: dict[str, collections.Counter] = {k: collections.Counter() for k in ("all", "dmarc_pass")}
    stats = collections.Counter()
    let_through: list[str] = []
    for p in paths:
        raw = {"alert_id": p.stem[:60], "source": "email", "severity": "medium",
               "observed": {"sender_prior_messages": 0},
               "email": {"raw_b64": base64.b64encode(p.read_bytes()).decode(), "envelope": {}}}
        try:
            alert = splitter.split(raw)
        except Exception:  # noqa: BLE001 - an email the pipeline cannot read is not judged benign
            stats["unparseable"] += 1
            continue
        f: TypedFacts = alert.facts
        stats["parsed"] += 1
        stats["ai_evasion"] += alert.ai_evasion_attempt
        stats[f"dmarc_{f.dmarc_pass}"] += 1
        cited = [f"facts.{c['fact']}" for c in floor["benign_support"] if getattr(f, c["fact"], None) is not None]
        verdicts = {
            "scorecard": score(f).verdict == "benign",
            "model": model(f).verdict == "benign",
            "ensemble": ensemble(f).verdict == "benign",
        }
        verdicts["t1"] = verdicts["ensemble"] and not t1_evidence(f, "email", floor, cited).reasons()
        for group in ("all", "dmarc_pass") if f.dmarc_pass else ("all",):
            judged[group]["n"] += 1
            for judge, benign in verdicts.items():
                judged[group][judge] += benign
        if verdicts["t1"] and len(let_through) < 20:
            let_through.append(p.name)

    def rates(c):
        return {judge: round(c[judge] / c["n"], 4) if c["n"] else None for judge in ("scorecard", "model", "ensemble", "t1")}

    return {
        "corpus": "phishing_pot (real phishing, honeypot inboxes)", "emails": len(paths), "trusted_authserv": authserv,
        "parsed": stats["parsed"], "unparseable": stats["unparseable"],
        "dmarc": {"pass": stats["dmarc_True"], "fail": stats["dmarc_False"], "unknown": stats["dmarc_None"]},
        "detector_flagged_ai_directed_text": round(stats["ai_evasion"] / max(1, stats["parsed"]), 4),
        "false_benign_rate": rates(judged["all"]),
        "false_benign_rate_dmarc_pass": rates(judged["dmarc_pass"]), "dmarc_pass_emails": judged["dmarc_pass"]["n"],
        "t1_let_through_examples": let_through,
    }


def main() -> int:
    parser = argparse.ArgumentParser(prog="eval.realmail_bench")
    parser.add_argument("folder", help="a folder of .eml files (phishing_pot/email)")
    parser.add_argument("--limit", type=int, default=None, help="random sample size (default: all)")
    parser.add_argument("--out", default="eval/results/realmail.json")
    args = parser.parse_args()
    result = run(args.folder, args.limit)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps({k: v for k, v in result.items() if k != "t1_let_through_examples"}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
