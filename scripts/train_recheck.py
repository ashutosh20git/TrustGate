"""Train the XGBoost facts-only re-check and report how often it wrongly says "benign".

    python scripts/train_recheck.py                                # synthetic starter model
    python scripts/train_recheck.py --data tickets.jsonl           # your SOC's labelled alerts
    python scripts/train_recheck.py --data tickets.jsonl --feedback  # + analyst decisions from the store

Data sources (combine freely):
  --data FILE      JSON lines, one alert per line, either
                     a raw alert as ingest accepts it plus {"ground_truth": {"label": "benign"|"malicious"}}, or
                     {"facts": {<TypedFacts fields>}, "label": "benign"|"malicious"}.
                   "unsure" is accepted too, for alerts whose facts cannot decide.
                   Export past tickets with their final analyst disposition.
  --feedback       Analyst decisions recorded by TrustGate (DATABASE_URL): approved or rejected
                   T1 escalations and reverted actions (Store.feedback_examples).
  --synthetic N    Generated alerts, including hard negatives (attacker-owned domains passing
                   SPF/DKIM/DMARC; compromised accounts). Default 4000 when no other data is given.

A stratified holdout (default 20%) measures the model before it is saved. The key number is the
false-benign rate: malicious alerts the model calls benign at the configured confidence. The
metrics and the training sources are written next to the model (<model>.meta.json).
"""

from __future__ import annotations

import pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import argparse
import json
import os
import random
from typing import Any

from eval.generate_alerts import generate
from trustgate.config import Settings
from trustgate.ingest.split import Splitter
from trustgate.models import TypedFacts
from trustgate.recheck import FEATURE_ORDER, vectorise

LABELS = {"benign": 0, "unsure": 1, "malicious": 2}


def load_jsonl(path: str, splitter: Splitter) -> list[tuple[TypedFacts, str]]:
    out: list[tuple[TypedFacts, str]] = []
    with open(path, encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            if not line.strip():
                continue
            row = json.loads(line)
            if "facts" in row:
                facts, label = TypedFacts.model_validate(row["facts"]), row["label"]
            else:
                label = (row.pop("ground_truth", None) or {}).get("label")
                facts = splitter.split(row).facts
            if label not in LABELS:
                raise SystemExit(f"{path}:{n}: label must be benign, malicious or unsure, got {label!r}")
            out.append((facts, label))
    return out


def synthetic(n: int, splitter: Splitter, authserv: str) -> list[tuple[TypedFacts, str]]:
    out = []
    for raw in generate(n, authserv_id=authserv, training=True):
        label = raw.pop("ground_truth")["label"]
        out.append((splitter.split(raw).facts, label))
    return out


def feedback(settings: Settings) -> list[tuple[TypedFacts, str]]:
    from trustgate.store import Store

    return [(alert.facts, label) for alert, label in Store(settings=settings).feedback_examples()]


def split_holdout(rows: list[tuple[TypedFacts, str]], fraction: float, seed: int = 7):
    """Stratified: each label keeps its share in both parts."""
    rng = random.Random(seed)
    train, test = [], []
    for label in LABELS:
        group = [r for r in rows if r[1] == label]
        rng.shuffle(group)
        k = int(round(len(group) * fraction))
        test += group[:k]
        train += group[k:]
    return train, test


def evaluate(booster, rows: list[tuple[TypedFacts, str]], min_confidence: float) -> dict[str, Any]:
    import xgboost as xgb

    if not rows:
        return {"n": 0}
    probs = booster.predict(xgb.DMatrix([vectorise(f) for f, _ in rows], feature_names=list(FEATURE_ORDER)))
    said_benign = [p[0] >= min_confidence and p[0] == max(p) for p in probs]
    # Anything not labelled benign (malicious, or unsure: a core fact unknown) must not pass.
    malicious = [i for i, (_, label) in enumerate(rows) if label != "benign"]
    benign = [i for i, (_, label) in enumerate(rows) if label == "benign"]
    false_benign = sum(1 for i in malicious if said_benign[i])
    benign_passed = sum(1 for i in benign if said_benign[i])
    return {
        "n": len(rows), "not_benign": len(malicious), "benign": len(benign),
        "false_benign": false_benign,
        "false_benign_rate": round(false_benign / len(malicious), 4) if malicious else None,
        "benign_pass_rate": round(benign_passed / len(benign), 4) if benign else None,
        "min_confidence": min_confidence,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="models/recheck_xgb.json")
    parser.add_argument("--data", action="append", default=[], help="labelled JSON lines (repeatable)")
    parser.add_argument("--feedback", action="store_true", help="add analyst decisions from the store")
    parser.add_argument("--synthetic", type=int, default=None, help="generated alerts (default 4000 if no data)")
    parser.add_argument("--holdout", type=float, default=0.2)
    parser.add_argument("-n", type=int, default=None, help=argparse.SUPPRESS)  # old name for --synthetic
    args = parser.parse_args()
    try:
        import xgboost as xgb
    except ImportError:
        raise SystemExit("install the recheck-xgb extra: pip install '.[recheck-xgb]'")

    settings = Settings()
    authserv = settings.mta_authserv_id or "mx.corp.example"
    os.environ.setdefault("TRUSTGATE_MTA_AUTHSERV_ID", authserv)
    splitter = Splitter(Settings(), enrich=False)

    rows: list[tuple[TypedFacts, str]] = []
    sources: dict[str, int] = {}
    for path in args.data:
        loaded = load_jsonl(path, splitter)
        rows += loaded
        sources[f"data:{path}"] = len(loaded)
    if args.feedback:
        fb = feedback(settings)
        rows += fb
        sources["analyst_feedback"] = len(fb)
    n_synth = args.synthetic if args.synthetic is not None else (args.n or (0 if rows else 4000))
    if n_synth:
        syn = synthetic(n_synth, splitter, authserv)
        rows += syn
        sources["synthetic"] = len(syn)
    if not {"benign", "malicious"} <= {label for _, label in rows}:
        raise SystemExit("need labelled examples of both benign and malicious alerts")

    train, test = split_holdout(rows, args.holdout)
    dtrain = xgb.DMatrix([vectorise(f) for f, _ in train], label=[LABELS[label] for _, label in train],
                         feature_names=list(FEATURE_ORDER))
    booster = xgb.train({"objective": "multi:softprob", "num_class": 3, "max_depth": 4, "eta": 0.3,
                         "eval_metric": "mlogloss"}, dtrain, num_boost_round=60)
    metrics = evaluate(booster, test, settings.recheck_min_confidence)

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    booster.save_model(args.out)
    meta = {"features": list(FEATURE_ORDER), "sources": sources, "train": len(train), "holdout": metrics,
            "synthetic_only": set(sources) == {"synthetic"}}
    with open(os.path.splitext(args.out)[0] + ".meta.json", "w", encoding="utf-8") as fh:
        json.dump(meta, fh, indent=2)
    print(f"wrote {args.out} from {sources}")
    print(f"holdout: {json.dumps(metrics)}")
    if meta["synthetic_only"]:
        print("note: trained on synthetic alerts only; retrain with --data / --feedback before relying on it")


if __name__ == "__main__":
    main()
