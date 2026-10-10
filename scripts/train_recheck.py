"""Train the XGBoost facts-only re-check over typed facts (blueprint alternative backend).

    python scripts/train_recheck.py --out models/recheck_xgb.json

Uses the synthetic alert generator for labelled facts. Replace the generator
with a real labelled dataset loader for a production model (PLACEHOLDERS.md).
This is optional: the default backend is Ollama (TRUSTGATE_RECHECK_BACKEND=ollama).
"""

from __future__ import annotations

import pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import argparse
import os

from eval.generate_alerts import generate
from trustgate.config import Settings
from trustgate.ingest.split import Splitter
from trustgate.recheck import FEATURE_ORDER, vectorise

LABELS = {"benign": 0, "unsure": 1, "malicious": 2}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="models/recheck_xgb.json")
    parser.add_argument("-n", type=int, default=2000)
    args = parser.parse_args()
    try:
        import xgboost as xgb
    except ImportError:
        raise SystemExit("install the recheck-xgb extra: pip install '.[recheck-xgb]'")

    settings = Settings()
    splitter = Splitter(settings, enrich=False)
    rows, labels = [], []
    for raw in generate(args.n, authserv_id=settings.mta_authserv_id or "mx.corp.example"):
        label = raw.pop("ground_truth")["label"]
        alert = splitter.split(raw)
        rows.append(vectorise(alert.facts))
        labels.append(LABELS["malicious" if label == "malicious" else "benign"])

    dtrain = xgb.DMatrix(rows, label=labels, feature_names=list(FEATURE_ORDER))
    booster = xgb.train({"objective": "multi:softprob", "num_class": 3, "max_depth": 4, "eta": 0.3,
                         "eval_metric": "mlogloss"}, dtrain, num_boost_round=60)
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    booster.save_model(args.out)
    print(f"wrote {args.out} (set TRUSTGATE_RECHECK_BACKEND=xgboost to use it)")


if __name__ == "__main__":
    main()
