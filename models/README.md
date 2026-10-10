# models/

Holds the optional XGBoost facts-only re-check model (`recheck_xgb.json`), which
is git-ignored. Train it with:

    python scripts/train_recheck.py --out models/recheck_xgb.json

Then set `TRUSTGATE_RECHECK_BACKEND=xgboost`. The default backend is Ollama +
a small Qwen/Llama model; see PLACEHOLDERS.md (`tg-8wu`).
