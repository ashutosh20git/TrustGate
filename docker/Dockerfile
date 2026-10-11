# Single image for every TrustGate Python service; the compose command (or the
# Helm chart) selects which one to run. Pinned to python:3.11-slim per the blueprint.
#
#   docker build -f docker/Dockerfile -t trustgate:2.4 .
#   docker build -f docker/Dockerfile --build-arg EXTRAS=full -t trustgate:2.4-full .
#
# EXTRAS=standard (default) leaves out the model-based detector (Prompt Guard 2 and
# LLM Guard pull in torch, several GB); the detector service then runs degraded and
# logs it, which only removes evidence for "benign". EXTRAS=full includes it.
FROM python:3.11-slim

ARG EXTRAS=standard
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PIP_NO_CACHE_DIR=1

WORKDIR /app

# Build deps for packages with native wheels (checkdmarc, psycopg, pymupdf); Tesseract for image OCR.
RUN apt-get update && apt-get install -y --no-install-recommends build-essential libpq-dev tesseract-ocr \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY trustgate ./trustgate
RUN set -e; \
    base="ingest,attachments,images,output-scan,recheck-xgb,mcp,server,agent,dashboard,eval"; \
    if [ "$EXTRAS" = "full" ]; then base="$base,detector"; fi; \
    pip install ".[$base]" && python -m spacy download en_core_web_lg

COPY . .

# Starter facts-only re-check (XGBoost on synthetic alerts) so T1 decisions work
# without Ollama or a GPU. Retrain on your own labelled alerts before relying on it
# (scripts/train_recheck.py); TRUSTGATE_RECHECK_BACKEND picks the backend.
RUN python scripts/train_recheck.py --out models/recheck_xgb.json

# Run as an unprivileged user. Only /app/data is writable (threat-intel cache,
# model downloads); mount a volume there to keep it across restarts.
RUN useradd --system --uid 10001 --home-dir /app/data trustgate \
    && mkdir -p /app/data && chown 10001 /app/data
ENV HOME=/app/data HF_HOME=/app/data/hf TRUSTGATE_TI_CACHE=/app/data/cache/ti
USER 10001

EXPOSE 8080 8081 8082 8090 8501
CMD ["uvicorn", "services.proxy.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8080"]
