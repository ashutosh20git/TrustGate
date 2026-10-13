# Single image for every TrustGate Python service; the compose command (or the
# Helm chart) selects which one to run. Pinned to python:3.11-slim per the blueprint.
#
#   docker build -f docker/Dockerfile -t trustgate:2.4 .
#   docker build -f docker/Dockerfile --build-arg EXTRAS=full -t trustgate:2.4-full .
#   docker build -f docker/Dockerfile --build-arg SPACY_MODEL=en_core_web_sm -t trustgate:2.4-sm .
#
# EXTRAS=standard (default) leaves out the model-based detector (Prompt Guard 2 and
# LLM Guard pull in torch, several GB); the detector service then runs degraded and
# logs it, which only removes evidence for "benign". EXTRAS=full includes it.
#
# SPACY_MODEL is the spaCy model Presidio uses for output scanning. en_core_web_lg
# (default) finds more names and places; en_core_web_sm is ~500 MB smaller. The
# runtime stage sets TRUSTGATE_SPACY_MODEL to match.
#
# Two stages: the builder installs everything into /opt/venv with compilers and
# headers available; the runtime stage copies only that venv, so build-essential
# and libpq-dev never reach the published image.

# ---- builder ------------------------------------------------------------------
FROM python:3.11-slim AS builder

ARG EXTRAS=standard
ARG SPACY_MODEL=en_core_web_lg
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PIP_NO_CACHE_DIR=1 \
    VIRTUAL_ENV=/opt/venv PATH=/opt/venv/bin:$PATH

WORKDIR /app

# Build deps for packages with native wheels (checkdmarc, psycopg, pymupdf).
RUN apt-get update && apt-get install -y --no-install-recommends build-essential libpq-dev \
    && rm -rf /var/lib/apt/lists/*

RUN python -m venv /opt/venv

COPY pyproject.toml README.md ./
COPY trustgate ./trustgate
RUN set -e; \
    base="ingest,attachments,images,output-scan,recheck-xgb,mcp,server,agent,dashboard,eval"; \
    if [ "$EXTRAS" = "full" ]; then base="$base,detector"; fi; \
    pip install ".[$base]" && python -m spacy download "$SPACY_MODEL"

# Starter facts-only re-check (XGBoost on synthetic alerts) so T1 decisions work
# without Ollama or a GPU. Retrain on your own labelled alerts before relying on it
# (scripts/train_recheck.py); TRUSTGATE_RECHECK_BACKEND picks the backend.
COPY eval ./eval
COPY scripts ./scripts
RUN python scripts/train_recheck.py --out models/recheck_xgb.json

# ---- runtime ------------------------------------------------------------------
FROM python:3.11-slim AS runtime

ARG SPACY_MODEL=en_core_web_lg
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 \
    VIRTUAL_ENV=/opt/venv PATH=/opt/venv/bin:$PATH \
    TRUSTGATE_SPACY_MODEL=$SPACY_MODEL

WORKDIR /app

# Shared libraries only: Tesseract for image OCR, libgomp for XGBoost.
RUN apt-get update && apt-get install -y --no-install-recommends tesseract-ocr libgomp1 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /opt/venv /opt/venv
COPY --from=builder /app/models ./models
COPY trustgate ./trustgate
COPY services ./services
COPY packs ./packs
COPY scripts ./scripts
COPY eval ./eval

# Run as an unprivileged user. Only /app/data is writable (threat-intel cache,
# model downloads); mount a volume there to keep it across restarts.
RUN useradd --system --uid 10001 --home-dir /app/data trustgate \
    && mkdir -p /app/data && chown 10001 /app/data
ENV HOME=/app/data HF_HOME=/app/data/hf TRUSTGATE_TI_CACHE=/app/data/cache/ti
USER 10001

EXPOSE 8080 8081 8082 8090 8501
CMD ["uvicorn", "services.proxy.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8080"]
