# Single image for every TrustGate Python service; the compose command selects
# which one to run. Pinned to python:3.11-slim per the blueprint.
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PIP_NO_CACHE_DIR=1

WORKDIR /app

# Build deps for packages with native wheels (checkdmarc, psycopg, pymupdf).
RUN apt-get update && apt-get install -y --no-install-recommends build-essential libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY trustgate ./trustgate
# Install the library plus every runtime extra the services need.
RUN pip install ".[ingest,attachments,output-scan,detector,recheck-xgb,mcp,server,agent,dashboard,eval]" \
    && python -m spacy download en_core_web_lg

COPY . .

EXPOSE 8080 8081 8082 8090 8501
CMD ["uvicorn", "services.proxy.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8080"]
