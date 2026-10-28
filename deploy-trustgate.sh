#!/usr/bin/env bash
set -euo pipefail

WORKDIR="${1:-trustgate}"
ANALYST="${2:-alice}"

echo "Creating directory: $WORKDIR"
mkdir -p "$WORKDIR"
cd "$WORKDIR"

echo "⬇Downloading docker-compose.yml..."
curl -fsSLO https://raw.githubusercontent.com/ashutosh20git/TrustGate/main/docker-compose.yml

echo "Generating secrets (analyst: $ANALYST)..."
curl -fsSL https://raw.githubusercontent.com/ashutosh20git/TrustGate/main/scripts/init_secrets.py | python3 - --analyst "$ANALYST"

echo "Pulling TrustGate image..."
docker compose pull

echo "Starting TrustGate stack..."
docker compose up -d

echo ""
echo "TrustGate is starting up..."
echo ""
echo "Next steps:"
echo "   1. Wait ~30-60 seconds for all services to be healthy"
echo "   2. Seed demo data:"
echo "      docker compose exec ingest python scripts/seed_demo.py"
echo ""
echo "   3. Access points:"
echo "      • Proxy (agent API):     http://127.0.0.1:8080"
echo "      • Ingest (SIEM endpoint): http://127.0.0.1:8081"
echo "      • Dashboard:             http://127.0.0.1:8501"
echo ""
echo "   4. Your analyst token was printed above — save it!"
echo "      Sign in to the dashboard with it at http://127.0.0.1:8501"
echo ""
echo "To stop:  docker compose down"
echo "To wipe: docker compose down -v"
echo "To upgrade: docker compose pull && docker compose up -d"