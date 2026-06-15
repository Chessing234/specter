#!/usr/bin/env bash
# SPECTER — hackathon / local setup (Docker + uv + npm)

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "SPECTER setup"
echo "============="

command -v docker >/dev/null 2>&1 || {
  echo "Docker is required."
  exit 1
}
command -v uv >/dev/null 2>&1 || {
  echo "uv is required (https://docs.astral.sh/uv/)."
  exit 1
}

echo "Starting PostgreSQL + Redis..."
docker compose up -d db redis

echo "Waiting for Postgres health..."
for i in {1..30}; do
  if docker compose exec -T db pg_isready -U specter -d specter >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

echo "Syncing Python (packages/backend)..."
(cd packages/backend && uv sync --all-extras)

echo "Initializing database schema..."
(cd packages/backend && uv run python -c "import asyncio; from specter.memory.db import init_db; asyncio.run(init_db())")

echo "Installing frontend dependencies..."
(cd frontend && npm install)

echo ""
echo "Done."
echo "  Backend:  cd packages/backend && uv run uvicorn specter.main:app --reload"
echo "  Frontend: cd frontend && npm run dev"
echo "  Demo data: make demo-data"
echo ""
echo "  API:       http://localhost:8000/health"
echo "  Dashboard: http://localhost:3000"
