#!/usr/bin/env bash
# SPECTER deployment helper — run from repo root after filling .env
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

info() { echo -e "${GREEN}==>${NC} $*"; }
warn() { echo -e "${RED}!!>${NC} $*"; }

usage() {
  cat <<EOF
Usage: ./scripts/deploy.sh <command>

Commands:
  check       Verify CLIs and auth (docker, vercel, render, supabase, railway)
  docker      Start local Postgres + Redis (requires Docker Desktop running)
  init-db     Create pgvector schema (uses DATABASE_URL from .env)
  demo-data   Load demo_data/*.json into memory fabric
  vercel      Deploy frontend to Vercel (production)
  render      Trigger Render redeploy of specter-api (srv-d8nufhsm0tmc73ehjv7g)
  supabase    Create Supabase project 'specter' (interactive org/region)
  all-local   docker + init-db + demo-data

Environment:
  Copy .env.example → .env and set DATABASE_URL, ANTHROPIC_API_KEY or OPENAI_API_KEY.

Vercel env (set in dashboard or via vercel env add):
  NEXT_PUBLIC_API_URL=https://specter-api.onrender.com
  NEXT_PUBLIC_WS_URL=wss://specter-api.onrender.com
EOF
}

cmd_check() {
  info "CLI availability"
  for bin in docker vercel render supabase railway gh curl; do
    if command -v "$bin" >/dev/null 2>&1; then
      echo "  ✓ $bin"
    else
      echo "  ✗ $bin (missing)"
    fi
  done
  echo
  info "Auth status"
  vercel whoami 2>/dev/null || warn "Vercel: not logged in (vercel login)"
  render whoami 2>/dev/null || warn "Render: not logged in (render login)"
  supabase projects list 2>/dev/null | head -6 || warn "Supabase: not logged in (supabase login)"
  railway whoami 2>/dev/null || warn "Railway: not logged in (railway login — interactive)"
  if docker info >/dev/null 2>&1; then
    echo "  ✓ Docker daemon running"
  else
    warn "Docker daemon not running — open Docker Desktop"
  fi
  echo
  info "Production API probe (read-only)"
  curl -sf "https://specter-api.onrender.com/health" && echo || warn "specter-api.onrender.com unreachable"
}

cmd_docker() {
  if ! docker info >/dev/null 2>&1; then
    warn "Starting Docker Desktop..."
    open -a Docker 2>/dev/null || true
    for i in $(seq 1 60); do
      docker info >/dev/null 2>&1 && break
      sleep 2
    done
  fi
  docker compose up -d db redis
  info "Postgres: postgresql://specter:specter@localhost:5432/specter"
  info "Redis:    redis://localhost:6379/0"
}

cmd_init_db() {
  cd packages/backend
  uv run python -c "import asyncio; from specter.memory.db import init_db; asyncio.run(init_db())"
  info "Database schema ready (pgvector + incidents tables)"
}

cmd_demo_data() {
  make demo-data
}

cmd_vercel() {
  cd frontend
  if [[ -z "${NEXT_PUBLIC_API_URL:-}" ]]; then
    export NEXT_PUBLIC_API_URL="${SPECTER_API_URL:-https://specter-api.onrender.com}"
  fi
  if [[ -z "${NEXT_PUBLIC_WS_URL:-}" ]]; then
    export NEXT_PUBLIC_WS_URL="${SPECTER_WS_URL:-wss://specter-api.onrender.com}"
  fi
  info "Deploying frontend (API=$NEXT_PUBLIC_API_URL WS=$NEXT_PUBLIC_WS_URL)"
  vercel --prod --yes \
    -e "NEXT_PUBLIC_API_URL=$NEXT_PUBLIC_API_URL" \
    -e "NEXT_PUBLIC_WS_URL=$NEXT_PUBLIC_WS_URL"
}

cmd_render() {
  info "Validating render.yaml"
  render blueprints validate "$ROOT/render.yaml"
  info "Triggering deploy for specter-api (srv-d8nufhsm0tmc73ehjv7g)"
  render deploys create srv-d8nufhsm0tmc73ehjv7g --confirm --wait
}

cmd_supabase() {
  info "Listing orgs — pick ORG_ID from output"
  supabase orgs list
  read -r -p "Org ID: " ORG_ID
  read -r -s -p "Database password (min 8 chars): " DB_PASS
  echo
  supabase projects create specter \
    --org-id "$ORG_ID" \
    --db-password "$DB_PASS" \
    --region us-east-1 \
    --size nano
  info "Enable pgvector: Supabase Dashboard → SQL → run init.sql"
  info "Connection string: Dashboard → Project Settings → Database → URI"
}

cmd_all_local() {
  cmd_docker
  cmd_init_db
  cmd_demo_data
  info "Start API:  cd packages/backend && uv run uvicorn specter.main:app --reload --app-dir src"
  info "Start UI:   cd frontend && npm run dev"
}

case "${1:-check}" in
  check) cmd_check ;;
  docker) cmd_docker ;;
  init-db) cmd_init_db ;;
  demo-data) cmd_demo_data ;;
  vercel) cmd_vercel ;;
  render) cmd_render ;;
  supabase) cmd_supabase ;;
  all-local) cmd_all_local ;;
  *) usage; exit 1 ;;
esac
