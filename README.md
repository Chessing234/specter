# SPECTER

**S**ecurity **P**rotocol for **E**xecutable **C**ontextual **T**hreat **E**valuation & **R**esponse.

Monorepo layout:

- `packages/backend` — FastAPI + LangGraph Python service (`specter` package)
- `frontend` — Next.js 15 dashboard (React 19, Tailwind, shadcn/ui)
- `infrastructure/aws` — optional IaC placeholders

## Prerequisites

- Python 3.12+
- [uv](https://docs.astral.sh/uv/) or `pip`
- Node.js 20+
- Docker (optional, for compose stack)

## Quick start (local)

1. Copy environment template and fill secrets:

   ```bash
   cp .env.example .env
   ```

2. Start Postgres + Redis:

   ```bash
   docker compose up -d db redis
   ```

3. Install and run the API:

   ```bash
   cd packages/backend && uv pip install -e ".[dev]" && cd ../..
   uvicorn specter.main:app --reload --app-dir packages/backend/src
   ```

   Or from `packages/backend` with `PYTHONPATH=src`:

   ```bash
   cd packages/backend
   uv pip install -e ".[dev]"
   PYTHONPATH=src uvicorn specter.main:app --reload --host 0.0.0.0 --port 8000
   ```

4. Install and run the dashboard (Next.js 15 / React 19; pinned to **15.2.8** for security patches):

   ```bash
   cd frontend && npm install && npm run dev
   ```

## Docker

```bash
docker compose up -d db redis
docker compose up backend
docker compose up frontend
```

The backend image installs the `specter` package from `packages/backend` into `/app` with `src` on `PYTHONPATH` via editable install.

## Organizational memory (PostgreSQL + pgvector)

After Postgres is up, create extensions and ORM tables once:

```bash
cd packages/backend
PYTHONPATH=src python -c "import asyncio; from specter.memory.db import init_db; asyncio.run(init_db())"
```

Uses **asyncpg** via `postgresql+asyncpg://` (see `specter.memory.db.make_async_database_url`). Embeddings default to OpenAI `text-embedding-3-small` (1536 dims) with a deterministic local fallback when `OPENAI_API_KEY` is unset.

## API

- `GET /` — service metadata
- `GET /health` — liveness
- `GET /api/v1/agents` — agent listing (stub)
- `POST /api/v1/memory/query` — semantic search over `memory_entities`
- `GET /api/v1/memory/entity/{entity_type}/{entity_id}` — fetch one entity
- WebSocket: `ws://localhost:8000/ws/events`

## Tests & CI

```bash
make test
# or
cd packages/backend && uv sync --all-extras && uv run pytest tests/ -v
```

GitHub Actions (`.github/workflows/ci.yml`): backend tests with Postgres + Redis services, Ruff lint, optional mypy (informational), frontend `npm ci` / lint / type-check / build.

One-shot local bootstrap:

```bash
./scripts/setup.sh
```

Load hackathon demo fixtures into memory (after DB is up):

```bash
make demo-data
```

## Makefile

| Target | Purpose |
|--------|---------|
| `make dev` | Start `db` + `redis` via Docker Compose |
| `make init-db` | Create pgvector tables (`init_db`) |
| `make demo-data` | Run `scripts/init_demo_data.py` |
| `make test` / `make test-cov` | Pytest (+ coverage HTML) |
| `make lint` / `make format` | Ruff |
| `make build` | `docker compose build` |
| `make deploy-vercel` | `vercel --prod` from `frontend/` |

## CLI helper (`gh`, Docker, `uv`, npm, Vercel)

From repo root, use **`./scripts/specter`** for common flows (see `./scripts/specter help`). Examples: `./scripts/specter status`, `./scripts/specter ci`, `./scripts/specter backend-test`.

## Next

See **Prompt 04** — MCP router and protocol infrastructure. Agents can load context with `get_knowledge_graph().get_context_for_incident(...)`.
