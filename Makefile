.PHONY: help dev test test-cov lint format build clean init-db demo-data deploy-vercel

help:
	@echo "SPECTER — development commands"
	@echo "  make dev        Start Postgres + Redis (docker compose)"
	@echo "  make test       Run backend pytest suite"
	@echo "  make test-cov   Run tests with HTML coverage report"
	@echo "  make lint       Ruff check + format check (backend)"
	@echo "  make format     Ruff format + auto-fix (backend)"
	@echo "  make init-db    Create extensions + ORM tables (Postgres)"
	@echo "  make demo-data  Load demo_data/*.json into memory fabric"
	@echo "  make build      Build docker images (compose)"
	@echo "  make deploy-vercel  Deploy frontend (requires Vercel CLI)"
	@echo "  make clean      Stop compose volumes + remove local frontend build"

dev:
	docker compose up -d db redis
	@echo "Postgres: postgresql://specter:specter@localhost:5432/specter"
	@echo "Redis:    redis://localhost:6379/0"
	@echo "Backend:  cd packages/backend && uv run uvicorn specter.main:app --reload"
	@echo "Frontend: cd frontend && npm run dev"

init-db:
	cd packages/backend && uv run python -c "import asyncio; from specter.memory.db import init_db; asyncio.run(init_db())"

demo-data: init-db
	cd packages/backend && uv run python ../../scripts/init_demo_data.py

test:
	cd packages/backend && uv run pytest tests/ -v

test-cov:
	cd packages/backend && uv run pytest tests/ -v --cov=specter --cov-report=html

lint:
	cd packages/backend && uv run ruff check src/ tests/ && uv run ruff format --check src/ tests/

format:
	cd packages/backend && uv run ruff format src/ tests/ && uv run ruff check --fix src/ tests/

build:
	docker compose build

deploy-vercel:
	cd frontend && npx vercel --prod

clean:
	docker compose down -v || true
	rm -rf frontend/.next frontend/node_modules packages/backend/.pytest_cache packages/backend/htmlcov
