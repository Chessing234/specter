FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    gcc \
    postgresql-client \
    libpq-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

RUN pip install uv

COPY packages/backend/pyproject.toml .
COPY packages/backend/src ./src

RUN uv pip install --system -e ".[dev]"

EXPOSE 8000

CMD ["sh", "-c", "uvicorn specter.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
