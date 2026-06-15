"""Tests for Organizational Memory Fabric (unit-level, no live Postgres required)."""

import pytest

from specter.memory.db import make_async_database_url
from specter.memory.embedding import EmbeddingService


def test_make_async_database_url() -> None:
    assert make_async_database_url("postgresql://u:p@localhost:5432/db").startswith(
        "postgresql+asyncpg://"
    )
    assert make_async_database_url("postgres://u:p@localhost/db").startswith(
        "postgresql+asyncpg://"
    )


@pytest.mark.asyncio
async def test_embedding_fallback_vectors(monkeypatch: pytest.MonkeyPatch) -> None:
    from specter.config import get_settings

    settings = get_settings()
    monkeypatch.setattr(settings, "openai_api_key", None)

    svc = EmbeddingService()
    vec = await svc.embed("hello world")
    assert len(vec) == EmbeddingService.EMBEDDING_DIM

    batch = await svc.embed_batch(["a", "b"])
    assert len(batch) == 2
    assert all(len(v) == EmbeddingService.EMBEDDING_DIM for v in batch)
