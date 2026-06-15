"""Vector embedding generation and similarity search."""

from __future__ import annotations

import hashlib
from typing import Any

import httpx

from specter.config import get_settings

settings = get_settings()


class EmbeddingService:
    """
    Service for generating and managing vector embeddings.

    Uses OpenAI's text-embedding-3-small by default (1536 dimensions).
    Falls back to deterministic pseudo-vectors when no API key is configured.
    """

    EMBEDDING_DIM = 1536
    DEFAULT_MODEL = "text-embedding-3-small"

    def __init__(self) -> None:
        self.api_key = settings.openai_api_key
        self.model = self.DEFAULT_MODEL
        self._client: httpx.AsyncClient | None = None

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url="https://api.openai.com/v1",
                headers={"Authorization": f"Bearer {self.api_key}"},
                timeout=30.0,
            )
        return self._client

    async def embed(self, text: str) -> list[float]:
        """Generate embedding for a single text."""
        if not self.api_key:
            return self._fallback_embed(text)

        client = self._get_client()
        response = await client.post(
            "/embeddings",
            json={
                "input": text,
                "model": self.model,
            },
        )
        response.raise_for_status()
        data: dict[str, Any] = response.json()
        return list(data["data"][0]["embedding"])

    async def embed_batch(self, texts: list[str]) -> list[list[float]]:
        """Generate embeddings for multiple texts."""
        if not self.api_key:
            return [self._fallback_embed(t) for t in texts]

        client = self._get_client()
        response = await client.post(
            "/embeddings",
            json={
                "input": texts,
                "model": self.model,
            },
        )
        response.raise_for_status()
        data: dict[str, Any] = response.json()
        return [list(item["embedding"]) for item in data["data"]]

    def _fallback_embed(self, text: str) -> list[float]:
        """
        Deterministic pseudo-embedding for local development.

        Not semantically meaningful — replace with real embeddings in production.
        """
        digest = hashlib.sha256(text.encode()).digest()
        floats: list[float] = []
        for i in range(self.EMBEDDING_DIM):
            b = digest[i % len(digest)]
            floats.append((b / 255.0) * 2.0 - 1.0)
        return floats

    async def aclose(self) -> None:
        """Close the HTTP client."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None


_embedding_service: EmbeddingService | None = None


def get_embedding_service() -> EmbeddingService:
    """Singleton embedding service."""
    global _embedding_service
    if _embedding_service is None:
        _embedding_service = EmbeddingService()
    return _embedding_service
