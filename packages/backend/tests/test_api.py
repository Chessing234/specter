"""API integration tests for wired endpoints."""

from unittest.mock import AsyncMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from specter.main import app


@pytest.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest.mark.asyncio
async def test_list_agents_returns_fleet(client: AsyncClient) -> None:
    async with app.router.lifespan_context(app):
        response = await client.get("/api/v1/agents/")
    assert response.status_code == 200
    agents = response.json()
    assert len(agents) == 6
    names = {a["name"] for a in agents}
    assert names == {"sentry", "triage", "sherlock", "commander", "patch", "audit"}


@pytest.mark.asyncio
async def test_create_demo_incident(client: AsyncClient) -> None:
    async with app.router.lifespan_context(app):
        with patch(
            "specter.services.runtime.run_incident_pipeline",
            new_callable=AsyncMock,
        ):
            response = await client.post("/api/v1/incidents/demo")
    assert response.status_code == 201
    body = response.json()
    assert body["title"]
    assert body["id"]


@pytest.mark.asyncio
async def test_detailed_health(client: AsyncClient) -> None:
    async with app.router.lifespan_context(app):
        response = await client.get("/health/detailed")
    assert response.status_code == 200
    data = response.json()
    assert "components" in data
    assert "database" in data["components"]
