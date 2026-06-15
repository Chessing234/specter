"""Tests for the LangGraph orchestration engine."""

from unittest.mock import AsyncMock

import pytest

from specter.core.engine import SpecterEngine
from specter.models.agent import AgentType
from specter.models.incident import Incident, Severity


@pytest.fixture
def engine() -> SpecterEngine:
    return SpecterEngine()


@pytest.fixture
def mock_agents() -> dict[str, AsyncMock]:
    return {
        "sentry": AsyncMock(),
        "triage": AsyncMock(),
        "sherlock": AsyncMock(),
        "commander": AsyncMock(),
        "audit": AsyncMock(),
    }


@pytest.mark.asyncio
async def test_engine_registration(
    engine: SpecterEngine,
    mock_agents: dict[str, AsyncMock],
) -> None:
    for name, agent in mock_agents.items():
        engine.register_agent(AgentType(name), agent)

    assert len(engine._agent_instances) == 5


@pytest.mark.asyncio
async def test_full_workflow(
    engine: SpecterEngine,
    mock_agents: dict[str, AsyncMock],
    sample_incident_data: dict,
) -> None:
    for name, agent in mock_agents.items():
        agent.process.return_value = {"status": "completed", "findings": []}
        engine.register_agent(AgentType(name), agent)

    incident = Incident(
        id="test-incident-1",
        title=sample_incident_data["title"],
        description=sample_incident_data["description"],
        severity=Severity(sample_incident_data["severity"]),
        source=sample_incident_data["source"],
        raw_data=sample_incident_data.get("raw_data", {}),
    )

    result = await engine.process_incident(incident)

    assert result.current_phase == "complete"
    assert result.iteration_count > 0
