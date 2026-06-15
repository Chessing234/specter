"""Pytest configuration and fixtures."""

from unittest.mock import MagicMock

import pytest


@pytest.fixture
def mock_settings():
    """Mock settings for testing."""
    from specter.config import Settings

    return Settings(
        environment="testing",
        database_url="postgresql://specter:specter@localhost:5432/specter_test",
        openai_api_key="test-key",
    )


@pytest.fixture
def mock_llm():
    """Mock LLM for testing."""
    mock = MagicMock()
    mock.ainvoke.return_value = MagicMock(content="Mock LLM response")
    return mock


@pytest.fixture
def sample_incident_data():
    """Sample incident data for tests."""
    return {
        "title": "Suspicious Login Detected",
        "description": "User admin logged in from unusual IP at 3:47 AM",
        "severity": "high",
        "source": "splunk",
        "raw_data": {
            "user": "admin",
            "ip": "185.220.101.7",
            "timestamp": "2026-06-10T03:47:00Z",
            "location": "Moscow, Russia",
        },
    }
