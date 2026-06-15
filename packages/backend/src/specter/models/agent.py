"""Agent-related Pydantic models."""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field


def _utcnow() -> datetime:
    return datetime.now(UTC)


class AgentType(StrEnum):
    """Available agent types."""

    SENTRY = "sentry"
    TRIAGE = "triage"
    SHERLOCK = "sherlock"
    COMMANDER = "commander"
    PATCH = "patch"
    AUDIT = "audit"


class AgentStatus(StrEnum):
    """Agent execution status."""

    IDLE = "idle"
    RUNNING = "running"
    ERROR = "error"
    DISABLED = "disabled"


class AgentMessage(BaseModel):
    """Inter-agent communication message."""

    id: str = Field(..., description="Unique message ID")
    from_agent: AgentType = Field(..., description="Source agent")
    to_agent: AgentType | None = Field(None, description="Target agent (None = broadcast)")
    message_type: Literal["task", "response", "alert", "status", "evidence"] = "task"
    content: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=_utcnow)
    priority: int = Field(default=5, ge=1, le=10, description="1 = highest, 10 = lowest")
    correlation_id: str | None = Field(None, description="Links related messages")


class AgentAction(BaseModel):
    """An action taken by an agent."""

    id: str
    agent: AgentType
    action_type: str
    tool_used: str | None = None
    input_params: dict[str, Any] = Field(default_factory=dict)
    output: dict[str, Any] | None = None
    started_at: datetime = Field(default_factory=_utcnow)
    completed_at: datetime | None = None
    status: Literal["pending", "running", "completed", "failed"] = "pending"
    error_message: str | None = None


class AgentState(BaseModel):
    """Current state of an agent."""

    agent: AgentType
    status: AgentStatus
    current_task: str | None = None
    last_action: AgentAction | None = None
    memory_context: dict[str, Any] = Field(default_factory=dict)
    iteration_count: int = 0
    max_iterations: int = 10
