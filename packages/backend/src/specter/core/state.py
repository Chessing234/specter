"""Shared state management for the LangGraph agent orchestration."""

from __future__ import annotations

import operator
from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from specter.models.agent import AgentAction, AgentMessage, AgentState
from specter.models.evidence import AuditLogEntry, Evidence
from specter.models.incident import Finding, Incident

Phase = Literal[
    "detection",
    "triage",
    "investigation",
    "command",
    "remediation",
    "audit",
    "complete",
    "error",
]


class SpecterState(BaseModel):
    """
    Shared orchestration state for LangGraph.

    List-like fields use ``Annotated[..., operator.add]`` so nodes can return
    partial updates (for example ``{"messages": [msg]}``) and LangGraph merges
    them. Scalar fields use last-write wins semantics.
    """

    model_config = ConfigDict(extra="ignore", arbitrary_types_allowed=True)

    incident: Incident | None = None

    agent_states: dict[str, AgentState] = Field(default_factory=dict)

    messages: Annotated[list[AgentMessage], operator.add] = Field(default_factory=list)
    actions: Annotated[list[AgentAction], operator.add] = Field(default_factory=list)
    evidence: Annotated[list[Evidence], operator.add] = Field(default_factory=list)
    findings: Annotated[list[Finding], operator.add] = Field(default_factory=list)
    audit_log: Annotated[list[AuditLogEntry], operator.add] = Field(default_factory=list)

    current_phase: Phase = "detection"

    iteration_count: int = 0
    max_iterations: int = 10
    corrections_made: Annotated[list[dict[str, Any]], operator.add] = Field(default_factory=list)

    validation_errors: list[str] = Field(default_factory=list)
    requires_human_review: bool = False

    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    completed_at: datetime | None = None

    memory_context: dict[str, Any] = Field(default_factory=dict)

    def model_dump_json_compatible(self) -> dict[str, Any]:
        """JSON-friendly dump for debugging / external serializers."""
        return self.model_dump(mode="json")

    def add_message(self, message: AgentMessage) -> dict[str, Any]:
        """Partial state update with a new bus message."""
        return {"messages": [message]}

    def add_action(self, action: AgentAction) -> dict[str, Any]:
        return {"actions": [action]}

    def add_evidence(self, evidence: Evidence) -> dict[str, Any]:
        return {"evidence": [evidence]}

    def add_finding(self, finding: Finding) -> dict[str, Any]:
        return {"findings": [finding]}

    def increment_iteration(self) -> dict[str, Any]:
        return {"iteration_count": self.iteration_count + 1}

    def set_phase(self, phase: Phase) -> dict[str, Any]:
        return {"current_phase": phase}

    def mark_complete(self) -> dict[str, Any]:
        return {
            "current_phase": "complete",
            "completed_at": datetime.now(UTC),
        }
