"""Evidence and audit trail models."""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


def _utcnow() -> datetime:
    return datetime.now(UTC)


class EvidenceType(StrEnum):
    """Categories of forensic or analytical evidence."""

    TOOL_OUTPUT = "tool_output"
    LOG_ENTRY = "log_entry"
    FILE_HASH = "file_hash"
    NETWORK_CAPTURE = "network_capture"
    AGENT_REASONING = "agent_reasoning"
    CORRELATION = "correlation"


class Evidence(BaseModel):
    """A piece of evidence collected during investigation."""

    id: str
    incident_id: str
    agent: str
    evidence_type: EvidenceType
    source_tool: str | None = None
    raw_data: dict[str, Any]
    interpreted_data: dict[str, Any] | None = None
    chain_of_custody: list[dict[str, Any]] = Field(default_factory=list)
    collected_at: datetime = Field(default_factory=_utcnow)
    integrity_hash: str | None = None


class AuditLogEntry(BaseModel):
    """An entry in the audit trail."""

    id: str
    timestamp: datetime = Field(default_factory=_utcnow)
    agent: str
    action: str
    target: str | None = None
    input_params: dict[str, Any] | None = None
    output: dict[str, Any] | None = None
    tokens_used: int | None = None
    duration_ms: int | None = None
    correlation_id: str | None = None
