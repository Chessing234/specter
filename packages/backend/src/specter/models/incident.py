"""Incident-related Pydantic models."""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


def _utcnow() -> datetime:
    return datetime.now(UTC)


class Severity(StrEnum):
    """Incident severity levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IncidentStatus(StrEnum):
    """Incident lifecycle status."""

    NEW = "new"
    TRIAGING = "triaging"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    CLOSED = "closed"


class Incident(BaseModel):
    """A security incident."""

    id: str = Field(..., description="Unique incident ID (UUID)")
    title: str
    description: str
    severity: Severity
    status: IncidentStatus = IncidentStatus.NEW
    source: str = Field(..., description="Alert source (e.g., 'splunk', 'sift', 'manual')")
    raw_data: dict[str, Any] = Field(default_factory=dict)
    findings: list[dict[str, Any]] = Field(default_factory=list)
    assigned_agent: str | None = None
    confidence_score: float = Field(default=0.0, ge=0.0, le=1.0)
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)
    resolved_at: datetime | None = None


class Finding(BaseModel):
    """A finding within an incident."""

    id: str
    incident_id: str
    agent: str
    finding_type: str
    description: str
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)
    verified: bool = False
    created_at: datetime = Field(default_factory=_utcnow)
