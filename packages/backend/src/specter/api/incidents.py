"""Incident management endpoints."""

from datetime import datetime
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from specter.services.runtime import DEMO_INCIDENT, schedule_incident_pipeline

router = APIRouter()


class IncidentCreate(BaseModel):
    title: str
    description: str
    severity: Literal["low", "medium", "high", "critical"]
    source: str
    raw_data: dict | None = None


class WorkflowMessage(BaseModel):
    id: str
    from_agent: str
    to_agent: str | None
    message_type: str
    content: dict[str, Any]
    timestamp: str
    priority: int = 5


class IncidentResponse(BaseModel):
    id: str
    title: str
    description: str
    severity: str
    status: str
    source: str
    created_at: datetime
    updated_at: datetime
    assigned_agent: str | None
    confidence_score: float = 0.0
    raw_data: dict[str, Any] = Field(default_factory=dict)
    current_phase: str | None = None
    messages: list[WorkflowMessage] = Field(default_factory=list)
    findings: list[dict[str, Any]] = Field(default_factory=list)
    memory_context: dict[str, Any] = Field(default_factory=dict)
    actions: list[dict[str, Any]] = Field(default_factory=list)


def _parse_dt(value: str | None) -> datetime:
    if not value:
        return datetime.now()
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _record_to_response(record: dict[str, Any]) -> IncidentResponse:
    workflow = record.get("workflow_state") or {}
    messages_raw = workflow.get("messages") or []

    messages = [
        WorkflowMessage(
            id=str(m.get("id", "")),
            from_agent=str(
                m.get("from_agent", "")
                if not isinstance(m.get("from_agent"), dict)
                else m.get("from_agent", {}).get("value", m.get("from_agent"))
            ),
            to_agent=(
                str(m["to_agent"])
                if m.get("to_agent") and not isinstance(m.get("to_agent"), dict)
                else (
                    str(m.get("to_agent", {}).get("value"))
                    if isinstance(m.get("to_agent"), dict)
                    else m.get("to_agent")
                )
            ),
            message_type=str(m.get("message_type", "")),
            content=m.get("content") if isinstance(m.get("content"), dict) else {},
            timestamp=str(m.get("timestamp", "")),
            priority=int(m.get("priority", 5)),
        )
        for m in messages_raw
        if isinstance(m, dict)
    ]

    return IncidentResponse(
        id=record["id"],
        title=record["title"],
        description=record["description"],
        severity=record["severity"],
        status=record["status"],
        source=record["source"],
        created_at=_parse_dt(record.get("created_at")),
        updated_at=_parse_dt(record.get("updated_at")),
        assigned_agent=record.get("assigned_agent"),
        confidence_score=float(record.get("confidence_score") or 0.0),
        raw_data=record.get("raw_data") or {},
        current_phase=workflow.get("current_phase"),
        messages=messages,
        findings=workflow.get("findings") or [],
        memory_context=workflow.get("memory_context") or {},
        actions=workflow.get("actions") or [],
    )


@router.get("/", response_model=list[IncidentResponse])
async def list_incidents(request: Request):
    """List all incidents."""
    store = request.app.state.incident_store
    records = await store.list_all()
    return [_record_to_response(r) for r in records]


@router.post("/", response_model=IncidentResponse, status_code=201)
async def create_incident(incident: IncidentCreate, request: Request):
    """Create a new incident and start the agent pipeline."""
    store = request.app.state.incident_store
    record = await store.create(
        title=incident.title,
        description=incident.description,
        severity=incident.severity,
        source=incident.source,
        raw_data=incident.raw_data,
    )
    schedule_incident_pipeline(request.app, record["id"])
    return _record_to_response(record)


@router.post("/demo", response_model=IncidentResponse, status_code=201)
async def create_demo_incident(request: Request):
    """Create a pre-built demo incident for hackathon presentations."""
    store = request.app.state.incident_store
    record = await store.create(
        title=DEMO_INCIDENT["title"],
        description=DEMO_INCIDENT["description"],
        severity=DEMO_INCIDENT["severity"],
        source=DEMO_INCIDENT["source"],
        raw_data=DEMO_INCIDENT["raw_data"],
    )
    schedule_incident_pipeline(request.app, record["id"])
    return _record_to_response(record)


@router.get("/{incident_id}", response_model=IncidentResponse)
async def get_incident(incident_id: str, request: Request):
    """Get incident details including workflow timeline."""
    store = request.app.state.incident_store
    record = await store.get(incident_id)
    if not record:
        raise HTTPException(status_code=404, detail="Incident not found")
    return _record_to_response(record)
