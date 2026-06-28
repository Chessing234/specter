"""Incident persistence with PostgreSQL and in-memory fallback."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select

from specter.memory.db import get_session
from specter.memory.models import IncidentORM
from specter.models.incident import Incident, IncidentStatus, Severity


def _utcnow() -> datetime:
    return datetime.now(UTC)


class IncidentStore:
    """CRUD for incidents; falls back to in-memory storage when DB is unavailable."""

    def __init__(self) -> None:
        self._memory: dict[str, dict[str, Any]] = {}
        self._db_available = True

    async def create(
        self,
        *,
        title: str,
        description: str,
        severity: str,
        source: str,
        raw_data: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        incident_id = str(uuid.uuid4())
        now = _utcnow()
        record = {
            "id": incident_id,
            "title": title,
            "description": description,
            "severity": severity,
            "status": IncidentStatus.NEW.value,
            "source": source,
            "raw_data": raw_data or {},
            "assigned_agent": "sentry",
            "confidence_score": 0.0,
            "workflow_state": None,
            "created_at": now.isoformat(),
            "updated_at": now.isoformat(),
            "resolved_at": None,
        }

        if self._db_available:
            try:
                async with get_session() as session:
                    orm = IncidentORM(
                        id=uuid.UUID(incident_id),
                        title=title,
                        description=description,
                        severity=severity,
                        status=IncidentStatus.NEW.value,
                        source=source,
                        raw_data=raw_data or {},
                        assigned_agent="sentry",
                        confidence_score=0.0,
                    )
                    session.add(orm)
                    await session.flush()
                    record = orm.to_dict()
            except Exception:
                self._db_available = False
                self._memory[incident_id] = record
        else:
            self._memory[incident_id] = record

        return record

    async def list_all(self, limit: int = 100) -> list[dict[str, Any]]:
        if self._db_available:
            try:
                async with get_session() as session:
                    result = await session.execute(
                        select(IncidentORM).order_by(IncidentORM.created_at.desc()).limit(limit)
                    )
                    return [row.to_dict() for row in result.scalars().all()]
            except Exception:
                self._db_available = False

        rows = list(self._memory.values())
        rows.sort(key=lambda r: r.get("created_at", ""), reverse=True)
        return rows[:limit]

    async def get(self, incident_id: str) -> dict[str, Any] | None:
        if self._db_available:
            try:
                async with get_session() as session:
                    result = await session.execute(
                        select(IncidentORM).where(IncidentORM.id == uuid.UUID(incident_id))
                    )
                    row = result.scalar_one_or_none()
                    if row:
                        return row.to_dict()
            except Exception:
                self._db_available = False

        return self._memory.get(incident_id)

    async def update(
        self,
        incident_id: str,
        *,
        status: str | None = None,
        assigned_agent: str | None = None,
        confidence_score: float | None = None,
        workflow_state: dict[str, Any] | None = None,
        resolved_at: datetime | None = None,
    ) -> dict[str, Any] | None:
        record = await self.get(incident_id)
        if not record:
            return None

        if status is not None:
            record["status"] = status
        if assigned_agent is not None:
            record["assigned_agent"] = assigned_agent
        if confidence_score is not None:
            record["confidence_score"] = confidence_score
        if workflow_state is not None:
            record["workflow_state"] = workflow_state
        if resolved_at is not None:
            record["resolved_at"] = resolved_at.isoformat()
        record["updated_at"] = _utcnow().isoformat()

        if self._db_available:
            try:
                async with get_session() as session:
                    result = await session.execute(
                        select(IncidentORM).where(IncidentORM.id == uuid.UUID(incident_id))
                    )
                    orm = result.scalar_one_or_none()
                    if orm:
                        if status is not None:
                            orm.status = status
                        if assigned_agent is not None:
                            orm.assigned_agent = assigned_agent
                        if confidence_score is not None:
                            orm.confidence_score = confidence_score
                        if workflow_state is not None:
                            orm.workflow_state = workflow_state
                        if resolved_at is not None:
                            orm.resolved_at = resolved_at
                        await session.flush()
                        await session.refresh(orm)
                        return orm.to_dict()
            except Exception:
                self._db_available = False

        self._memory[incident_id] = record
        return record

    def to_incident_model(self, record: dict[str, Any]) -> Incident:
        created = record.get("created_at")
        updated = record.get("updated_at")
        resolved = record.get("resolved_at")

        return Incident(
            id=record["id"],
            title=record["title"],
            description=record["description"],
            severity=Severity(record["severity"]),
            status=IncidentStatus(record.get("status", "new")),
            source=record["source"],
            raw_data=record.get("raw_data") or {},
            assigned_agent=record.get("assigned_agent"),
            confidence_score=float(record.get("confidence_score") or 0.0),
            created_at=datetime.fromisoformat(created) if isinstance(created, str) else _utcnow(),
            updated_at=datetime.fromisoformat(updated) if isinstance(updated, str) else _utcnow(),
            resolved_at=datetime.fromisoformat(resolved)
            if isinstance(resolved, str)
            else None,
        )


_store: IncidentStore | None = None


def get_incident_store() -> IncidentStore:
    global _store
    if _store is None:
        _store = IncidentStore()
    return _store
