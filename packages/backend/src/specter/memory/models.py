"""SQLAlchemy ORM models for the Organizational Memory Fabric."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from pgvector.sqlalchemy import Vector
from sqlalchemy import (
    JSON,
    DateTime,
    Float,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from specter.memory.db import Base


def _utcnow() -> datetime:
    return datetime.now(UTC)


class MemoryEntityORM(Base):
    """An entity in the knowledge graph."""

    __tablename__ = "memory_entities"

    id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    entity_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    properties: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    vector_embedding: Mapped[list[float] | None] = mapped_column(Vector(1536), nullable=True)
    source: Mapped[str] = mapped_column(String(100), default="manual")
    confidence: Mapped[float] = mapped_column(Float, default=1.0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    outgoing_relationships: Mapped[list[MemoryRelationshipORM]] = relationship(
        "MemoryRelationshipORM",
        foreign_keys="MemoryRelationshipORM.source_id",
        back_populates="source",
        cascade="all, delete-orphan",
    )
    incoming_relationships: Mapped[list[MemoryRelationshipORM]] = relationship(
        "MemoryRelationshipORM",
        foreign_keys="MemoryRelationshipORM.target_id",
        back_populates="target",
        cascade="all, delete-orphan",
    )

    __table_args__ = (Index("ix_memory_entities_type_name", "entity_type", "name"),)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": str(self.id),
            "entity_type": self.entity_type,
            "name": self.name,
            "properties": self.properties or {},
            "source": self.source,
            "confidence": self.confidence,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
        }


class MemoryRelationshipORM(Base):
    """A relationship between two entities in the knowledge graph."""

    __tablename__ = "memory_relationships"

    id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    source_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("memory_entities.id"), nullable=False
    )
    target_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("memory_entities.id"), nullable=False
    )
    relationship_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    properties: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    confidence: Mapped[float] = mapped_column(Float, default=1.0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    source: Mapped[MemoryEntityORM] = relationship(
        "MemoryEntityORM",
        foreign_keys=[source_id],
        back_populates="outgoing_relationships",
    )
    target: Mapped[MemoryEntityORM] = relationship(
        "MemoryEntityORM",
        foreign_keys=[target_id],
        back_populates="incoming_relationships",
    )

    __table_args__ = (
        UniqueConstraint("source_id", "target_id", "relationship_type", name="uix_relationship"),
        Index("ix_memory_relationships_type", "relationship_type"),
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": str(self.id),
            "source_id": str(self.source_id),
            "target_id": str(self.target_id),
            "relationship_type": self.relationship_type,
            "properties": self.properties or {},
            "confidence": self.confidence,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class UserBaselineORM(Base):
    """Behavioral baseline for a user."""

    __tablename__ = "user_baselines"

    id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    user_entity_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("memory_entities.id"), nullable=True
    )
    typical_login_times: Mapped[list[Any]] = mapped_column(JSON, default=list)
    typical_locations: Mapped[list[Any]] = mapped_column(JSON, default=list)
    typical_devices: Mapped[list[Any]] = mapped_column(JSON, default=list)
    accessed_assets: Mapped[list[Any]] = mapped_column(JSON, default=list)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    last_access_review: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": str(self.id),
            "user_id": self.user_id,
            "typical_login_times": self.typical_login_times or [],
            "typical_locations": self.typical_locations or [],
            "typical_devices": self.typical_devices or [],
            "accessed_assets": self.accessed_assets or [],
            "risk_score": self.risk_score,
            "last_access_review": self.last_access_review.isoformat()
            if self.last_access_review
            else None,
        }


class IncidentHistoryORM(Base):
    """Historical incidents for pattern recognition."""

    __tablename__ = "incident_history"

    id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    incident_id: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    incident_type: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    indicators: Mapped[list[Any]] = mapped_column(JSON, default=list)
    vector_embedding: Mapped[list[float] | None] = mapped_column(Vector(1536), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (Index("ix_incident_history_type_severity", "incident_type", "severity"),)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": str(self.id),
            "incident_id": self.incident_id,
            "title": self.title,
            "incident_type": self.incident_type,
            "severity": self.severity,
            "status": self.status,
            "summary": self.summary,
            "indicators": self.indicators or [],
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
        }


class ComplianceControlORM(Base):
    """Compliance control state tracking."""

    __tablename__ = "compliance_controls"

    id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    control_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    framework: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="not_assessed")
    evidence_last_collected: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    evidence_summary: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    assigned_entity_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("memory_entities.id"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": str(self.id),
            "control_id": self.control_id,
            "framework": self.framework,
            "name": self.name,
            "status": self.status,
            "evidence_last_collected": self.evidence_last_collected.isoformat()
            if self.evidence_last_collected
            else None,
        }
