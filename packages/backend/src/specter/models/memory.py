"""Organizational Memory Fabric models."""

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class EntityType(StrEnum):
    """Types of entities in the knowledge graph."""

    ASSET = "asset"
    USER = "user"
    APPLICATION = "application"
    THREAT_ACTOR = "threat_actor"
    INCIDENT = "incident"
    POLICY = "policy"
    COMPLIANCE_CONTROL = "compliance_control"


class RelationshipType(StrEnum):
    """Types of relationships between entities."""

    CONNECTS_TO = "connects_to"
    HAS_ACCESS = "has_access"
    DEPENDS_ON = "depends_on"
    OWNS = "owns"
    SIMILAR_TO = "similar_to"
    PREVIOUSLY_INVOLVED_IN = "previously_involved_in"
    VIOLATES = "violates"
    COMPLIES_WITH = "complies_with"


class MemoryEntity(BaseModel):
    """An entity in the organizational memory."""

    id: str | None = None
    entity_type: EntityType
    name: str
    properties: dict[str, Any] = Field(default_factory=dict)
    vector_embedding: list[float] | None = None
    source: str = "manual"
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime | None = None


class MemoryRelationship(BaseModel):
    """A relationship between two memory entities."""

    id: str
    source_id: str
    target_id: str
    relationship_type: RelationshipType
    properties: dict[str, Any] = Field(default_factory=dict)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    created_at: datetime = Field(default_factory=datetime.utcnow)


class UserBaseline(BaseModel):
    """Behavioral baseline for a user."""

    user_id: str
    typical_login_times: list[str] = Field(default_factory=list)
    typical_locations: list[str] = Field(default_factory=list)
    typical_devices: list[str] = Field(default_factory=list)
    accessed_assets: list[str] = Field(default_factory=list)
    risk_score: float = Field(default=0.0, ge=0.0, le=1.0)
    last_access_review: datetime | None = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
