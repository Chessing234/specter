"""Knowledge graph operations - CRUD and queries."""

from __future__ import annotations

import uuid
from typing import Any, cast

from sqlalchemy import case, or_, select

from specter.memory.db import get_session
from specter.memory.embedding import get_embedding_service
from specter.memory.models import (
    IncidentHistoryORM,
    MemoryEntityORM,
    MemoryRelationshipORM,
    UserBaselineORM,
)
from specter.models.memory import MemoryEntity


def _uuid(value: str | uuid.UUID) -> uuid.UUID:
    return value if isinstance(value, uuid.UUID) else uuid.UUID(str(value))


class KnowledgeGraph:
    """
    Organizational Memory Fabric — graph CRUD, vector search, and agent context.
    """

    async def create_entity(self, entity: MemoryEntity) -> MemoryEntityORM:
        """Create a new entity in the knowledge graph."""
        embedding_text = f"{entity.name} {entity.entity_type} {entity.properties!s}"
        embedding_service = get_embedding_service()
        vector = await embedding_service.embed(embedding_text)

        eid = uuid.UUID(entity.id) if entity.id else uuid.uuid4()

        async with get_session() as session:
            orm_entity = MemoryEntityORM(
                id=eid,
                entity_type=entity.entity_type.value,
                name=entity.name,
                properties=dict(entity.properties),
                vector_embedding=vector,
                source=entity.source,
                confidence=entity.confidence,
                last_seen=entity.last_seen,
            )
            session.add(orm_entity)
            await session.flush()
            await session.refresh(orm_entity)
            return orm_entity

    async def get_entity(self, entity_id: str) -> dict[str, Any] | None:
        """Get an entity by ID."""
        async with get_session() as session:
            result = await session.execute(
                select(MemoryEntityORM).where(MemoryEntityORM.id == _uuid(entity_id))
            )
            entity = result.scalar_one_or_none()
            return entity.to_dict() if entity else None

    async def find_entities(
        self,
        entity_type: str | None = None,
        name_pattern: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Find entities by type and/or name."""
        async with get_session() as session:
            query = select(MemoryEntityORM)
            if entity_type:
                query = query.where(MemoryEntityORM.entity_type == entity_type)
            if name_pattern:
                query = query.where(MemoryEntityORM.name.ilike(f"%{name_pattern}%"))
            query = query.limit(limit)
            result = await session.execute(query)
            return [e.to_dict() for e in result.scalars().all()]

    async def semantic_search(
        self,
        query_text: str,
        entity_type: str | None = None,
        limit: int = 10,
        min_similarity: float = 0.7,
    ) -> list[dict[str, Any]]:
        """Semantic search using pgvector cosine distance."""
        embedding_service = get_embedding_service()
        query_vector = await embedding_service.embed(query_text)

        async with get_session() as session:
            dist = MemoryEntityORM.vector_embedding.cosine_distance(query_vector)
            similarity = (1.0 - dist).label("similarity")

            stmt = (
                select(
                    MemoryEntityORM.id,
                    MemoryEntityORM.entity_type,
                    MemoryEntityORM.name,
                    MemoryEntityORM.properties,
                    MemoryEntityORM.source,
                    MemoryEntityORM.confidence,
                    MemoryEntityORM.updated_at,
                    similarity,
                )
                .where(MemoryEntityORM.vector_embedding.isnot(None))
                .where(dist <= (1.0 - min_similarity))
            )
            if entity_type:
                stmt = stmt.where(MemoryEntityORM.entity_type == entity_type)
            stmt = stmt.order_by(dist).limit(limit)

            rows = (await session.execute(stmt)).all()
            return [
                {
                    "id": str(row.id),
                    "entity_type": row.entity_type,
                    "name": row.name,
                    "properties": row.properties,
                    "source": row.source,
                    "confidence": row.confidence,
                    "similarity": float(row.similarity),
                    "updated_at": row.updated_at.isoformat() if row.updated_at else "",
                }
                for row in rows
            ]

    async def create_relationship(
        self,
        source_id: str,
        target_id: str,
        relationship_type: str,
        properties: dict[str, Any] | None = None,
        confidence: float = 1.0,
    ) -> MemoryRelationshipORM:
        """Create a relationship between two entities."""
        rtype = (
            relationship_type.value
            if hasattr(relationship_type, "value")
            else str(relationship_type)
        )
        async with get_session() as session:
            rel = MemoryRelationshipORM(
                source_id=_uuid(source_id),
                target_id=_uuid(target_id),
                relationship_type=rtype,
                properties=dict(properties or {}),
                confidence=confidence,
            )
            session.add(rel)
            await session.flush()
            await session.refresh(rel)
            return rel

    async def get_related_entities(
        self,
        entity_id: str,
        relationship_type: str | None = None,
    ) -> list[dict[str, Any]]:
        """Return neighbor entities connected by an edge to ``entity_id``."""
        eid = _uuid(entity_id)
        rel_orm = MemoryRelationshipORM
        ent_orm = MemoryEntityORM

        neighbor_id = case(
            (rel_orm.source_id == eid, rel_orm.target_id),
            else_=rel_orm.source_id,
        )

        stmt = (
            select(ent_orm)
            .join(rel_orm, or_(rel_orm.source_id == eid, rel_orm.target_id == eid))
            .where(ent_orm.id == neighbor_id)
        )
        if relationship_type:
            stmt = stmt.where(rel_orm.relationship_type == relationship_type)

        async with get_session() as session:
            result = await session.execute(stmt)
            return [row.to_dict() for row in result.scalars().all()]

    async def get_context_for_incident(self, incident: dict[str, Any]) -> dict[str, Any]:
        """Assemble organizational context for an incident."""
        context: dict[str, Any] = {
            "related_entities": [],
            "similar_incidents": [],
            "user_baselines": [],
            "threat_intel": [],
        }

        search_parts: list[str] = []
        if incident.get("description"):
            search_parts.append(str(incident["description"]))
        raw = cast(dict[str, Any], incident.get("raw_data") or {})
        if raw.get("user"):
            search_parts.append(f"user {raw['user']}")
        if raw.get("ip"):
            search_parts.append(f"IP {raw['ip']}")
        if raw.get("host"):
            search_parts.append(f"host {raw['host']}")

        search_query = " ".join(search_parts) or str(incident.get("title", ""))

        context["related_entities"] = await self.semantic_search(
            query_text=search_query,
            limit=20,
            min_similarity=0.5,
        )
        context["similar_incidents"] = await self.semantic_search(
            query_text=search_query,
            entity_type="incident",
            limit=5,
            min_similarity=0.6,
        )

        if raw.get("user"):
            async with get_session() as session:
                result = await session.execute(
                    select(UserBaselineORM).where(UserBaselineORM.user_id == str(raw["user"]))
                )
                baseline = result.scalar_one_or_none()
                if baseline:
                    context["user_baselines"].append(baseline.to_dict())

        return context

    async def upsert_user_baseline(self, baseline: dict[str, Any]) -> UserBaselineORM:
        """Create or update a user behavioral baseline."""
        async with get_session() as session:
            result = await session.execute(
                select(UserBaselineORM).where(UserBaselineORM.user_id == baseline["user_id"])
            )
            existing = result.scalar_one_or_none()

            if existing:
                for key, value in baseline.items():
                    if key in {"id"}:
                        continue
                    if hasattr(existing, key):
                        setattr(existing, key, value)
                await session.flush()
                await session.refresh(existing)
                return existing

            new_baseline = UserBaselineORM(
                user_id=baseline["user_id"],
                typical_login_times=list(baseline.get("typical_login_times", [])),
                typical_locations=list(baseline.get("typical_locations", [])),
                typical_devices=list(baseline.get("typical_devices", [])),
                accessed_assets=list(baseline.get("accessed_assets", [])),
                risk_score=float(baseline.get("risk_score", 0.0)),
            )
            session.add(new_baseline)
            await session.flush()
            await session.refresh(new_baseline)
            return new_baseline

    async def record_incident(self, incident: dict[str, Any]) -> IncidentHistoryORM:
        """Persist a resolved incident for future similarity search."""
        embedding_service = get_embedding_service()
        summary = str(incident.get("summary") or incident.get("description") or "")
        vector = await embedding_service.embed(summary)

        async with get_session() as session:
            record = IncidentHistoryORM(
                incident_id=str(incident["id"]),
                title=str(incident["title"]),
                incident_type=str(incident.get("incident_type", "unknown")),
                severity=str(incident.get("severity", "medium")),
                status=str(incident.get("status", "resolved")),
                summary=summary,
                indicators=list(incident.get("indicators", [])),
                vector_embedding=vector,
            )
            session.add(record)
            await session.flush()
            await session.refresh(record)
            return record


_knowledge_graph: KnowledgeGraph | None = None


def get_knowledge_graph() -> KnowledgeGraph:
    global _knowledge_graph
    if _knowledge_graph is None:
        _knowledge_graph = KnowledgeGraph()
    return _knowledge_graph
