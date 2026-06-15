"""Organizational memory query endpoints."""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from specter.memory.graph import get_knowledge_graph

router = APIRouter()


class MemoryQuery(BaseModel):
    query: str
    entity_type: str | None = None  # "asset", "user", "incident", etc.
    limit: int = 10


class MemoryEntry(BaseModel):
    id: str
    entity_type: str
    content: dict
    confidence: float
    source: str
    timestamp: str


@router.post("/query", response_model=list[MemoryEntry])
async def query_memory(query: MemoryQuery):
    """Semantic query against the memory fabric (pgvector)."""
    kg = get_knowledge_graph()
    rows = await kg.semantic_search(
        query_text=query.query,
        entity_type=query.entity_type,
        limit=query.limit,
        min_similarity=0.55,
    )
    return [
        MemoryEntry(
            id=r["id"],
            entity_type=r["entity_type"],
            content={
                "name": r["name"],
                "properties": r.get("properties") or {},
                "similarity": r.get("similarity"),
            },
            confidence=float(r["confidence"]),
            source=str(r["source"]),
            timestamp=str(r.get("updated_at", "")),
        )
        for r in rows
    ]


@router.get("/entity/{entity_type}/{entity_id}")
async def get_entity(entity_type: str, entity_id: str):
    """Fetch a single entity by id and type."""
    kg = get_knowledge_graph()
    row = await kg.get_entity(entity_id)
    if not row or row.get("entity_type") != entity_type:
        raise HTTPException(status_code=404, detail="Entity not found")
    return row
