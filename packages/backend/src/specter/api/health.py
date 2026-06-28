"""Health check endpoints."""

from fastapi import APIRouter
from sqlalchemy import text

from specter.config import get_settings

router = APIRouter()
settings = get_settings()


async def _check_database() -> str:
    try:
        from specter.memory.db import get_session

        async with get_session() as session:
            await session.execute(text("SELECT 1"))
        return "up"
    except Exception:
        return "down"


async def _check_redis() -> str:
    try:
        import redis.asyncio as aioredis

        client = aioredis.from_url(settings.redis_url, socket_connect_timeout=2)
        try:
            await client.ping()
            return "up"
        finally:
            await client.aclose()
    except Exception:
        return "down"


@router.get("/health")
async def health_check():
    """Basic health check."""
    return {"status": "healthy", "service": "specter"}


@router.get("/health/detailed")
async def detailed_health():
    """Detailed health check with component status."""
    db_status = await _check_database()
    redis_status = await _check_redis()
    components = {
        "api": "up",
        "database": db_status,
        "redis": redis_status,
    }
    overall = "healthy" if all(v == "up" for v in components.values()) else "degraded"
    return {"status": overall, "components": components}
