"""Health check endpoints."""

from fastapi import APIRouter

router = APIRouter()


@router.get("/health")
async def health_check():
    """Basic health check."""
    return {"status": "healthy", "service": "specter"}


@router.get("/health/detailed")
async def detailed_health():
    """Detailed health check with component status."""
    return {
        "status": "healthy",
        "components": {
            "api": "up",
            "database": "up",  # TODO: actual DB check
            "redis": "up",  # TODO: actual Redis check
        },
    }
