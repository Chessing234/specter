"""FastAPI entry point for SPECTER."""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from specter.api import agents, health, incidents, memory, websocket
from specter.config import get_settings
from specter.services.runtime import bootstrap_specter

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    print(f"Starting {settings.app_name} in {settings.environment} mode")
    await bootstrap_specter(app)
    yield
    for task in getattr(app.state, "background_tasks", set()):
        task.cancel()
    print(f"Shutting down {settings.app_name}")


app = FastAPI(
    title="SPECTER API",
    description="Security Protocol for Executable Contextual Threat Evaluation & Response",
    version="0.1.0",
    lifespan=lifespan,
)

# CORS — Starlette does not expand "*" in allow_origins; use regex for Vercel previews
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_origin_regex=r"https://.*\.vercel\.app",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Routers
app.include_router(health.router, tags=["Health"])
app.include_router(agents.router, prefix="/api/v1/agents", tags=["Agents"])
app.include_router(incidents.router, prefix="/api/v1/incidents", tags=["Incidents"])
app.include_router(memory.router, prefix="/api/v1/memory", tags=["Memory"])
app.include_router(websocket.router, prefix="/ws", tags=["WebSocket"])


@app.get("/")
async def root():
    return {
        "name": settings.app_name,
        "version": "0.1.0",
        "status": "operational",
        "environment": settings.environment,
    }
