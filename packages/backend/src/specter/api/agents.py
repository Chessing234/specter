"""Agent management endpoints."""

from typing import Literal

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter()


class AgentActionRequest(BaseModel):
    agent_name: str
    action: str
    context: dict | None = None


class AgentStatusResponse(BaseModel):
    name: str
    status: Literal["idle", "running", "error", "disabled"]
    last_action: str | None
    capabilities: list[str]


@router.get("/", response_model=list[AgentStatusResponse])
async def list_agents():
    """List all available agents and their status."""
    # TODO: Integrate with core engine (Prompt 02)
    return []


@router.post("/{agent_name}/invoke")
async def invoke_agent(agent_name: str, request: AgentActionRequest):
    """Invoke a specific agent with context."""
    # TODO: Integrate with core engine (Prompt 02)
    raise HTTPException(status_code=501, detail="Not yet implemented")


@router.get("/{agent_name}/status")
async def get_agent_status(agent_name: str):
    """Get status of a specific agent."""
    # TODO: Integrate with core engine (Prompt 02)
    raise HTTPException(status_code=501, detail="Not yet implemented")
