"""Agent management endpoints."""

from typing import Literal

from fastapi import APIRouter, HTTPException, Request
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
async def list_agents(request: Request):
    """List all available agents and their status."""
    tracker = request.app.state.agent_tracker
    return tracker.list_status()


@router.post("/{agent_name}/invoke")
async def invoke_agent(agent_name: str, request_body: AgentActionRequest, request: Request):
    """Invoke a single agent with context (manual demo mode)."""
    engine = request.app.state.engine
    agent = engine._agent_instances.get(agent_name.lower())  # noqa: SLF001
    if not agent:
        raise HTTPException(status_code=404, detail=f"Agent '{agent_name}' not found")

    ctx = request_body.context or {}
    try:
        from specter.models.incident import Incident, Severity

        incident = Incident(
            id=ctx.get("incident_id", "manual-invoke"),
            title=ctx.get("title", f"Manual {agent_name.upper()} invoke"),
            description=ctx.get("description", ""),
            severity=Severity(ctx.get("severity", "high")),
            source=ctx.get("source", "manual"),
            raw_data=ctx.get("raw_data", {}),
        )
        findings = ctx.get("findings", [])

        if agent_name.lower() == "sentry":
            result = await agent.process(incident, ctx.get("memory_context"))
        elif agent_name.lower() == "triage":
            result = await agent.process(
                incident,
                ctx.get("detection_result"),
                ctx.get("memory_context"),
            )
        elif agent_name.lower() == "sherlock":
            result = await agent.process(
                incident,
                ctx.get("triage_result"),
                ctx.get("evidence"),
                ctx.get("memory_context"),
            )
        elif agent_name.lower() == "commander":
            result = await agent.process(incident, findings, ctx.get("evidence", []))
        elif agent_name.lower() == "patch":
            result = await agent.process(incident, findings)
        elif agent_name.lower() == "audit":
            result = await agent.process(incident, findings, ctx.get("actions", []))
        else:
            raise HTTPException(status_code=400, detail="Unsupported agent")
        return {"agent": agent_name, "result": result}
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/{agent_name}/status", response_model=AgentStatusResponse)
async def get_agent_status(agent_name: str, request: Request):
    """Get status of a specific agent."""
    tracker = request.app.state.agent_tracker
    agents = {a["name"]: a for a in tracker.list_status()}
    agent = agents.get(agent_name.lower())
    if not agent:
        raise HTTPException(status_code=404, detail=f"Agent '{agent_name}' not found")
    return agent
