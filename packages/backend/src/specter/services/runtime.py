"""Runtime bootstrap — engine, MCP adapters, agent status, incident pipeline."""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime
from typing import Any

from fastapi import FastAPI

from specter.agents import (
    AuditAgent,
    CommanderAgent,
    PatchAgent,
    SentryAgent,
    SherlockAgent,
    TriageAgent,
)
from specter.core.engine import SpecterEngine
from specter.core.state import SpecterState
from specter.mcp import init_sift_adapter, init_sola_adapter, init_splunk_adapter
from specter.memory.db import init_db
from specter.memory.graph import get_knowledge_graph
from specter.models.agent import AgentMessage, AgentType
from specter.models.incident import IncidentStatus
from specter.services.incident_store import IncidentStore, get_incident_store

logger = logging.getLogger(__name__)

ALL_AGENTS = ("sentry", "triage", "sherlock", "commander", "patch", "audit")

DEFAULT_CAPABILITIES: dict[str, list[str]] = {
    "sentry": ["detection", "monitoring", "splunk_search", "threat_intel"],
    "triage": ["prioritization", "business_impact", "memory_context"],
    "sherlock": ["forensics", "SIFT", "splunk_correlation"],
    "commander": ["orchestration", "containment", "SLA"],
    "patch": ["remediation", "splunk_update_alert"],
    "audit": ["compliance", "Sola", "access_review"],
}

DEMO_INCIDENT: dict[str, Any] = {
    "title": "Crown Jewel Access — Impossible Travel & Lateral Movement",
    "description": (
        "Admin account admin@company.com authenticated from Moscow (185.220.101.7) at "
        "03:47 UTC — inconsistent with New York baseline. Subsequent SSH session to "
        "prod-db-01 (crown jewel database) detected within 12 minutes."
    ),
    "severity": "critical",
    "source": "splunk",
    "raw_data": {
        "user": "admin@company.com",
        "ip": "185.220.101.7",
        "timestamp": "2026-06-10T03:47:00Z",
        "location": "Moscow, Russia",
        "target_asset": "prod-db-01",
        "iocs": ["185.220.101.7", "malware.example.bad"],
        "event_type": "impossible_travel",
    },
}


class AgentStatusTracker:
    """Tracks live agent status for the dashboard API."""

    def __init__(self) -> None:
        self._status: dict[str, str] = dict.fromkeys(ALL_AGENTS, "idle")
        self._last_action: dict[str, str | None] = dict.fromkeys(ALL_AGENTS)
        self._capabilities: dict[str, list[str]] = dict(DEFAULT_CAPABILITIES)
        self._active_incidents: set[str] = set()

    def register_capabilities(self, agent_name: str, capabilities: list[str]) -> None:
        self._capabilities[agent_name] = capabilities

    def on_bus_message(self, message: AgentMessage) -> None:
        name = message.from_agent.value
        if name in self._status:
            self._status[name] = "running"
            self._last_action[name] = message.message_type

    def begin_incident(self, incident_id: str) -> None:
        self._active_incidents.add(incident_id)
        for name in ALL_AGENTS:
            if name != "patch":
                self._status[name] = "idle"

    def end_incident(self, incident_id: str) -> None:
        self._active_incidents.discard(incident_id)
        for name in ALL_AGENTS:
            self._status[name] = "idle"

    def set_agent_error(self, agent_name: str) -> None:
        self._status[agent_name] = "error"

    def list_status(self) -> list[dict[str, Any]]:
        return [
            {
                "name": name,
                "status": self._status.get(name, "idle"),
                "last_action": self._last_action.get(name),
                "capabilities": self._capabilities.get(name, []),
            }
            for name in ALL_AGENTS
        ]


def _status_from_phase(phase: str) -> str:
    mapping = {
        "detection": IncidentStatus.NEW.value,
        "triage": IncidentStatus.TRIAGING.value,
        "investigation": IncidentStatus.INVESTIGATING.value,
        "command": IncidentStatus.INVESTIGATING.value,
        "remediation": IncidentStatus.CONTAINED.value,
        "audit": IncidentStatus.INVESTIGATING.value,
        "complete": IncidentStatus.RESOLVED.value,
        "error": IncidentStatus.NEW.value,
    }
    return mapping.get(phase, IncidentStatus.INVESTIGATING.value)


def _extract_confidence(final_state: SpecterState) -> float:
    if final_state.incident and final_state.incident.confidence_score:
        return float(final_state.incident.confidence_score)

    for message in reversed(final_state.messages):
        content = message.content
        for key in ("detection_result", "triage_result", "investigation_result"):
            block = content.get(key)
            if isinstance(block, dict):
                for conf_key in ("confidence", "confidence_score", "priority_score"):
                    val = block.get(conf_key)
                    if isinstance(val, (int, float)):
                        return float(val) / 100.0 if val > 1 else float(val)
    return 0.0


def _phase_to_agent(phase: str) -> str:
    return {
        "detection": "sentry",
        "triage": "triage",
        "investigation": "sherlock",
        "command": "commander",
        "remediation": "patch",
        "audit": "audit",
    }.get(phase, "commander")


async def run_incident_pipeline(
    engine: SpecterEngine,
    store: IncidentStore,
    tracker: AgentStatusTracker,
    incident_id: str,
) -> None:
    """Process an incident through the LangGraph engine in the background."""
    record = await store.get(incident_id)
    if not record:
        return

    incident = store.to_incident_model(record)
    tracker.begin_incident(incident_id)

    await store.update(
        incident_id,
        status=IncidentStatus.TRIAGING.value,
        assigned_agent="sentry",
    )

    try:
        final_state = await engine.process_incident(incident)
        workflow = final_state.model_dump(mode="json")
        confidence = _extract_confidence(final_state)
        phase = str(final_state.current_phase)
        status = _status_from_phase(phase)

        resolved_at = datetime.now(UTC) if phase == "complete" else None

        await store.update(
            incident_id,
            status=status,
            assigned_agent=_phase_to_agent(phase),
            confidence_score=confidence,
            workflow_state=workflow,
            resolved_at=resolved_at,
        )

        if phase == "complete" and final_state.incident:
            try:
                kg = get_knowledge_graph()
                await kg.record_incident(
                    {
                        "id": incident_id,
                        "title": final_state.incident.title,
                        "description": final_state.incident.description,
                        "severity": final_state.incident.severity.value,
                        "status": status,
                        "incident_type": record.get("raw_data", {}).get("event_type", "unknown"),
                        "indicators": list(record.get("raw_data", {}).get("iocs", [])),
                        "summary": final_state.incident.description,
                    }
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning("Could not record incident to knowledge graph: %s", exc)

        from specter.api.websocket import broadcast_event

        await broadcast_event(
            {
                "type": "incident_complete",
                "incident_id": incident_id,
                "status": status,
                "phase": phase,
                "confidence_score": confidence,
            }
        )
    except Exception as exc:  # noqa: BLE001
        logger.exception("Incident pipeline failed for %s", incident_id)
        await store.update(
            incident_id,
            status="error",
            workflow_state={"error": str(exc)},
        )
        tracker.set_agent_error("commander")
    finally:
        tracker.end_incident(incident_id)


def _wire_bus_tracker(engine: SpecterEngine, tracker: AgentStatusTracker) -> None:
    original = engine.bus.broadcast_to_websocket

    async def wrapped(message: AgentMessage) -> None:
        tracker.on_bus_message(message)
        await original(message)

    engine.bus.broadcast_to_websocket = wrapped  # type: ignore[method-assign]


async def bootstrap_specter(app: FastAPI) -> None:
    """Initialize DB, MCP adapters, engine, and attach to app state."""
    try:
        await init_db()
        logger.info("Database initialized")
    except Exception as exc:  # noqa: BLE001
        logger.warning("Database init skipped (in-memory fallback): %s", exc)

    try:
        await init_splunk_adapter()
        await init_sift_adapter()
        await init_sola_adapter()
        logger.info("MCP adapters registered")
    except Exception as exc:  # noqa: BLE001
        logger.warning("MCP adapter init partial failure: %s", exc)

    engine = SpecterEngine()
    agents: list[tuple[AgentType, Any]] = [
        (AgentType.SENTRY, SentryAgent()),
        (AgentType.TRIAGE, TriageAgent()),
        (AgentType.SHERLOCK, SherlockAgent()),
        (AgentType.COMMANDER, CommanderAgent()),
        (AgentType.PATCH, PatchAgent()),
        (AgentType.AUDIT, AuditAgent()),
    ]
    for agent_type, instance in agents:
        engine.register_agent(agent_type, instance)

    tracker = AgentStatusTracker()
    for agent_type, instance in agents:
        caps = instance.get_capabilities() if hasattr(instance, "get_capabilities") else []
        tracker.register_capabilities(agent_type.value, caps)

    _wire_bus_tracker(engine, tracker)

    store = get_incident_store()
    app.state.engine = engine
    app.state.incident_store = store
    app.state.agent_tracker = tracker
    app.state.background_tasks: set[asyncio.Task[Any]] = set()

    logger.info("SPECTER runtime ready — %d agents registered", len(agents))


def schedule_incident_pipeline(app: FastAPI, incident_id: str) -> None:
    """Fire-and-forget background processing for an incident."""
    task = asyncio.create_task(
        run_incident_pipeline(
            app.state.engine,
            app.state.incident_store,
            app.state.agent_tracker,
            incident_id,
        )
    )
    app.state.background_tasks.add(task)
    task.add_done_callback(app.state.background_tasks.discard)
