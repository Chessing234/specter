"""Base classes for SPECTER agents (memory fabric + MCP)."""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from datetime import UTC, datetime
from typing import Any

from specter.mcp.router import MCPRouter, get_router
from specter.memory.graph import KnowledgeGraph, get_knowledge_graph
from specter.models.agent import AgentAction, AgentType
from specter.models.incident import Incident
from specter.models.mcp import MCPAdapterType, MCPToolCall


def _infer_mcp_adapter(tool_name: str) -> MCPAdapterType:
    if tool_name.startswith("splunk_"):
        return MCPAdapterType.SPLUNK
    if tool_name.startswith("sola_"):
        return MCPAdapterType.SOLA
    if tool_name in {
        "cross_reference_iocs",
        "extract_mft_timeline",
        "correlate_disk_memory",
        "analyze_prefetch_files",
        "parse_registry_hives",
        "parse_amcache",
        "volatility_pslist",
        "volatility_netscan",
        "volatility_malfind",
        "volatility_cmdline",
        "generate_super_timeline",
        "auto_triage_disk",
        "auto_triage_memory",
    }:
        return MCPAdapterType.SIFT
    return MCPAdapterType.SPLUNK


class BaseAgent(ABC):
    """Minimal contract for any node invoked by ``SpecterEngine``."""

    name: str = "base"

    @abstractmethod
    async def process(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        """Run agent logic (signatures vary by agent)."""
        ...


class BaseSpecterAgent(BaseAgent):
    """
    Agents with Memory Fabric + MCP access.

    Subclasses implement ``process``, ``get_capabilities``, and ``get_system_prompt``.
    """

    agent_type: AgentType
    status: str = "idle"

    def __init__(self) -> None:
        self.memory: KnowledgeGraph = get_knowledge_graph()
        self.mcp: MCPRouter = get_router()
        self._action_history: list[AgentAction] = []

    def _create_action(
        self,
        action_type: str,
        tool_used: str | None = None,
        input_params: dict[str, Any] | None = None,
    ) -> AgentAction:
        action = AgentAction(
            id=str(uuid.uuid4()),
            agent=self.agent_type,
            action_type=action_type,
            tool_used=tool_used,
            input_params=input_params or {},
            started_at=datetime.now(UTC),
            status="running",
        )
        self._action_history.append(action)
        return action

    def _complete_action(self, action: AgentAction, output: dict[str, Any] | None = None) -> None:
        action.status = "completed"
        action.output = output or {}
        action.completed_at = datetime.now(UTC)

    def _fail_action(self, action: AgentAction, message: str) -> None:
        action.status = "failed"
        action.error_message = message
        action.completed_at = datetime.now(UTC)

    @abstractmethod
    async def process(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        """Main processing entrypoint."""

    @abstractmethod
    def get_capabilities(self) -> list[str]:
        """Human-readable capability ids (Splunk tools, memory, etc.)."""

    @abstractmethod
    def get_system_prompt(self) -> str:
        """LLM system prompt for reasoning-heavy steps."""

    async def _query_memory(self, query: str, limit: int = 10) -> list[dict[str, Any]]:
        return await self.memory.semantic_search(query, limit=limit)

    async def _call_mcp(
        self,
        tool_name: str,
        parameters: dict[str, Any],
        *,
        adapter: MCPAdapterType | None = None,
    ) -> dict[str, Any]:
        call = MCPToolCall(
            id=str(uuid.uuid4()),
            tool_name=tool_name,
            adapter=adapter or _infer_mcp_adapter(tool_name),
            parameters=parameters,
        )
        result = await self.mcp.call(call)
        return {
            "status": result.status,
            "data": result.data or {},
            "error": result.error_message,
        }

    async def _get_incident_context(self, incident: Incident) -> dict[str, Any]:
        payload = incident.model_dump(mode="python")
        return await self.memory.get_context_for_incident(payload)
