"""Base adapter interface for MCP platform integrations."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from specter.models.mcp import MCPAdapterType, MCPToolCall, MCPToolDefinition, MCPToolResult


class MCPAdapter(ABC):
    """
    Abstract base for SIFT, Splunk, Sola, and future integrations.

    Adapters expose only typed tools; the router enforces security before ``execute``.
    """

    def __init__(self) -> None:
        self._connected = False
        self._tools: list[MCPToolDefinition] = []

    @property
    @abstractmethod
    def adapter_type(self) -> MCPAdapterType:
        """Adapter enum value."""

    @property
    @abstractmethod
    def adapter_name(self) -> str:
        """Human-readable name."""

    @abstractmethod
    async def connect(self) -> bool:
        """Return True when the backing platform is reachable."""

    @abstractmethod
    async def disconnect(self) -> None:
        """Release connections / clients."""

    @abstractmethod
    async def discover_tools(self) -> list[MCPToolDefinition]:
        """Return tool definitions (also expected to populate ``self._tools``)."""

    @abstractmethod
    async def execute(self, call: MCPToolCall) -> MCPToolResult:
        """Perform the platform-specific operation for ``call``."""

    @abstractmethod
    async def health_check(self) -> dict[str, Any]:
        """Return ``{"status": "healthy|degraded|unhealthy", "details": {...}}``."""

    @property
    def is_connected(self) -> bool:
        return self._connected

    @property
    def tools(self) -> list[MCPToolDefinition]:
        return list(self._tools)

    def _create_success_result(
        self,
        call: MCPToolCall,
        data: dict[str, Any],
        execution_time_ms: int,
    ) -> MCPToolResult:
        return MCPToolResult(
            call_id=call.id,
            tool_name=call.tool_name,
            status="success",
            data=data,
            execution_time_ms=execution_time_ms,
        )

    def _create_error_result(self, call: MCPToolCall, error_message: str) -> MCPToolResult:
        return MCPToolResult(
            call_id=call.id,
            tool_name=call.tool_name,
            status="error",
            error_message=error_message,
        )

    def _create_timeout_result(self, call: MCPToolCall) -> MCPToolResult:
        return MCPToolResult(
            call_id=call.id,
            tool_name=call.tool_name,
            status="timeout",
            error_message=f"Execution timed out after {call.timeout_seconds}s",
        )


# Backwards-compatible alias for older imports.
BaseMCPAdapter = MCPAdapter
