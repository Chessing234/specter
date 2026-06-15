"""MCP Router — routes typed tool calls to adapters with architectural guardrails."""

from __future__ import annotations

import asyncio
import time
from typing import Any

from specter.mcp.adapters.base import MCPAdapter
from specter.mcp.registry import ToolRegistry, get_registry
from specter.mcp.security import EvidenceProtector, SecurityPolicy
from specter.models.mcp import MCPToolCall, MCPToolResult


class MCPRouter:
    """
    Central MCP entrypoint: registry lookup, policy enforcement, adapter dispatch,
    timeouts, and audit logging.
    """

    def __init__(
        self,
        registry: ToolRegistry | None = None,
        security: SecurityPolicy | None = None,
    ) -> None:
        self.registry = registry or get_registry()
        self.security = security or SecurityPolicy()
        self.protector = EvidenceProtector()
        self._adapters: dict[str, MCPAdapter] = {}
        self._execution_log: list[dict[str, Any]] = []
        max_conc = int(self.security.config.get("max_concurrent_executions", 10))
        self._concurrency = asyncio.Semaphore(max(1, max_conc))

    def register_adapter(self, adapter: MCPAdapter) -> None:
        """Register adapter and its typed tools in the shared registry."""
        key = adapter.adapter_type.value
        if key in self._adapters:
            for tool in self._adapters[key].tools:
                self.registry.unregister(tool.name)

        self._adapters[key] = adapter
        for tool in adapter.tools:
            self.registry.register(tool)

    async def call(self, call: MCPToolCall) -> MCPToolResult:
        """Execute a single MCP tool call."""
        start = time.perf_counter()

        tool = self.registry.get(call.tool_name)
        if not tool:
            return MCPToolResult(
                call_id=call.id,
                tool_name=call.tool_name,
                status="error",
                error_message=f"Tool '{call.tool_name}' not found in registry",
            )

        allowed, reason = self.security.can_execute(tool)
        if not allowed:
            return MCPToolResult(
                call_id=call.id,
                tool_name=call.tool_name,
                status="error",
                error_message=f"SECURITY BLOCKED: {reason}",
            )

        if self.security.requires_approval(tool):
            return MCPToolResult(
                call_id=call.id,
                tool_name=call.tool_name,
                status="error",
                error_message=f"TOOL REQUIRES HUMAN APPROVAL: {call.tool_name}",
            )

        if call.adapter != tool.adapter:
            return MCPToolResult(
                call_id=call.id,
                tool_name=call.tool_name,
                status="error",
                error_message=(
                    f"Adapter mismatch: call specifies {call.adapter} but tool is bound to "
                    f"{tool.adapter}"
                ),
            )

        adapter = self._adapters.get(tool.adapter.value)
        if not adapter:
            return MCPToolResult(
                call_id=call.id,
                tool_name=call.tool_name,
                status="error",
                error_message=f"Adapter '{tool.adapter.value}' not registered",
            )

        if not adapter.is_connected:
            connected = await adapter.connect()
            if not connected:
                return MCPToolResult(
                    call_id=call.id,
                    tool_name=call.tool_name,
                    status="error",
                    error_message=f"Failed to connect to adapter '{tool.adapter.value}'",
                )

        async with self._concurrency:
            try:
                result = await asyncio.wait_for(adapter.execute(call), timeout=call.timeout_seconds)
            except TimeoutError:
                result = MCPToolResult(
                    call_id=call.id,
                    tool_name=call.tool_name,
                    status="timeout",
                    error_message=f"Tool execution timed out after {call.timeout_seconds}s",
                )
            except Exception as exc:  # noqa: BLE001
                result = MCPToolResult(
                    call_id=call.id,
                    tool_name=call.tool_name,
                    status="error",
                    error_message=f"Execution error: {exc}",
                )

        elapsed_ms = int((time.perf_counter() - start) * 1000)
        result = result.model_copy(update={"execution_time_ms": elapsed_ms})

        self._execution_log.append(
            {
                "timestamp": time.time(),
                "call_id": call.id,
                "tool_name": call.tool_name,
                "adapter": tool.adapter.value,
                "status": result.status,
                "execution_time_ms": elapsed_ms,
                "parameters": call.parameters,
                "chain_of_custody": [
                    {
                        "step": "mcp_router.dispatch",
                        "component": "MCPRouter",
                        "detail": f"adapter={tool.adapter.value}",
                    }
                ],
            }
        )

        return result

    async def call_batch(self, calls: list[MCPToolCall]) -> list[MCPToolResult]:
        return list(await asyncio.gather(*[self.call(c) for c in calls]))

    def get_execution_log(self, limit: int = 100) -> list[dict[str, Any]]:
        return self._execution_log[-limit:]

    async def health_check(self) -> dict[str, Any]:
        results: dict[str, Any] = {}
        for name, adapter in self._adapters.items():
            results[name] = await adapter.health_check()
        return results

    def get_available_tools_schema(self) -> dict[str, Any]:
        return self.registry.get_schema()


_router: MCPRouter | None = None


def get_router() -> MCPRouter:
    global _router
    if _router is None:
        _router = MCPRouter()
    return _router
