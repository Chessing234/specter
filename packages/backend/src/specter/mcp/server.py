"""MCP Server wrapper — JSON control plane over the router."""

from __future__ import annotations

import builtins
import json
import uuid
from typing import Any

from specter.mcp.router import MCPRouter, get_router
from specter.models.mcp import MCPAdapterType, MCPToolCall


class SpecterMCPServer:
    """
    Lightweight MCP-style request handler backed by ``MCPRouter``.

    Methods mirror common MCP operations (initialize, tools/list, tools/call, health).
    """

    def __init__(self, router: MCPRouter | None = None) -> None:
        self.router = router or get_router()

    async def handle_request(self, request: dict[str, Any]) -> dict[str, Any]:
        method = request.get("method")

        if method == "initialize":
            return self._handle_initialize()
        if method == "tools/list":
            return self._handle_tools_list()
        if method == "tools/call":
            return await self._handle_tool_call(request.get("params") or {})
        if method == "health":
            return await self._handle_health()

        return {
            "error": f"Unknown method: {method}",
            "supported_methods": ["initialize", "tools/list", "tools/call", "health"],
        }

    def _handle_initialize(self) -> dict[str, Any]:
        return {
            "protocol_version": "2024-11-05",
            "server_info": {"name": "specter", "version": "0.1.0"},
            "capabilities": {"tools": {}, "logging": {}},
        }

    def _handle_tools_list(self) -> dict[str, Any]:
        schema = self.router.get_available_tools_schema()
        return {"tools": schema["tools"]}

    async def _handle_tool_call(self, params: dict[str, Any]) -> dict[str, Any]:
        call = MCPToolCall(
            id=str(params.get("id") or uuid.uuid4()),
            tool_name=params["name"],
            adapter=MCPAdapterType(params.get("adapter", "sift")),
            parameters=params.get("arguments") or {},
            timeout_seconds=int(params.get("timeout", 60)),
        )
        result = await self.router.call(call)

        payload = (
            json.dumps(result.data) if result.data is not None else (result.error_message or "")
        )

        return {
            "content": [{"type": "text", "text": payload}],
            "isError": result.status == "error",
            "_meta": {
                "status": result.status,
                "execution_time_ms": result.execution_time_ms,
            },
        }

    async def _handle_health(self) -> dict[str, Any]:
        adapter_health = await self.router.health_check()
        if not adapter_health:
            return {"status": "healthy", "adapters": {}}
        healthy = all(a.get("status") == "healthy" for a in adapter_health.values())
        return {
            "status": "healthy" if healthy else "degraded",
            "adapters": adapter_health,
        }


def create_mcp_server(router: MCPRouter | None = None) -> SpecterMCPServer:
    """Factory for embedding the MCP server in other runtimes."""
    return SpecterMCPServer(router)


async def serve_stdio() -> None:
    """Minimal stdio loop (one JSON object per line) for local integrations."""
    server = SpecterMCPServer()
    while True:
        try:
            line = builtins.input()
        except EOFError:
            break
        try:
            request = json.loads(line)
            response = await server.handle_request(request)
            print(json.dumps(response), flush=True)
        except Exception as exc:  # noqa: BLE001
            print(json.dumps({"error": str(exc)}), flush=True)
