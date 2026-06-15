"""MCP Tool Registry — typed tools registered per adapter."""

from __future__ import annotations

from typing import Any

from specter.models.mcp import MCPAdapterType, MCPToolDefinition


class ToolRegistry:
    """
    Central registry for MCP tools.

    Only tools present here can be invoked by the router (architectural allowlist).
    """

    def __init__(self) -> None:
        self._tools: dict[str, MCPToolDefinition] = {}
        self._adapter_tools: dict[MCPAdapterType, list[str]] = {}

    def register(self, tool: MCPToolDefinition) -> None:
        """Register a tool; names must be unique across adapters."""
        if tool.name in self._tools:
            raise ValueError(
                f"Tool '{tool.name}' already registered from adapter "
                f"'{self._tools[tool.name].adapter}'"
            )

        self._tools[tool.name] = tool
        self._adapter_tools.setdefault(tool.adapter, []).append(tool.name)

    def register_batch(self, tools: list[MCPToolDefinition]) -> None:
        """Register many tools."""
        for tool in tools:
            self.register(tool)

    def get(self, tool_name: str) -> MCPToolDefinition | None:
        """Lookup a tool definition by name."""
        return self._tools.get(tool_name)

    def list_tools(
        self,
        adapter: MCPAdapterType | None = None,
        read_only: bool | None = None,
    ) -> list[MCPToolDefinition]:
        """List tools with optional filters."""
        tools = list(self._tools.values())

        if adapter:
            names = set(self._adapter_tools.get(adapter, []))
            tools = [t for t in tools if t.name in names]

        if read_only is not None:
            tools = [t for t in tools if t.read_only == read_only]

        return tools

    def get_adapter_tools(self, adapter: MCPAdapterType) -> list[MCPToolDefinition]:
        """All tools for one adapter."""
        names = self._adapter_tools.get(adapter, [])
        return [self._tools[name] for name in names if name in self._tools]

    def unregister(self, tool_name: str) -> None:
        """Remove a tool."""
        if tool_name not in self._tools:
            return
        tool = self._tools.pop(tool_name)
        if tool.adapter in self._adapter_tools:
            self._adapter_tools[tool.adapter] = [
                n for n in self._adapter_tools[tool.adapter] if n != tool_name
            ]

    def has_tool(self, tool_name: str) -> bool:
        return tool_name in self._tools

    def get_schema(self) -> dict[str, Any]:
        """OpenAPI-style listing for LLM / client discovery."""
        return {
            "tools": [
                {
                    "name": tool.name,
                    "description": tool.description,
                    "adapter": str(tool.adapter),
                    "read_only": tool.read_only,
                    "destructive": tool.destructive,
                    "parameters": tool.parameters,
                    "returns": tool.returns,
                }
                for tool in self._tools.values()
            ]
        }


_registry: ToolRegistry | None = None


def get_registry() -> ToolRegistry:
    global _registry
    if _registry is None:
        _registry = ToolRegistry()
    return _registry
