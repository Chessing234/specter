"""MCP-related Pydantic models."""

from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field


class MCPAdapterType(StrEnum):
    """Available MCP adapter types."""

    SIFT = "sift"
    SPLUNK = "splunk"
    SOLA = "sola"


class MCPToolDefinition(BaseModel):
    """Definition of a tool exposed via MCP."""

    name: str
    description: str
    adapter: MCPAdapterType
    parameters: dict[str, Any] = Field(default_factory=dict)
    returns: dict[str, Any] = Field(default_factory=dict)
    read_only: bool = True
    destructive: bool = False


class MCPToolCall(BaseModel):
    """A call to an MCP tool."""

    id: str
    tool_name: str
    adapter: MCPAdapterType
    parameters: dict[str, Any] = Field(default_factory=dict)
    timeout_seconds: int = 60


class MCPToolResult(BaseModel):
    """Result of an MCP tool call."""

    call_id: str
    tool_name: str
    status: Literal["success", "error", "timeout"]
    data: dict[str, Any] | None = None
    error_message: str | None = None
    execution_time_ms: int | None = None
    raw_output: str | None = None
