"""MCP Router and Protocol Infrastructure for SPECTER."""

from specter.mcp.adapters.base import BaseMCPAdapter, MCPAdapter
from specter.mcp.adapters.sift_init import init_sift_adapter
from specter.mcp.adapters.sola_init import init_sola_adapter
from specter.mcp.adapters.splunk_init import init_splunk_adapter
from specter.mcp.registry import ToolRegistry, get_registry
from specter.mcp.router import MCPRouter, get_router
from specter.mcp.security import EvidenceProtector, SecurityPolicy, ToolPermission
from specter.mcp.server import SpecterMCPServer, create_mcp_server, serve_stdio

__all__ = [
    "BaseMCPAdapter",
    "MCPAdapter",
    "MCPRouter",
    "SpecterMCPServer",
    "ToolPermission",
    "ToolRegistry",
    "SecurityPolicy",
    "EvidenceProtector",
    "create_mcp_server",
    "get_registry",
    "get_router",
    "init_sift_adapter",
    "init_sola_adapter",
    "init_splunk_adapter",
    "serve_stdio",
]
