"""Register the Splunk MCP adapter with the global MCP router."""

from __future__ import annotations

from specter.config import get_settings
from specter.mcp.adapters.splunk import SplunkAdapter
from specter.mcp.router import get_router


async def init_splunk_adapter() -> SplunkAdapter:
    """Connect (or enable mock mode) and register typed Splunk tools on the shared router."""
    settings = get_settings()
    adapter = SplunkAdapter(
        host=settings.splunk_host,
        port=settings.splunk_port,
        username=settings.splunk_username,
        password=settings.splunk_password,
        token=settings.splunk_token,
    )
    await adapter.connect()
    get_router().register_adapter(adapter)
    return adapter
