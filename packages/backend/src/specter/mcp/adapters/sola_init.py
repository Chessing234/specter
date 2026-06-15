"""Register the Sola Security MCP adapter with the global MCP router."""

from __future__ import annotations

from specter.config import get_settings
from specter.mcp.adapters.sola import SolaAdapter
from specter.mcp.router import get_router


async def init_sola_adapter() -> SolaAdapter:
    """Connect (or enable mock mode) and register typed Sola tools on the shared router."""
    settings = get_settings()
    adapter = SolaAdapter(
        api_key=settings.sola_api_key,
        base_url=settings.sola_base_url,
    )
    await adapter.connect()
    get_router().register_adapter(adapter)
    return adapter
