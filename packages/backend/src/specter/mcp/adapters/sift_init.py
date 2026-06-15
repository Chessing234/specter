"""Register the SANS SIFT MCP adapter with the global MCP router."""

from __future__ import annotations

from specter.config import get_settings
from specter.mcp.adapters.sift import SIFTAdapter
from specter.mcp.router import get_router


async def init_sift_adapter() -> SIFTAdapter:
    """Connect (or enable mock mode), register typed SIFT tools on the shared router."""
    settings = get_settings()
    adapter = SIFTAdapter(
        sift_host=settings.sift_host,
        sift_username=settings.sift_username,
    )
    await adapter.connect()
    get_router().register_adapter(adapter)
    return adapter
