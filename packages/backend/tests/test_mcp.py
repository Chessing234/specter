"""Tests for MCP router, registry, security, and server."""

import os
from pathlib import Path

import pytest

from specter.mcp.adapters.sift import SIFTAdapter
from specter.mcp.adapters.sift_init import init_sift_adapter
from specter.mcp.adapters.sola import SolaAdapter
from specter.mcp.adapters.sola_init import init_sola_adapter
from specter.mcp.adapters.splunk import SplunkAdapter
from specter.mcp.adapters.splunk_init import init_splunk_adapter
from specter.mcp.registry import ToolRegistry
from specter.mcp.router import MCPRouter
from specter.mcp.security import EvidenceProtector, SecurityPolicy
from specter.mcp.server import SpecterMCPServer
from specter.models.mcp import MCPAdapterType, MCPToolCall, MCPToolDefinition


def test_registry_duplicate_tool_raises() -> None:
    reg = ToolRegistry()
    tool = MCPToolDefinition(
        name="dup.tool",
        description="x",
        adapter=MCPAdapterType.SIFT,
    )
    reg.register(tool)
    with pytest.raises(ValueError):
        reg.register(tool)


def test_registry_filters() -> None:
    reg = ToolRegistry()
    reg.register(
        MCPToolDefinition(
            name="a.ro",
            description="read",
            adapter=MCPAdapterType.SIFT,
            read_only=True,
        )
    )
    reg.register(
        MCPToolDefinition(
            name="b.rw",
            description="write",
            adapter=MCPAdapterType.SPLUNK,
            read_only=False,
        )
    )
    assert len(reg.list_tools(read_only=True)) == 1
    assert len(reg.list_tools(adapter=MCPAdapterType.SPLUNK)) == 1


@pytest.mark.asyncio
async def test_router_happy_path() -> None:
    reg = ToolRegistry()
    router = MCPRouter(registry=reg)
    adapter = SIFTAdapter()
    router.register_adapter(adapter)

    call = MCPToolCall(
        id="c1",
        tool_name="extract_mft_timeline",
        adapter=MCPAdapterType.SIFT,
        parameters={"disk_image": "/cases/demo/disk.E01", "output_format": "json"},
    )
    result = await router.call(call)
    assert result.status == "success"
    assert result.data is not None
    assert "timeline" in result.data
    assert router.get_execution_log(limit=1)[0]["tool_name"] == "extract_mft_timeline"


@pytest.mark.asyncio
async def test_router_unknown_tool() -> None:
    router = MCPRouter(registry=ToolRegistry())
    result = await router.call(
        MCPToolCall(
            id="c2",
            tool_name="missing",
            adapter=MCPAdapterType.SIFT,
        )
    )
    assert result.status == "error"
    assert "not found" in (result.error_message or "")


@pytest.mark.asyncio
async def test_router_blocks_destructive() -> None:
    reg = ToolRegistry()
    security = SecurityPolicy({"allowed_destructive": []})
    router = MCPRouter(registry=reg, security=security)
    reg.register(
        MCPToolDefinition(
            name="danger.rm_data",
            description="bad",
            adapter=MCPAdapterType.SIFT,
            destructive=True,
        )
    )
    adapter = SIFTAdapter()
    router.register_adapter(adapter)

    result = await router.call(
        MCPToolCall(
            id="c3",
            tool_name="danger.rm_data",
            adapter=MCPAdapterType.SIFT,
        )
    )
    assert result.status == "error"
    assert "SECURITY BLOCKED" in (result.error_message or "")


@pytest.mark.asyncio
async def test_router_requires_approval() -> None:
    reg = ToolRegistry()
    router = MCPRouter(registry=reg)
    reg.register(
        MCPToolDefinition(
            name="splunk.block_ip_stub",
            description="needs approval",
            adapter=MCPAdapterType.SIFT,
        )
    )
    adapter = SIFTAdapter()
    router.register_adapter(adapter)

    result = await router.call(
        MCPToolCall(
            id="c4",
            tool_name="splunk.block_ip_stub",
            adapter=MCPAdapterType.SIFT,
        )
    )
    assert result.status == "error"
    assert "APPROVAL" in (result.error_message or "")


@pytest.mark.asyncio
async def test_init_sift_adapter_registers_tools(monkeypatch: pytest.MonkeyPatch) -> None:
    reg = ToolRegistry()
    router = MCPRouter(registry=reg)
    monkeypatch.setattr("specter.mcp.adapters.sift_init.get_router", lambda: router)
    adapter = await init_sift_adapter()
    assert adapter.is_connected
    assert reg.get("extract_mft_timeline") is not None


@pytest.mark.asyncio
async def test_splunk_mock_search() -> None:
    reg = ToolRegistry()
    router = MCPRouter(registry=reg)
    adapter = SplunkAdapter()
    await adapter.connect()
    router.register_adapter(adapter)
    result = await router.call(
        MCPToolCall(
            id="s1",
            tool_name="splunk_search",
            adapter=MCPAdapterType.SPLUNK,
            parameters={"query": "failed login", "earliest": "-24h"},
        )
    )
    assert result.status == "success"
    assert result.data is not None
    assert result.data["result_count"] >= 1


@pytest.mark.asyncio
async def test_splunk_writable_update_alert() -> None:
    reg = ToolRegistry()
    router = MCPRouter(registry=reg)
    adapter = SplunkAdapter()
    await adapter.connect()
    router.register_adapter(adapter)
    result = await router.call(
        MCPToolCall(
            id="s2",
            tool_name="splunk_update_alert",
            adapter=MCPAdapterType.SPLUNK,
            parameters={"alert_id": "n-1", "status": "in_progress", "comment": "triage"},
        )
    )
    assert result.status == "success"
    assert result.data is not None
    assert result.data.get("success") is True


@pytest.mark.asyncio
async def test_init_splunk_adapter_registers_tools(monkeypatch: pytest.MonkeyPatch) -> None:
    reg = ToolRegistry()
    router = MCPRouter(registry=reg)
    monkeypatch.setattr("specter.mcp.adapters.splunk_init.get_router", lambda: router)
    adapter = await init_splunk_adapter()
    assert adapter.is_connected
    assert reg.get("splunk_search") is not None


@pytest.mark.asyncio
async def test_sola_mock_access_review() -> None:
    reg = ToolRegistry()
    router = MCPRouter(registry=reg)
    adapter = SolaAdapter()
    await adapter.connect()
    router.register_adapter(adapter)
    result = await router.call(
        MCPToolCall(
            id="so1",
            tool_name="sola_access_review",
            adapter=MCPAdapterType.SOLA,
            parameters={
                "platforms": ["aws", "github"],
                "output_format": "html",
            },
        )
    )
    assert result.status == "success"
    assert result.data is not None
    assert "report_url" in result.data
    assert result.data.get("risk_score") is not None


@pytest.mark.asyncio
async def test_init_sola_adapter_registers_tools(monkeypatch: pytest.MonkeyPatch) -> None:
    reg = ToolRegistry()
    router = MCPRouter(registry=reg)
    monkeypatch.setattr("specter.mcp.adapters.sola_init.get_router", lambda: router)
    adapter = await init_sola_adapter()
    assert adapter.is_connected
    assert reg.get("sola_access_review") is not None


@pytest.mark.asyncio
async def test_server_tools_list() -> None:
    reg = ToolRegistry()
    router = MCPRouter(registry=reg)
    router.register_adapter(SIFTAdapter())
    server = SpecterMCPServer(router)
    out = await server.handle_request({"method": "tools/list"})
    assert "tools" in out
    assert len(out["tools"]) >= 13


class TestSecurityPolicy:
    """Architectural guardrails on MCP tool definitions."""

    def test_blocked_tool_name_pattern(self) -> None:
        policy = SecurityPolicy()
        rm_tool = MCPToolDefinition(
            name="rm_file",
            description="Remove file",
            adapter=MCPAdapterType.SIFT,
            read_only=False,
            destructive=False,
        )
        allowed, reason = policy.can_execute(rm_tool)
        assert allowed is False
        assert "blocked" in reason.lower() or "rm" in reason.lower()

    def test_read_only_tool_allowed(self) -> None:
        policy = SecurityPolicy()
        read_tool = MCPToolDefinition(
            name="read_file_safe",
            description="Read file",
            adapter=MCPAdapterType.SIFT,
            read_only=True,
            destructive=False,
        )
        allowed, _reason = policy.can_execute(read_tool)
        assert allowed is True

    def test_destructive_not_allowlisted(self) -> None:
        policy = SecurityPolicy()
        delete_tool = MCPToolDefinition(
            name="delete_evidence",
            description="Delete evidence",
            adapter=MCPAdapterType.SIFT,
            read_only=False,
            destructive=True,
        )
        allowed, _reason = policy.can_execute(delete_tool)
        assert allowed is False


class TestMCPRouterGuardrails:
    """Router rejects blocked tool registrations."""

    @pytest.mark.asyncio
    async def test_call_blocked_by_policy(self) -> None:
        reg = ToolRegistry()
        reg.register(
            MCPToolDefinition(
                name="rm_rf",
                description="danger",
                adapter=MCPAdapterType.SIFT,
                read_only=True,
                destructive=False,
            )
        )
        router = MCPRouter(registry=reg)
        router.register_adapter(SIFTAdapter())

        result = await router.call(
            MCPToolCall(
                id="test-rm",
                tool_name="rm_rf",
                adapter=MCPAdapterType.SIFT,
            )
        )
        assert result.status == "error"
        assert "SECURITY BLOCKED" in (result.error_message or "")


class TestEvidenceProtector:
    """Evidence integrity helpers."""

    def test_protect_evidence_creates_copy(self, tmp_path: Path) -> None:
        test_file = tmp_path / "evidence.txt"
        test_file.write_text("sensitive evidence data", encoding="utf-8")

        protector = EvidenceProtector()
        copy_path = protector.protect_evidence(str(test_file))

        assert os.path.exists(copy_path)
        assert Path(copy_path).read_text(encoding="utf-8") == "sensitive evidence data"
        assert test_file.read_text(encoding="utf-8") == "sensitive evidence data"

    def test_verify_integrity(self, tmp_path: Path) -> None:
        import hashlib

        test_file = tmp_path / "evidence.txt"
        test_file.write_text("evidence", encoding="utf-8")
        expected_hash = hashlib.sha256(test_file.read_bytes()).hexdigest()

        protector = EvidenceProtector()
        assert protector.verify_integrity(str(test_file), expected_hash) is True
        assert protector.verify_integrity(str(test_file), "wrong_hash") is False
