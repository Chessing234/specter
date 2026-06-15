"""Tests for SPECTER agents (SENTRY, TRIAGE, SHERLOCK, COMMANDER, AUDIT)."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from specter.agents.audit import AuditAgent
from specter.agents.base import BaseSpecterAgent
from specter.agents.commander import CommanderAgent
from specter.agents.sentry import SentryAgent
from specter.agents.sherlock import SherlockAgent
from specter.agents.triage import TriageAgent
from specter.mcp.adapters.sola import SolaAdapter
from specter.mcp.adapters.splunk import SplunkAdapter
from specter.mcp.registry import ToolRegistry
from specter.mcp.router import MCPRouter
from specter.models.incident import Incident, Severity


@pytest.mark.asyncio
async def test_sentry_process_with_mock_graph_and_mcp(
    monkeypatch: pytest.MonkeyPatch,
    sample_incident_data: dict,
) -> None:
    import specter.agents.base as base_mod

    reg = ToolRegistry()
    router = MCPRouter(registry=reg)
    splunk = SplunkAdapter()
    await splunk.connect()
    router.register_adapter(splunk)
    monkeypatch.setattr(base_mod, "get_router", lambda: router)

    kg = MagicMock()
    kg.semantic_search = AsyncMock(return_value=[])
    kg.get_context_for_incident = AsyncMock(
        return_value={
            "related_entities": [],
            "similar_incidents": [],
            "user_baselines": [],
        }
    )
    monkeypatch.setattr(base_mod, "get_knowledge_graph", lambda: kg)

    incident = Incident(
        id="inc-1",
        title=sample_incident_data["title"],
        description=sample_incident_data["description"],
        severity=Severity(sample_incident_data["severity"]),
        source=sample_incident_data["source"],
        raw_data=sample_incident_data.get("raw_data", {}),
    )

    agent = SentryAgent()
    out = await agent.process(incident)

    assert out["status"] == "completed"
    assert "detection_result" in out
    assert isinstance(out["detection_result"], dict)
    kg.get_context_for_incident.assert_awaited()


@pytest.mark.asyncio
async def test_triage_process_heuristic(
    monkeypatch: pytest.MonkeyPatch,
    sample_incident_data: dict,
) -> None:
    import specter.agents.base as base_mod

    reg = ToolRegistry()
    router = MCPRouter(registry=reg)
    monkeypatch.setattr(base_mod, "get_router", lambda: router)

    kg = MagicMock()
    kg.get_context_for_incident = AsyncMock(
        return_value={"related_entities": [], "similar_incidents": [], "user_baselines": []}
    )
    kg.find_entities = AsyncMock(return_value=[])
    monkeypatch.setattr(base_mod, "get_knowledge_graph", lambda: kg)

    incident = Incident(
        id="inc-2",
        title=sample_incident_data["title"],
        description=sample_incident_data["description"],
        severity=Severity(sample_incident_data["severity"]),
        source=sample_incident_data["source"],
        raw_data=sample_incident_data.get("raw_data", {}),
    )

    detection_payload = {
        "detection_result": {
            "status": "completed",
            "detection_result": {
                "is_threat": True,
                "confidence": 0.8,
                "threat_type": "intrusion",
                "severity": "high",
                "enriched_context": {"user_baseline_match": "normal"},
                "reasoning": "test",
            },
        }
    }

    agent = TriageAgent()
    out = await agent.process(incident, detection_payload, None)

    assert "priority_score" in out
    assert out.get("routing_decision")


def test_base_specter_agent_is_abstract() -> None:
    with pytest.raises(TypeError):
        BaseSpecterAgent()  # type: ignore[call-arg]


@pytest.mark.asyncio
async def test_audit_scheduled_sola_and_memory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import specter.agents.base as base_mod

    reg = ToolRegistry()
    router = MCPRouter(registry=reg)
    sola = SolaAdapter(api_key="")
    await sola.connect()
    router.register_adapter(sola)
    monkeypatch.setattr(base_mod, "get_router", lambda: router)

    kg = MagicMock()
    kg.find_entities = AsyncMock(
        return_value=[{"properties": {"department": "Engineering", "role": "IC"}}]
    )
    kg.semantic_search = AsyncMock(return_value=[])
    monkeypatch.setattr(base_mod, "get_knowledge_graph", lambda: kg)

    incident = Incident(
        id="aud-1",
        title="Weekly access review",
        description="Scheduled compliance sweep",
        severity=Severity.LOW,
        source="scheduled_audit",
    )
    agent = AuditAgent()
    out = await agent.process(incident, [], [])

    assert out["status"] == "completed"
    assert out["mode"] == "scheduled_audit"
    assert "unified_report" in out
    rep = out["unified_report"]
    assert "html" in rep and "<!DOCTYPE html>" in rep["html"]
    assert out["access_review"]["status"] == "completed"
    kg.find_entities.assert_awaited()


@pytest.mark.asyncio
async def test_audit_post_incident_documentation(
    monkeypatch: pytest.MonkeyPatch,
    sample_incident_data: dict,
) -> None:
    import specter.agents.base as base_mod

    reg = ToolRegistry()
    router = MCPRouter(registry=reg)
    monkeypatch.setattr(base_mod, "get_router", lambda: router)

    kg = MagicMock()
    kg.semantic_search = AsyncMock(return_value=[{"name": "policy", "entity_type": "document"}])
    monkeypatch.setattr(base_mod, "get_knowledge_graph", lambda: kg)

    incident = Incident(
        id="aud-2",
        title=sample_incident_data["title"],
        description=sample_incident_data["description"],
        severity=Severity(sample_incident_data["severity"]),
        source=sample_incident_data["source"],
    )
    findings = [
        {
            "description": "Possible data exfiltration to external bucket",
            "finding_type": "data_exfil",
        }
    ]
    agent = AuditAgent()
    out = await agent.process(incident, findings, [])

    assert out["status"] == "completed"
    doc = out["incident_documentation"]
    assert doc is not None
    assert doc["incident_id"] == "aud-2"
    assert doc["compliance_impact"]["soc2"]["impact"] == "high"
    kg.semantic_search.assert_awaited()


def _mcp_ok(data: dict) -> dict:
    return {"status": "success", "data": data}


@pytest.fixture
def sample_incident_full() -> Incident:
    return Incident(
        id="test-incident-1",
        title="Suspicious Login",
        description="Admin login from unusual IP",
        severity=Severity.HIGH,
        source="splunk",
        raw_data={
            "user": "admin@company.com",
            "ip": "185.220.101.7",
            "timestamp": "2026-06-10T03:47:00Z",
            "host": "prod-web-01",
        },
    )


class TestSentryAgentExtended:
    """SENTRY — LLM + MCP wiring (mocked)."""

    @pytest.mark.asyncio
    async def test_detection_with_mocked_llm_and_mcp(
        self,
        monkeypatch: pytest.MonkeyPatch,
        sample_incident_full: Incident,
    ) -> None:
        import specter.agents.base as base_mod

        monkeypatch.setattr(base_mod, "get_router", lambda: MCPRouter(registry=ToolRegistry()))

        kg = MagicMock()
        kg.semantic_search = AsyncMock(return_value=[])
        kg.get_context_for_incident = AsyncMock(
            return_value={
                "related_entities": [],
                "similar_incidents": [],
                "user_baselines": [],
            }
        )
        monkeypatch.setattr(base_mod, "get_knowledge_graph", lambda: kg)

        agent = SentryAgent()
        llm = AsyncMock()
        llm.ainvoke.return_value = MagicMock(
            content=(
                '{"detection_result": {"is_threat": true, "confidence": 0.85, '
                '"severity": "high", "threat_type": "intrusion", '
                '"reasoning": "Unusual IP and time", "enriched_context": {}, '
                '"iocs_found": []}}'
            )
        )
        agent._llm = llm

        async def fake_mcp(_self, tool_name: str, _parameters: dict) -> dict:
            if tool_name == "splunk_search":
                return _mcp_ok({"results": [], "result_count": 0, "fields": []})
            if tool_name == "splunk_threat_intel_lookup":
                return _mcp_ok({"matches": [], "risk_level": "none"})
            if tool_name == "splunk_user_behavior_analytics":
                return _mcp_ok({"risk_score": 75, "anomalies": []})
            return {"status": "error", "data": {}, "error": "unexpected tool"}

        monkeypatch.setattr(SentryAgent, "_call_mcp", fake_mcp)

        result = await agent.process(sample_incident_full)
        assert result["status"] == "completed"
        assert result["detection_result"]["is_threat"] is True
        llm.ainvoke.assert_awaited()

    @pytest.mark.asyncio
    async def test_false_positive_suppression(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        import specter.agents.base as base_mod

        monkeypatch.setattr(base_mod, "get_router", lambda: MCPRouter(registry=ToolRegistry()))

        kg = MagicMock()
        kg.semantic_search = AsyncMock(return_value=[])
        kg.get_context_for_incident = AsyncMock(
            return_value={
                "related_entities": [
                    {
                        "name": "moscow-contractor@company.com",
                        "properties": {"location": "Moscow"},
                    }
                ],
                "similar_incidents": [],
                "user_baselines": [
                    {
                        "user_id": "moscow-contractor@company.com",
                        "typical_locations": ["Moscow"],
                    }
                ],
            }
        )
        monkeypatch.setattr(base_mod, "get_knowledge_graph", lambda: kg)

        incident = Incident(
            id="test-fp-1",
            title="Login from Moscow",
            description="Contractor login from Moscow IP",
            severity=Severity.MEDIUM,
            source="splunk",
            raw_data={"user": "moscow-contractor@company.com", "ip": "185.220.101.7"},
        )

        agent = SentryAgent()
        llm = AsyncMock()
        llm.ainvoke.return_value = MagicMock(
            content=(
                '{"detection_result": {"is_threat": false, "confidence": 0.95, '
                '"severity": "low", "reasoning": "Baseline matches contractor", '
                '"enriched_context": {}, "iocs_found": []}}'
            )
        )
        agent._llm = llm

        async def fake_mcp(_self, tool_name: str, _parameters: dict) -> dict:
            if tool_name == "splunk_search":
                return _mcp_ok({"results": [], "result_count": 0})
            if tool_name == "splunk_threat_intel_lookup":
                return _mcp_ok({"matches": [], "risk_level": "none"})
            if tool_name == "splunk_user_behavior_analytics":
                return _mcp_ok({"risk_score": 5, "anomalies": []})
            return {"status": "error", "data": {}, "error": "unexpected"}

        monkeypatch.setattr(SentryAgent, "_call_mcp", fake_mcp)

        result = await agent.process(incident)
        detection = result["detection_result"]
        assert detection["is_threat"] is False
        assert float(detection["confidence"]) > 0.9


class TestSherlockAgentExtended:
    """SHERLOCK — self-correction and disk-only paths."""

    @pytest.mark.asyncio
    async def test_self_correction_step(
        self,
        monkeypatch: pytest.MonkeyPatch,
        sample_incident_full: Incident,
    ) -> None:
        import specter.agents.base as base_mod

        monkeypatch.setattr(base_mod, "get_router", lambda: MCPRouter(registry=ToolRegistry()))

        kg = MagicMock()
        kg.get_context_for_incident = AsyncMock(return_value={"related_entities": []})
        monkeypatch.setattr(base_mod, "get_knowledge_graph", lambda: kg)

        sample_incident_full.raw_data["disk_image"] = "/evidence/disk.E01"
        sample_incident_full.raw_data["memory_dump"] = "/evidence/memory.raw"

        agent = SherlockAgent()
        llm = AsyncMock()
        llm.ainvoke.return_value = MagicMock(
            content=(
                '{"investigation_summary": "Test", "timeline": [], "findings": [], '
                '"indicators": [], "confidence": 0.8, "requires_human_review": false}'
            )
        )
        agent._llm = llm

        responses = [
            _mcp_ok({}),  # auto_triage_disk
            _mcp_ok({}),  # auto_triage_memory
            _mcp_ok({"timeline": [{"t": 1}], "entry_count": 1}),  # mft
            _mcp_ok({"suspicious_executions": []}),  # prefetch
            _mcp_ok({"persistence_mechanisms": []}),  # registry
            _mcp_ok({"suspicious_processes": [{"pid": 1}]}),  # pslist
            _mcp_ok({"suspicious_connections": []}),  # netscan
            _mcp_ok({"suspicious_regions": []}),  # malfind
            _mcp_ok({"suspicious_commands": []}),  # cmdline
            _mcp_ok(
                {
                    "correlations": [{"type": "process", "confidence": 0.9}],
                    "discrepancies": [
                        {
                            "type": "timeline_mismatch",
                            "disk_time": "03:47:00",
                            "memory_time": "03:47:15",
                        }
                    ],
                }
            ),
            _mcp_ok({"timeline": [{"timestamp": "2026-06-09T03:47:00Z", "event": "ok"}]}),
            _mcp_ok({"results": [{"_raw": "x"}], "result_count": 1}),  # splunk
        ]

        async def fake_mcp(_self, _tool: str, _params: dict) -> dict:
            if not responses:
                return {"status": "error", "data": {}, "error": "exhausted"}
            return responses.pop(0)

        monkeypatch.setattr(SherlockAgent, "_call_mcp", fake_mcp)

        result = await agent.process(sample_incident_full)
        assert result["status"] == "completed"
        correction = [s for s in result["steps"] if s.get("tool_used") == "self_correction"]
        assert correction, "expected self_correction after timeline discrepancy"

    @pytest.mark.asyncio
    async def test_disk_only_investigation(
        self,
        monkeypatch: pytest.MonkeyPatch,
        sample_incident_full: Incident,
    ) -> None:
        import specter.agents.base as base_mod

        monkeypatch.setattr(base_mod, "get_router", lambda: MCPRouter(registry=ToolRegistry()))

        kg = MagicMock()
        kg.get_context_for_incident = AsyncMock(return_value={"related_entities": []})
        monkeypatch.setattr(base_mod, "get_knowledge_graph", lambda: kg)

        sample_incident_full.raw_data = {
            "disk_image": "/evidence/disk.E01",
            "user": "admin",
        }

        agent = SherlockAgent()
        agent._llm = None  # heuristic synthesis

        responses = [
            _mcp_ok({}),  # triage disk only (no memory_dump)
            _mcp_ok({"timeline": [], "entry_count": 0}),
            _mcp_ok({"suspicious_executions": []}),
            _mcp_ok({"persistence_mechanisms": []}),
            _mcp_ok({"results": [], "result_count": 0}),
        ]

        async def fake_mcp(_self, _tool: str, _params: dict) -> dict:
            return responses.pop(0) if responses else _mcp_ok({})

        monkeypatch.setattr(SherlockAgent, "_call_mcp", fake_mcp)

        result = await agent.process(sample_incident_full)
        assert result["status"] == "completed"


class TestCommanderAgentExtended:
    """COMMANDER — scope and containment rules."""

    @pytest.fixture
    def commander(self) -> CommanderAgent:
        return CommanderAgent()

    def test_scope_assessment_critical(self, commander: CommanderAgent) -> None:
        findings = [
            {"significance": "critical", "type": "injected_code", "evidence": []},
            {"significance": "critical", "type": "suspicious_processes", "evidence": []},
            {"significance": "high", "type": "suspicious_connections", "evidence": []},
        ]
        scope = commander._assess_scope(findings)
        assert scope["severity"] == "critical"
        assert scope["blast_radius"] == "single_system"

    def test_containment_with_active_c2(self, commander: CommanderAgent) -> None:
        findings = [
            {"type": "injected_code", "significance": "critical"},
            {"type": "suspicious_connections", "significance": "high"},
        ]
        scope = {"severity": "critical"}
        containment = commander._determine_containment(scope, findings)
        assert containment["action_required"] is True
        assert containment["urgency"] == "immediate"

    def test_no_containment_for_low_signal(self, commander: CommanderAgent) -> None:
        findings = [{"type": "info", "significance": "low"}]
        scope = {"severity": "low"}
        containment = commander._determine_containment(scope, findings)
        assert containment["action_required"] is False


class TestAuditAgentExtended:
    """AUDIT — MCP-backed access review and hygiene."""

    @pytest.mark.asyncio
    async def test_access_review_mcp(self, monkeypatch: pytest.MonkeyPatch) -> None:
        agent = AuditAgent()

        async def fake_mcp(_self, tool_name: str, _parameters: dict) -> dict:
            assert tool_name == "sola_access_review"
            return _mcp_ok(
                {
                    "findings": [{"user": "alice", "issue": "dormant"}],
                    "statistics": {"issues_found": 1, "total_accounts_reviewed": 100},
                    "risk_score": 25,
                }
            )

        monkeypatch.setattr(AuditAgent, "_call_mcp", fake_mcp)
        agent.memory.find_entities = AsyncMock(return_value=[])

        result = await agent._run_access_review()
        assert result["status"] == "completed"
        assert result["risk_score"] == 25
        assert len(result["findings"]) == 1

    @pytest.mark.asyncio
    async def test_hygiene_check_mcp(self, monkeypatch: pytest.MonkeyPatch) -> None:
        agent = AuditAgent()

        async def fake_mcp(_self, tool_name: str, _parameters: dict) -> dict:
            assert tool_name == "sola_identity_hygiene"
            return _mcp_ok(
                {
                    "findings": [{"platform": "aws", "check": "orphaned_accounts"}],
                    "hygiene_score": 72,
                    "recommendations": ["Remove orphaned accounts"],
                }
            )

        monkeypatch.setattr(AuditAgent, "_call_mcp", fake_mcp)

        result = await agent._run_hygiene_check()
        assert result["hygiene_score"] == 72
        assert len(result["recommendations"]) == 1


class TestTriageAgentExtended:
    """TRIAGE — crown-jewel style prioritization (mocked LLM)."""

    @pytest.mark.asyncio
    async def test_crown_jewel_prioritization(
        self,
        monkeypatch: pytest.MonkeyPatch,
        sample_incident_full: Incident,
    ) -> None:
        import specter.agents.base as base_mod

        monkeypatch.setattr(base_mod, "get_router", lambda: MCPRouter(registry=ToolRegistry()))

        kg = MagicMock()
        kg.find_entities = AsyncMock(
            return_value=[{"properties": {"criticality": "critical"}, "name": "prod-db"}]
        )
        kg.get_context_for_incident = AsyncMock(
            return_value={
                "related_entities": [
                    {"name": "prod-db", "properties": {"criticality": "critical"}},
                ],
                "similar_incidents": [],
                "user_baselines": [],
            }
        )
        monkeypatch.setattr(base_mod, "get_knowledge_graph", lambda: kg)

        agent = TriageAgent()
        llm = AsyncMock()
        llm.ainvoke.return_value = MagicMock(
            content=(
                '{"priority_score": 88, "priority_level": "critical", '
                '"business_impact": "crown_jewel", "routing_decision": "immediate_response", '
                '"justification": "Crown jewel asset", "false_positive_likelihood": 0.1, '
                '"sla_minutes": 60}'
            )
        )
        agent._llm = llm

        result = await agent.process(sample_incident_full, None, None)
        assert result["priority_score"] > 70
        assert result.get("business_impact") in ("crown_jewel", "critical")
