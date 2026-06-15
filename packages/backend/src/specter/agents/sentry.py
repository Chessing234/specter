"""SENTRY agent — detection and threat monitoring."""

from __future__ import annotations

import json
from typing import Any

from langchain_core.messages import HumanMessage, SystemMessage

from specter.agents.base import BaseSpecterAgent
from specter.config import get_settings
from specter.models.agent import AgentType
from specter.models.incident import Incident


def _as_match_dicts(items: list[Any]) -> list[dict[str, Any]]:
    return [x for x in items if isinstance(x, dict)]


class SentryAgent(BaseSpecterAgent):
    """
    SENTRY — monitors sources, enriches with Memory Fabric, queries Splunk / intel / UBA.
    """

    agent_type = AgentType.SENTRY

    def __init__(self) -> None:
        super().__init__()
        settings = get_settings()
        self._llm: Any = None
        if settings.anthropic_api_key:
            from langchain_anthropic import ChatAnthropic

            self._llm = ChatAnthropic(
                model=settings.default_llm_model,
                api_key=settings.anthropic_api_key,
                temperature=0.1,
            )
        elif settings.openai_api_key:
            from langchain_openai import ChatOpenAI

            self._llm = ChatOpenAI(
                model="gpt-4o",
                api_key=settings.openai_api_key,
                temperature=0.1,
            )

    def get_system_prompt(self) -> str:
        return """You are SENTRY, the detection agent for SPECTER Security Operations.

Your role is to:
1. Analyze security alerts and logs for threats
2. Enrich alerts with organizational context from the Memory Fabric
3. Detect anomalies by comparing against user baselines and asset profiles
4. Correlate indicators of compromise against known threat actors

Rules:
- ALWAYS consider organizational memory context before classifying
- NEVER downgrade severity without strong contextual justification
- Flag discrepancies between observed behavior and established baselines
- Report confidence levels for all findings (0.0-1.0)

Respond with JSON only (no markdown fences) using this shape:
{
  "detection_result": {
    "is_threat": true,
    "threat_type": "intrusion",
    "confidence": 0.75,
    "severity": "high",
    "enriched_context": {
      "user_baseline_match": "normal",
      "asset_criticality": "high",
      "related_threat_actors": [],
      "historical_pattern": "new"
    },
    "iocs_found": [],
    "reasoning": "detailed explanation"
  }
}
"""

    def get_capabilities(self) -> list[str]:
        return [
            "splunk_search",
            "splunk_nl_search",
            "splunk_detect_anomalies",
            "splunk_get_alerts",
            "splunk_threat_intel_lookup",
            "splunk_user_behavior_analytics",
            "cross_reference_iocs",
            "memory_query",
        ]

    async def process(
        self,
        incident: Incident,
        memory_context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        action = self._create_action("detect", "multi_source_analysis")

        try:
            if memory_context is None:
                memory_context = await self._get_incident_context(incident)

            search_bits = [incident.title, incident.description]
            raw = incident.raw_data or {}
            if raw.get("user"):
                search_bits.append(f"user:{raw['user']}")
            if raw.get("host"):
                search_bits.append(f"host:{raw['host']}")
            mem_hits = await self._query_memory(" ".join(search_bits)[:2000], limit=8)
            memory_context = {**memory_context, "semantic_hits": mem_hits}

            splunk_results = await self._query_splunk(raw)
            ioc_results = await self._check_threat_intel(raw)
            uba_results = await self._check_user_behavior(raw)

            detection_result = await self._classify_threat(
                incident=incident,
                memory_context=memory_context,
                splunk_data=splunk_results,
                ioc_data=ioc_results,
                uba_data=uba_results,
            )

            self._complete_action(action, detection_result)

            ev = int(splunk_results.get("result_count", 0)) + len(ioc_results.get("matches", []))

            return {
                "status": "completed",
                "detection_result": detection_result,
                "sources_queried": ["splunk", "threat_intel", "user_behavior", "memory_fabric"],
                "evidence_count": ev,
                "reasoning": str(detection_result.get("reasoning", "")),
            }

        except Exception as exc:  # noqa: BLE001
            self._fail_action(action, str(exc))
            return {"status": "error", "error": str(exc), "reasoning": str(exc)}

    async def _query_splunk(self, raw_data: dict[str, Any]) -> dict[str, Any]:
        queries: list[str] = []
        if raw_data.get("user"):
            u = str(raw_data["user"])
            queries.append(f'user="{u}" OR src_user="{u}"')
        if raw_data.get("ip"):
            ip = str(raw_data["ip"])
            queries.append(f"src_ip={ip} OR dest_ip={ip}")
        if raw_data.get("host"):
            h = str(raw_data["host"])
            queries.append(f'host="{h}"')

        if not queries:
            return {"results": [], "result_count": 0, "fields": [], "search_time": 0.0}

        spl = (
            f"index=* ({' OR '.join(queries)}) earliest=-7d "
            "| stats count by _time, host, sourcetype | sort -_time"
        )

        raw = await self._call_mcp(
            "splunk_search",
            {"query": spl, "earliest": "-7d", "max_results": 100},
        )
        if raw.get("status") != "success":
            return {
                "results": [],
                "result_count": 0,
                "fields": [],
                "search_time": 0.0,
                "error": raw.get("error"),
            }
        return raw.get("data") or {}

    async def _check_threat_intel(self, raw_data: dict[str, Any]) -> dict[str, Any]:
        iocs: list[tuple[str, str]] = []
        if raw_data.get("ip"):
            iocs.append(("ip", str(raw_data["ip"])))
        if raw_data.get("hash"):
            iocs.append(("hash", str(raw_data["hash"])))
        if raw_data.get("domain"):
            iocs.append(("domain", str(raw_data["domain"])))

        if not iocs:
            return {"matches": [], "risk_level": "none"}

        all_matches: list[dict[str, Any]] = []
        for ioc_type, ioc_value in iocs:
            result = await self._call_mcp(
                "splunk_threat_intel_lookup",
                {"ioc_type": ioc_type, "ioc_value": ioc_value},
            )
            if result.get("status") == "success":
                data = result.get("data") or {}
                matches = data.get("matches") or []
                if isinstance(matches, list):
                    all_matches.extend(_as_match_dicts(matches))

        risk = "none"
        if all_matches and any(float(m.get("confidence", 0) or 0) > 90 for m in all_matches):
            risk = "critical"
        elif all_matches:
            risk = "medium"

        return {"matches": all_matches, "risk_level": risk}

    async def _check_user_behavior(self, raw_data: dict[str, Any]) -> dict[str, Any]:
        user = raw_data.get("user")
        if not user:
            return {"risk_score": 0.0, "anomalies": []}

        raw = await self._call_mcp(
            "splunk_user_behavior_analytics",
            {"user": str(user), "time_range": "-30d"},
        )
        if raw.get("status") != "success":
            return {"risk_score": 0.0, "anomalies": [], "error": raw.get("error")}
        return raw.get("data") or {}

    async def _classify_threat(
        self,
        incident: Incident,
        memory_context: dict[str, Any],
        splunk_data: dict[str, Any],
        ioc_data: dict[str, Any],
        uba_data: dict[str, Any],
    ) -> dict[str, Any]:
        if self._llm is None:
            return self._heuristic_detection(
                incident, memory_context, splunk_data, ioc_data, uba_data
            )

        entities = memory_context.get("related_entities") or []
        entity_names = [str(e.get("name", "")) for e in entities[:5] if isinstance(e, dict)]

        prompt = f"""
Analyze the following security alert with organizational context:

ALERT:
- Title: {incident.title}
- Description: {incident.description}
- Severity: {incident.severity}
- Source: {incident.source}
- Raw Data: {incident.raw_data}

ORGANIZATIONAL CONTEXT:
- Related entities: {entity_names}
- Similar past incidents: {len(memory_context.get("similar_incidents", []))}
- User baselines: {len(memory_context.get("user_baselines", []))}

SPLUNK DATA:
- Related events found: {splunk_data.get("result_count", 0)}

THREAT INTEL:
- IOC matches: {len(ioc_data.get("matches", []))}
- Risk level: {ioc_data.get("risk_level", "none")}

USER BEHAVIOR:
- Risk score: {uba_data.get("risk_score", 0)}
- Anomalies: {len(uba_data.get("anomalies", []))}

Classify this threat with confidence and enriched_context.
"""

        messages = [
            SystemMessage(content=self.get_system_prompt()),
            HumanMessage(content=prompt),
        ]

        response = await self._llm.ainvoke(messages)
        content = str(response.content)

        try:
            if "```json" in content:
                content = content.split("```json", 1)[1].split("```", 1)[0]
            elif "```" in content:
                content = content.split("```", 1)[1].split("```", 1)[0]

            parsed = json.loads(content.strip())
            if isinstance(parsed, dict) and "detection_result" in parsed:
                inner = parsed["detection_result"]
                if isinstance(inner, dict):
                    return inner
            if isinstance(parsed, dict):
                return parsed
        except (json.JSONDecodeError, IndexError, ValueError):
            pass

        return {
            "is_threat": True,
            "threat_type": "other",
            "confidence": 0.5,
            "severity": str(incident.severity),
            "enriched_context": {
                "user_baseline_match": "unknown",
                "asset_criticality": "medium",
                "related_threat_actors": [],
                "historical_pattern": "new",
            },
            "iocs_found": [],
            "reasoning": content[:4000],
        }

    def _heuristic_detection(
        self,
        incident: Incident,
        memory_context: dict[str, Any],
        splunk_data: dict[str, Any],
        ioc_data: dict[str, Any],
        uba_data: dict[str, Any],
    ) -> dict[str, Any]:
        conf = 0.55
        is_threat = True
        if ioc_data.get("risk_level") == "critical":
            conf = 0.88
        elif ioc_data.get("risk_level") == "medium":
            conf = 0.72
        elif not ioc_data.get("matches") and int(splunk_data.get("result_count", 0)) == 0:
            conf = 0.35
            is_threat = incident.severity.value in {"high", "critical"}

        uba_risk = float(uba_data.get("risk_score") or 0)
        if uba_risk > 60:
            conf = min(0.95, conf + 0.1)

        baseline_hint = "unknown"
        if memory_context.get("user_baselines"):
            baseline_hint = "normal" if uba_risk < 40 else "anomalous"

        ioc_found: list[Any] = []
        for m in ioc_data.get("matches", []):
            if isinstance(m, dict):
                ioc_found.append(m.get("ioc") or m)

        return {
            "is_threat": is_threat,
            "threat_type": "intrusion" if ioc_data.get("matches") else "reconnaissance",
            "confidence": round(conf, 3),
            "severity": str(incident.severity),
            "enriched_context": {
                "user_baseline_match": baseline_hint,
                "asset_criticality": "medium",
                "related_threat_actors": [],
                "historical_pattern": "new",
            },
            "iocs_found": ioc_found,
            "reasoning": (
                "Heuristic classification (no LLM API keys): "
                f"events={splunk_data.get('result_count', 0)}, "
                f"ioc_risk={ioc_data.get('risk_level')}, uba_risk={uba_risk}."
            ),
        }
