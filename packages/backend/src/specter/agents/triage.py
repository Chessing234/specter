"""TRIAGE agent — alert prioritization using business impact and memory context."""

from __future__ import annotations

import json
from typing import Any

from langchain_core.messages import HumanMessage, SystemMessage

from specter.agents.base import BaseSpecterAgent
from specter.config import get_settings
from specter.models.agent import AgentType
from specter.models.incident import Incident


def _unwrap_detection_payload(payload: dict[str, Any] | None) -> dict[str, Any]:
    """Normalize SENTRY bus payload into the inner detection_result dict."""
    if not isinstance(payload, dict):
        return {}
    outer = payload.get("detection_result")
    if not isinstance(outer, dict):
        return {}
    inner = outer.get("detection_result")
    if isinstance(inner, dict):
        return inner
    return outer


class TriageAgent(BaseSpecterAgent):
    """
    TRIAGE — prioritizes using asset criticality, SENTRY confidence, and org baselines.
    """

    agent_type = AgentType.TRIAGE

    def __init__(self) -> None:
        super().__init__()
        settings = get_settings()
        self._llm: Any = None
        if settings.anthropic_api_key:
            from langchain_anthropic import ChatAnthropic

            self._llm = ChatAnthropic(
                model=settings.default_llm_model,
                api_key=settings.anthropic_api_key,
                temperature=0.2,
            )
        elif settings.openai_api_key:
            from langchain_openai import ChatOpenAI

            self._llm = ChatOpenAI(
                model="gpt-4o",
                api_key=settings.openai_api_key,
                temperature=0.2,
            )

    def get_system_prompt(self) -> str:
        return """You are TRIAGE, the prioritization agent for SPECTER Security Operations.

Prioritize using:
1. Business impact (crown jewel vs dev)
2. Threat likelihood (SENTRY confidence, IOC context)
3. Organizational baselines (false positive suppression)
4. Regulatory / compliance implications when obvious

Priority bands:
- critical (90-100): confirmed or highly likely threat to crown jewels
- high (70-89): likely threat to production
- medium (40-69): needs investigation
- low (10-39): monitor
- ignore (0-9): likely benign / false positive

Return JSON only (no markdown fences):
{
  "priority_score": 72,
  "priority_level": "high",
  "business_impact": "production",
  "routing_decision": "investigate",
  "justification": "text",
  "false_positive_likelihood": 0.25,
  "recommended_actions": ["action"],
  "sla_minutes": 120
}
"""

    def get_capabilities(self) -> list[str]:
        return [
            "memory_query",
            "asset_criticality_lookup",
            "baseline_comparison",
            "risk_scoring",
        ]

    async def process(
        self,
        incident: Incident,
        detection_result: dict[str, Any] | None = None,
        memory_context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        action = self._create_action("triage", "priority_assessment")

        try:
            if memory_context is None:
                memory_context = await self._get_incident_context(incident)

            detection_inner = _unwrap_detection_payload(detection_result)

            asset_criticality = await self._get_asset_criticality(incident.raw_data or {})

            triage_result = await self._assess_priority(
                incident=incident,
                detection_result=detection_inner,
                memory_context=memory_context,
                asset_criticality=asset_criticality,
            )

            self._complete_action(action, triage_result)

            triage_result.setdefault("priority", triage_result.get("priority_level", "medium"))
            triage_result.setdefault("reasoning", triage_result.get("justification", ""))

            return triage_result

        except Exception as exc:  # noqa: BLE001
            self._fail_action(action, str(exc))
            return {
                "priority_score": 50,
                "priority_level": "medium",
                "routing_decision": "investigate",
                "justification": f"Triage error: {exc}; defaulting to medium",
                "false_positive_likelihood": 0.3,
                "recommended_actions": ["Manual review"],
                "sla_minutes": 240,
                "priority": "medium",
                "reasoning": str(exc),
            }

    async def _get_asset_criticality(self, raw_data: dict[str, Any]) -> str:
        host = raw_data.get("host") or raw_data.get("asset")
        if not host:
            return "unknown"

        entities = await self.memory.find_entities(
            entity_type="asset",
            name_pattern=str(host),
            limit=1,
        )
        if entities:
            props = entities[0].get("properties") or {}
            return str(props.get("criticality", "medium"))
        return "unknown"

    async def _assess_priority(
        self,
        incident: Incident,
        detection_result: dict[str, Any],
        memory_context: dict[str, Any],
        asset_criticality: str,
    ) -> dict[str, Any]:
        if self._llm is None:
            return self._heuristic_triage(
                incident, detection_result, memory_context, asset_criticality
            )

        entities = memory_context.get("related_entities") or []
        entity_names = [str(e.get("name", "")) for e in entities[:5] if isinstance(e, dict)]

        prompt = f"""
Prioritize this security alert:

ALERT:
- Title: {incident.title}
- Source Severity: {incident.severity}
- Raw Data: {incident.raw_data}

DETECTION (SENTRY):
- is_threat: {detection_result.get("is_threat")}
- threat_type: {detection_result.get("threat_type")}
- confidence: {detection_result.get("confidence")}
- IOC context in enriched_context: {detection_result.get("enriched_context", {})}

ORG CONTEXT:
- Asset criticality (memory): {asset_criticality}
- Related entities: {entity_names}
- Baselines available: {bool(memory_context.get("user_baselines"))}

Assign priority_score 0-100 and routing_decision.
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
            return json.loads(content.strip())
        except (json.JSONDecodeError, IndexError, ValueError):
            return {
                "priority_score": 60,
                "priority_level": "medium",
                "business_impact": (
                    asset_criticality if asset_criticality != "unknown" else "internal"
                ),
                "routing_decision": "investigate",
                "justification": content[:500],
                "false_positive_likelihood": 0.3,
                "recommended_actions": ["Investigate manually"],
                "sla_minutes": 240,
            }

    def _heuristic_triage(
        self,
        incident: Incident,
        detection_result: dict[str, Any],
        memory_context: dict[str, Any],
        asset_criticality: str,
    ) -> dict[str, Any]:
        sev_map = {"critical": 85, "high": 70, "medium": 50, "low": 30}
        score = float(sev_map.get(str(incident.severity), 50))

        crit_boost = {"critical": 12, "high": 8, "medium": 4, "low": 0, "unknown": 2}
        score += crit_boost.get(asset_criticality, 0)

        conf = float(detection_result.get("confidence") or 0.5)
        score = score * 0.6 + conf * 40 * 0.4

        if memory_context.get("user_baselines") and conf < 0.45:
            score -= 15

        fp = 0.25
        if detection_result.get("enriched_context", {}).get("user_baseline_match") == "normal":
            fp = min(0.85, fp + 0.35)

        score = max(0.0, min(100.0, score))

        if score >= 90:
            level, route, sla = "critical", "immediate_response", 30
        elif score >= 70:
            level, route, sla = "high", "investigate", 120
        elif score >= 40:
            level, route, sla = "medium", "investigate", 240
        elif score >= 10:
            level, route, sla = "low", "monitor", 1440
        else:
            level, route, sla = "ignore", "ignore", 0

        return {
            "priority_score": int(round(score)),
            "priority_level": level,
            "business_impact": asset_criticality if asset_criticality != "unknown" else "internal",
            "routing_decision": route,
            "justification": (
                "Heuristic triage (no LLM keys): severity="
                f"{incident.severity}, asset_criticality={asset_criticality}, "
                f"detection_confidence={conf:.2f}, fp_hint={fp:.2f}."
            ),
            "false_positive_likelihood": round(fp, 3),
            "recommended_actions": [
                "Validate with owner",
                "Correlate with recent changes",
            ],
            "sla_minutes": sla,
        }
