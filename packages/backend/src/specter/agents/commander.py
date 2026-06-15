"""COMMANDER agent — incident command, containment, and SLA-aware planning."""

from __future__ import annotations

import json
from typing import Any

from langchain_core.messages import HumanMessage, SystemMessage

from specter.agents.base import BaseSpecterAgent
from specter.config import get_settings
from specter.models.agent import AgentType
from specter.models.incident import Incident


def _finding_as_dict(finding: Any) -> dict[str, Any]:
    if hasattr(finding, "model_dump"):
        return finding.model_dump(mode="python")
    if isinstance(finding, dict):
        return finding
    return {}


class CommanderAgent(BaseSpecterAgent):
    """
    COMMANDER — orchestrates response: scope, containment, playbooks, SLA targets.
    """

    agent_type = AgentType.COMMANDER

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
        return """You are COMMANDER, the incident command agent for SPECTER.

You manage incidents from assessment through containment planning:
1. Understand blast radius and business impact
2. Decide if containment is required and how urgent
3. Produce phased response plans with clear tasks
4. Note communications / legal triggers when appropriate

Return JSON only (no fences) describing phases with name, tasks (list), duration, owner_hint.
"""

    def get_capabilities(self) -> list[str]:
        return [
            "incident_assessment",
            "containment_recommendation",
            "playbook_generation",
            "sla_tracking",
            "report_generation",
        ]

    async def process(
        self,
        incident: Incident,
        findings: list[Any] | None = None,
        evidence: list[Any] | None = None,
    ) -> dict[str, Any]:
        _ = evidence
        action = self._create_action("command", "incident_assessment")
        findings = findings or []
        fd: list[dict[str, Any]] = [_finding_as_dict(f) for f in findings]

        try:
            scope = self._assess_scope(fd)
            containment = self._determine_containment(scope, fd)
            response_plan = await self._generate_response_plan(
                incident, scope, containment, fd
            )
            sla = self._calculate_sla(scope)

            self._complete_action(
                action,
                {"scope": scope, "containment": containment, "response_plan": response_plan},
            )

            needs_reval = bool(containment.get("action_required")) and scope["severity"] in (
                "critical",
                "high",
            )

            reasoning = (
                f"Scope={scope['severity']}, blast_radius={scope['blast_radius']}, "
                f"containment={containment.get('urgency')}, sla_minutes={sla}."
            )

            return {
                "scope_assessment": scope,
                "containment_decision": containment,
                "response_plan": response_plan,
                "requires_containment": bool(containment.get("action_required", False)),
                "sla_target_minutes": sla,
                "needs_revalidation": needs_reval,
                "reasoning": reasoning,
            }
        except Exception as exc:  # noqa: BLE001
            self._fail_action(action, str(exc))
            return {
                "requires_containment": False,
                "needs_revalidation": False,
                "sla_target_minutes": 480,
                "reasoning": str(exc),
                "error": str(exc),
            }

    def _assess_scope(self, findings: list[dict[str, Any]]) -> dict[str, Any]:
        critical = [f for f in findings if f.get("significance") == "critical"]
        high = [f for f in findings if f.get("significance") == "high"]

        affected: set[str] = set()
        for f in findings:
            for e in f.get("evidence", []) or []:
                if not isinstance(e, dict):
                    continue
                host = e.get("host") or e.get("name") or e.get("program")
                if host:
                    affected.add(str(host))

        sev = "critical" if critical else "high" if high else "medium"
        n = len(affected)
        blast = "organization" if n > 5 else "department" if n > 1 else "single_system"

        return {
            "severity": sev,
            "critical_findings": len(critical),
            "high_findings": len(high),
            "affected_systems_count": n,
            "affected_systems": list(affected)[:10],
            "blast_radius": blast,
        }

    def _determine_containment(
        self,
        scope: dict[str, Any],
        findings: list[dict[str, Any]],
    ) -> dict[str, Any]:
        has_malware = any(
            f.get("type") in {"injected_code", "suspicious_processes"}
            and f.get("significance") == "critical"
            for f in findings
        )
        has_active_c2 = any(f.get("type") == "suspicious_connections" for f in findings)

        if has_malware and has_active_c2:
            return {
                "action_required": True,
                "urgency": "immediate",
                "actions": [
                    "isolate_affected_systems",
                    "block_c2_ips",
                    "disable_compromised_accounts",
                ],
                "justification": "Malware indicators with suspicious network activity",
            }
        if has_malware:
            return {
                "action_required": True,
                "urgency": "high",
                "actions": ["isolate_affected_systems", "capture_memory_dump"],
                "justification": "Strong malware signals without confirmed C2",
            }
        if scope["severity"] == "critical":
            return {
                "action_required": True,
                "urgency": "high",
                "actions": ["increase_monitoring", "prepare_containment"],
                "justification": "Critical-scope incident — precautionary posture",
            }

        return {
            "action_required": False,
            "urgency": "none",
            "actions": ["continue_monitoring", "document_findings"],
            "justification": "No immediate containment required from current findings",
        }

    async def _generate_response_plan(
        self,
        incident: Incident,
        scope: dict[str, Any],
        containment: dict[str, Any],
        findings: list[dict[str, Any]],
    ) -> dict[str, Any]:
        if self._llm is None:
            return self._heuristic_plan(incident, scope, containment)

        finding_sample = json.dumps(
            [{"type": f.get("type"), "sig": f.get("significance")} for f in findings[:8]],
        )
        prompt = f"""
Incident response plan:

TITLE: {incident.title}
SEVERITY: {scope['severity']}
BLAST_RADIUS: {scope['blast_radius']}
AFFECTED_SYSTEMS: {scope['affected_systems_count']}

CONTAINMENT:
action_required={containment['action_required']}
urgency={containment['urgency']}
actions={containment['actions']}

FINDINGS (sample): {finding_sample}
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
            if isinstance(parsed, dict):
                return parsed
        except (json.JSONDecodeError, IndexError, ValueError):
            pass

        return self._heuristic_plan(incident, scope, containment)

    def _heuristic_plan(
        self,
        incident: Incident,
        scope: dict[str, Any],
        containment: dict[str, Any],
    ) -> dict[str, Any]:
        _ = incident
        phases = [
            {
                "name": "Assessment",
                "tasks": ["Confirm scope", "Notify IR lead"],
                "duration": "15 minutes",
                "owner_hint": "commander",
            },
            {
                "name": "Containment",
                "tasks": list(containment.get("actions", [])),
                "duration": "30-120 minutes",
                "owner_hint": "ir_team",
            },
            {
                "name": "Recovery",
                "tasks": ["Validate eradication", "Restore services"],
                "duration": "4 hours",
                "owner_hint": "it_ops",
            },
        ]
        if not containment.get("action_required"):
            phases = [phases[0], phases[2]]

        return {
            "phases": phases,
            "communication_plan": (
                "Notify security leadership; involve legal if data impact suspected. "
                f"Severity={scope['severity']}, blast_radius={scope['blast_radius']}."
            ),
        }

    def _calculate_sla(self, scope: dict[str, Any]) -> int:
        sla_map = {"critical": 60, "high": 240, "medium": 480, "low": 1440}
        return int(sla_map.get(str(scope["severity"]), 480))
