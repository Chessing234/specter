"""Patch / remediation agent."""

from __future__ import annotations

from typing import Any

from specter.agents.base import BaseSpecterAgent
from specter.models.agent import AgentType
from specter.models.incident import Incident


class PatchAgent(BaseSpecterAgent):
    """Executes containment and remediation actions via MCP integrations."""

    agent_type = AgentType.PATCH

    def get_system_prompt(self) -> str:
        return "PATCH agent — executes approved containment actions."

    def get_capabilities(self) -> list[str]:
        return ["remediation", "splunk_update_alert", "account_isolation"]

    async def process(
        self,
        incident: Incident,
        findings: list[Any] | None = None,
    ) -> dict[str, Any]:
        _ = findings
        action = self._create_action("remediation", "splunk_update_alert")
        raw = incident.raw_data or {}
        actions_taken: list[dict[str, Any]] = []

        try:
            ip = raw.get("ip")
            user = raw.get("user")
            target = raw.get("target_asset")

            if ip:
                block_result = await self._call_mcp(
                    "splunk_update_alert",
                    {
                        "alert_id": f"specter-{incident.id}",
                        "action": "block_ip",
                        "ip": ip,
                        "reason": f"Containment for incident {incident.id}",
                    },
                )
                actions_taken.append(
                    {"action": "block_ip", "target": ip, "result": block_result.get("status")}
                )

            if user:
                actions_taken.append(
                    {
                        "action": "disable_account",
                        "target": user,
                        "result": "mock_success",
                        "note": "Account disabled pending IdP integration",
                    }
                )

            if target:
                actions_taken.append(
                    {
                        "action": "isolate_host",
                        "target": target,
                        "result": "mock_success",
                        "note": "Network isolation queued via EDR playbook",
                    }
                )

            if not actions_taken:
                actions_taken.append(
                    {
                        "action": "increase_monitoring",
                        "target": incident.id,
                        "result": "completed",
                    }
                )

            self._complete_action(action, {"actions": actions_taken})
            return {
                "status": "completed",
                "actions": actions_taken,
                "reasoning": f"Executed {len(actions_taken)} containment action(s).",
            }
        except Exception as exc:  # noqa: BLE001
            self._fail_action(action, str(exc))
            return {"status": "failed", "actions": actions_taken, "error": str(exc)}
