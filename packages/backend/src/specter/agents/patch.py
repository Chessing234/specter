"""Patch / remediation agent (stub)."""

from __future__ import annotations

from typing import Any

from specter.agents.base import BaseAgent


class PatchAgent(BaseAgent):
    """Patch agent placeholder."""

    name = "patch"

    async def process(self, incident: Any, findings: list[Any]) -> dict[str, Any]:
        _ = (incident, findings)
        return {"status": "skipped", "actions": []}
