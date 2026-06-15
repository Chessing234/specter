"""SHERLOCK agent — forensic investigation via SIFT + Splunk + Memory Fabric."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any

from langchain_core.messages import HumanMessage, SystemMessage

from specter.agents.base import BaseSpecterAgent
from specter.config import get_settings
from specter.models.agent import AgentType
from specter.models.incident import Incident


def _mcp_data(resp: dict[str, Any]) -> dict[str, Any]:
    """Unwrap successful MCP tool body."""
    if resp.get("status") == "success" and isinstance(resp.get("data"), dict):
        return resp["data"]
    return {}


class SherlockAgent(BaseSpecterAgent):
    """
    SHERLOCK — DFIR-style investigation using SIFT (MCP), Splunk correlation,
    and organizational memory, with lightweight self-correction on discrepancies.
    """

    agent_type = AgentType.SHERLOCK

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
        self._max_iterations = 5
        self._correction_threshold = 0.7

    def get_system_prompt(self) -> str:
        return """You are SHERLOCK, the forensic investigation agent for SPECTER.

Investigate like a senior DFIR analyst:
1. Start from triage — what is already known?
2. Gather disk, memory, and log evidence systematically.
3. Cross-reference artifacts; resolve or flag contradictions.
4. Document reasoning at each step.

Self-correction:
- If artifacts disagree, say so and narrow the next query (time range, host, user).
- Do not report findings you cannot justify.

Return JSON only (no fences) with:
{
  "investigation_summary": "string",
  "timeline": [{"ts": "ISO", "event": "string"}],
  "findings": [
    {"type": "string", "description": "string", "significance": "low|medium|high|critical"}
  ],
  "indicators": [],
  "confidence": 0.0-1.0,
  "requires_human_review": true|false
}
"""

    def get_capabilities(self) -> list[str]:
        return [
            "extract_mft_timeline",
            "analyze_prefetch_files",
            "parse_registry_hives",
            "parse_amcache",
            "volatility_pslist",
            "volatility_netscan",
            "volatility_malfind",
            "volatility_cmdline",
            "correlate_disk_memory",
            "cross_reference_iocs",
            "generate_super_timeline",
            "auto_triage_disk",
            "auto_triage_memory",
            "splunk_search",
            "splunk_correlation_search",
        ]

    async def process(
        self,
        incident: Incident,
        triage_result: dict[str, Any] | None = None,
        existing_evidence: list[Any] | None = None,
        memory_context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        _ = (triage_result, existing_evidence)
        action = self._create_action("investigate", "forensic_analysis")
        steps: list[dict[str, Any]] = []
        all_findings: list[dict[str, Any]] = []

        try:
            if memory_context is None:
                memory_context = await self._get_incident_context(incident)

            raw = incident.raw_data or {}

            triage_data = await self._auto_triage(raw)
            steps.append(self._create_step(1, "auto_triage", triage_data))

            if raw.get("disk_image"):
                disk_findings = await self._analyze_disk(raw)
                steps.append(self._create_step(2, "disk_analysis", disk_findings))
                all_findings.extend(disk_findings.get("findings", []))

            if raw.get("memory_dump"):
                memory_findings = await self._analyze_memory(raw)
                steps.append(self._create_step(3, "memory_analysis", memory_findings))
                all_findings.extend(memory_findings.get("findings", []))

            if raw.get("disk_image") and raw.get("memory_dump"):
                correlation = await self._cross_reference(raw)
                steps.append(self._create_step(4, "correlation", correlation))
                disc = correlation.get("discrepancies") or []
                if disc:
                    correction = await self._self_correct(correlation, raw)
                    steps.append(self._create_step(5, "self_correction", correction))
                    for r in correction.get("resolved_findings", []):
                        if isinstance(r, dict):
                            all_findings.append(
                                {
                                    "type": "self_correction",
                                    "description": str(r.get("resolution", "adjusted analysis")),
                                    "evidence": [r],
                                    "significance": "medium",
                                }
                            )
                else:
                    for c in correlation.get("correlations", []) or []:
                        if isinstance(c, dict):
                            all_findings.append(
                                {
                                    "type": "correlation",
                                    "description": str(c.get("type", "correlated")),
                                    "evidence": [c],
                                    "significance": "medium",
                                }
                            )

            log_findings = await self._analyze_logs(raw, memory_context)
            steps.append(self._create_step(len(steps) + 1, "log_analysis", log_findings))
            all_findings.extend(log_findings.get("findings", []))

            final_report = await self._synthesize_report(
                incident=incident,
                steps=steps,
                findings=all_findings,
                memory_context=memory_context,
            )

            new_findings = self._build_new_findings(incident, all_findings)

            self._complete_action(
                action,
                {"steps_taken": len(steps), "findings": len(all_findings)},
            )

            reasoning_parts = [s.get("tool_used", "") for s in steps]
            reasoning = (
                f"SHERLOCK completed {len(steps)} steps: {', '.join(reasoning_parts)}. "
                f"{final_report.get('investigation_summary', '')[:400]}"
            )

            return {
                "status": "completed",
                "investigation_report": final_report,
                "steps": steps,
                "findings_count": len(all_findings),
                "new_findings": new_findings,
                "requires_human_review": bool(final_report.get("requires_human_review", False)),
                "reasoning": reasoning,
            }

        except Exception as exc:  # noqa: BLE001
            self._fail_action(action, str(exc))
            return {
                "status": "error",
                "error": str(exc),
                "steps": steps,
                "new_findings": [],
                "reasoning": str(exc),
            }

    def _build_new_findings(
        self,
        incident: Incident,
        items: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for idx, item in enumerate(items):
            fid = str(uuid.uuid4())
            out.append(
                {
                    "id": fid,
                    "incident_id": incident.id,
                    "agent": "sherlock",
                    "finding_type": str(item.get("type", "forensic")),
                    "description": str(item.get("description", ""))[:2000],
                    "evidence": item.get("evidence")
                    if isinstance(item.get("evidence"), list)
                    else [],
                    "confidence": 0.75 if item.get("significance") == "critical" else 0.65,
                    "verified": False,
                    "evidence_refs": [
                        {
                            "source": "sherlock",
                            "artifact": item.get("type"),
                            "idx": idx,
                        }
                    ],
                }
            )
        return out

    async def _auto_triage(self, raw_data: dict[str, Any]) -> dict[str, Any]:
        results: dict[str, Any] = {}
        if raw_data.get("disk_image"):
            resp = await self._call_mcp(
                "auto_triage_disk",
                {
                    "disk_image": raw_data["disk_image"],
                    "focus_areas": ["persistence", "execution"],
                },
            )
            results["disk"] = _mcp_data(resp)
        if raw_data.get("memory_dump"):
            resp = await self._call_mcp(
                "auto_triage_memory",
                {"memory_dump": raw_data["memory_dump"]},
            )
            results["memory"] = _mcp_data(resp)
        return {"findings": [], "raw": results, "confidence": 0.7}

    async def _analyze_disk(self, raw_data: dict[str, Any]) -> dict[str, Any]:
        disk_image = str(raw_data["disk_image"])
        findings: list[dict[str, Any]] = []

        mft = _mcp_data(
            await self._call_mcp("extract_mft_timeline", {"disk_image": disk_image})
        )
        timeline = mft.get("timeline") or []
        if timeline:
            suspicious = any("evil" in str(e).lower() for e in timeline)
            findings.append(
                {
                    "type": "mft_timeline",
                    "description": f"MFT entries: {mft.get('entry_count', len(timeline))}",
                    "evidence": timeline[:10],
                    "significance": "high" if suspicious else "medium",
                }
            )

        prefetch = _mcp_data(
            await self._call_mcp("analyze_prefetch_files", {"disk_image": disk_image})
        )
        susp = prefetch.get("suspicious_executions") or []
        if susp:
            findings.append(
                {
                    "type": "prefetch",
                    "description": f"Suspicious prefetch executions: {len(susp)}",
                    "evidence": susp,
                    "significance": "high",
                }
            )

        registry = _mcp_data(
            await self._call_mcp(
                "parse_registry_hives",
                {"disk_image": disk_image, "hives": ["SOFTWARE", "SYSTEM", "SAM"]},
            )
        )
        pers = registry.get("persistence_mechanisms") or []
        if pers:
            findings.append(
                {
                    "type": "registry",
                    "description": f"Persistence mechanisms: {len(pers)}",
                    "evidence": pers,
                    "significance": "critical",
                }
            )

        return {"findings": findings, "source": "disk"}

    async def _analyze_memory(self, raw_data: dict[str, Any]) -> dict[str, Any]:
        memory_dump = str(raw_data["memory_dump"])
        findings: list[dict[str, Any]] = []

        pslist = _mcp_data(
            await self._call_mcp("volatility_pslist", {"memory_dump": memory_dump})
        )
        sp = pslist.get("suspicious_processes") or []
        if sp:
            findings.append(
                {
                    "type": "suspicious_processes",
                    "description": f"Suspicious processes: {len(sp)}",
                    "evidence": sp,
                    "significance": "critical",
                }
            )

        netscan = _mcp_data(
            await self._call_mcp("volatility_netscan", {"memory_dump": memory_dump})
        )
        sc = netscan.get("suspicious_connections") or []
        if sc:
            findings.append(
                {
                    "type": "suspicious_connections",
                    "description": f"Suspicious connections: {len(sc)}",
                    "evidence": sc,
                    "significance": "high",
                }
            )

        malfind = _mcp_data(
            await self._call_mcp("volatility_malfind", {"memory_dump": memory_dump})
        )
        regions = malfind.get("suspicious_regions") or []
        if regions:
            findings.append(
                {
                    "type": "injected_code",
                    "description": f"Suspicious memory regions: {len(regions)}",
                    "evidence": regions,
                    "significance": "critical",
                }
            )

        cmdline = _mcp_data(
            await self._call_mcp("volatility_cmdline", {"memory_dump": memory_dump})
        )
        bad_cmd = cmdline.get("suspicious_commands") or []
        if bad_cmd:
            findings.append(
                {
                    "type": "suspicious_commands",
                    "description": f"Suspicious command lines: {len(bad_cmd)}",
                    "evidence": bad_cmd,
                    "significance": "high",
                }
            )

        return {"findings": findings, "source": "memory"}

    async def _cross_reference(self, raw_data: dict[str, Any]) -> dict[str, Any]:
        resp = await self._call_mcp(
            "correlate_disk_memory",
            {
                "disk_image": raw_data.get("disk_image"),
                "memory_dump": raw_data.get("memory_dump"),
                "correlation_types": ["process_execution", "network_activity"],
            },
        )
        return _mcp_data(resp)

    async def _self_correct(
        self,
        correlation: dict[str, Any],
        raw_data: dict[str, Any],
    ) -> dict[str, Any]:
        discrepancies = correlation.get("discrepancies") or []
        resolved: list[dict[str, Any]] = []

        for disc in discrepancies:
            if not isinstance(disc, dict):
                continue
            if disc.get("type") == "timeline_mismatch" and raw_data.get("disk_image"):
                adjusted = _mcp_data(
                    await self._call_mcp(
                        "generate_super_timeline",
                        {
                            "disk_image": raw_data.get("disk_image"),
                            "date_range": {
                                "start": str(disc.get("disk_time", "")),
                                "end": str(disc.get("memory_time", "")),
                            },
                        },
                    )
                )
                resolved.append(
                    {
                        "original_discrepancy": disc,
                        "resolution": "Re-ran super timeline with narrowed window",
                        "adjusted_timeline": adjusted.get("timeline", []),
                    }
                )
            else:
                resolved.append(
                    {
                        "original_discrepancy": disc,
                        "resolution": "Flagged for human review",
                        "requires_human_review": True,
                    }
                )

        return {
            "resolved_findings": resolved,
            "correlation_confidence": 0.85 if resolved else 0.6,
        }

    async def _analyze_logs(
        self,
        raw_data: dict[str, Any],
        memory_context: dict[str, Any],
    ) -> dict[str, Any]:
        _ = memory_context
        user = raw_data.get("user")
        ip = raw_data.get("ip")
        if not user and not ip:
            return {"findings": []}

        parts: list[str] = []
        if user:
            parts.append(f'user="{user}" OR src_user="{user}"')
        if ip:
            parts.append(f"src_ip={ip} OR dest_ip={ip}")
        spl = f"index=* ({' OR '.join(parts)}) earliest=-7d | sort -_time"

        result = _mcp_data(
            await self._call_mcp(
                "splunk_search",
                {"query": spl, "earliest": "-7d", "max_results": 50},
            )
        )
        rows = result.get("results") or []
        findings: list[dict[str, Any]] = []
        if rows:
            findings.append(
                {
                    "type": "log_correlation",
                    "description": f"Related log rows: {result.get('result_count', len(rows))}",
                    "evidence": rows[:5],
                    "significance": "medium",
                }
            )
        return {"findings": findings, "source": "logs"}

    async def _synthesize_report(
        self,
        incident: Incident,
        steps: list[dict[str, Any]],
        findings: list[dict[str, Any]],
        memory_context: dict[str, Any],
    ) -> dict[str, Any]:
        if self._llm is None:
            return self._heuristic_report(incident, steps, findings, memory_context)

        step_summary = json.dumps(
            [{"step": s.get("step"), "tool": s.get("tool_used")} for s in steps],
        )
        finding_summary = json.dumps(
            [{"type": f.get("type"), "sig": f.get("significance")} for f in findings[:20]],
        )
        n_entities = len(memory_context.get("related_entities", []))
        n_similar = len(memory_context.get("similar_incidents", []))

        prompt = f"""
Synthesize forensic investigation:

INCIDENT: {incident.title}
DESCRIPTION: {incident.description}

STEPS ({len(steps)}): {step_summary}

FINDINGS ({len(findings)}): {finding_summary}

CONTEXT: entities={n_entities}, similar={n_similar}
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

        return self._heuristic_report(
            incident,
            steps,
            findings,
            memory_context,
            fallback=content[:2000],
        )

    def _heuristic_report(
        self,
        incident: Incident,
        steps: list[dict[str, Any]],
        findings: list[dict[str, Any]],
        memory_context: dict[str, Any],
        *,
        fallback: str | None = None,
    ) -> dict[str, Any]:
        crit = sum(1 for f in findings if f.get("significance") == "critical")
        human = crit > 0 or len(findings) > 8
        summary = (
            f"Heuristic synthesis for '{incident.title}': {len(findings)} artifacts, "
            f"{crit} critical signals, {len(steps)} investigation steps."
        )
        if fallback:
            summary += f" LLM parse failed; excerpt: {fallback[:400]}"

        timeline = [
            {"ts": datetime.now(UTC).isoformat(), "event": s.get("tool_used", "step")}
            for s in steps[:10]
        ]
        indicators: list[str] = []
        for f in findings:
            for row in f.get("evidence", []) or []:
                if isinstance(row, dict):
                    for k in ("src_ip", "dest_ip", "program", "name"):
                        if row.get(k):
                            indicators.append(str(row[k]))

        return {
            "investigation_summary": summary,
            "timeline": timeline,
            "findings": findings[:25],
            "indicators": list(dict.fromkeys(indicators))[:30],
            "confidence": min(0.95, 0.45 + 0.05 * len(findings) + 0.1 * crit),
            "requires_human_review": human,
            "memory_entities_considered": len(memory_context.get("related_entities", [])),
        }

    def _create_step(self, step_num: int, tool: str, result: dict[str, Any]) -> dict[str, Any]:
        findings = []
        if isinstance(result.get("findings"), list):
            findings = result["findings"]
        return {
            "step": step_num,
            "tool_used": tool,
            "timestamp": datetime.now(UTC).isoformat(),
            "findings": findings,
            "confidence": float(result.get("confidence", 0.7)),
            "discrepancies": result.get("discrepancies", []),
        }
