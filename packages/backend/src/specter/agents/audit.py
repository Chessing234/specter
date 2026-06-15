"""AUDIT agent — compliance automation and access reviews via Sola (MCP)."""

from __future__ import annotations

import html
import json
import re
from datetime import UTC, datetime, timedelta
from typing import Any

from langchain_core.messages import HumanMessage, SystemMessage

from specter.agents.base import BaseSpecterAgent
from specter.config import get_settings
from specter.models.agent import AgentType
from specter.models.incident import Incident


def _mcp_data(resp: dict[str, Any]) -> dict[str, Any]:
    if resp.get("status") == "success" and isinstance(resp.get("data"), dict):
        return resp["data"]
    return {}


def _finding_row(finding: Any) -> dict[str, Any]:
    if hasattr(finding, "model_dump"):
        return finding.model_dump(mode="python")
    if isinstance(finding, dict):
        return finding
    return {}


class AuditAgent(BaseSpecterAgent):
    """
    AUDIT — automates access reviews, SOC2-style evidence collection, and identity
    hygiene using the Sola Security platform (MCP), plus organizational memory for
    user context on findings.
    """

    agent_type = AgentType.AUDIT

    def __init__(self) -> None:
        super().__init__()
        settings = get_settings()
        self._llm: Any = None
        if settings.anthropic_api_key:
            from langchain_anthropic import ChatAnthropic

            self._llm = ChatAnthropic(
                model=settings.default_llm_model,
                api_key=settings.anthropic_api_key,
                temperature=0.3,
            )
        elif settings.openai_api_key:
            from langchain_openai import ChatOpenAI

            self._llm = ChatOpenAI(
                model="gpt-4o",
                api_key=settings.openai_api_key,
                temperature=0.3,
            )

    def get_system_prompt(self) -> str:
        return """You are AUDIT, the compliance automation agent for SPECTER.

Eliminate tedious security work: access reviews, auditor evidence packs, dormant
accounts, and offboarding gaps. Be specific (principal, platform, date); never vague.

When asked for JSON, return JSON only (no markdown fences)."""

    def get_capabilities(self) -> list[str]:
        return [
            "sola_access_review",
            "sola_compliance_evidence",
            "sola_identity_hygiene",
            "sola_get_assets",
            "sola_risk_score",
            "memory_query",
        ]

    async def process(
        self,
        incident: Incident | None = None,
        findings: list[Any] | None = None,
        actions: list[Any] | None = None,
    ) -> dict[str, Any]:
        action = self._create_action("audit", "compliance_automation")
        try:
            if incident is not None and incident.source == "scheduled_audit":
                payload = await self._run_scheduled_audit()
                self._complete_action(
                    action,
                    {"mode": "scheduled_audit", "sections": list(payload.keys())},
                )
                return {"status": "completed", "mode": "scheduled_audit", **payload}

            payload = await self._document_incident(incident, findings, actions)
            self._complete_action(action, {"mode": "post_incident"})
            return {"status": "completed", "mode": "post_incident", **payload}
        except Exception as exc:  # noqa: BLE001
            self._fail_action(action, str(exc))
            return {"status": "error", "error": str(exc)}

    async def _run_scheduled_audit(self) -> dict[str, Any]:
        access_review = await self._run_access_review()
        hygiene = await self._run_hygiene_check()
        compliance = await self._collect_compliance_evidence()
        org_risk = _mcp_data(
            await self._call_mcp(
                "sola_risk_score",
                {
                    "entity_type": "organization",
                    "entity_id": "all",
                    "factors": ["access_scope", "compliance_gaps", "activity_level"],
                },
            )
        )
        report = await self._generate_unified_report(
            {
                "access_review": access_review,
                "identity_hygiene": hygiene,
                "compliance": compliance,
                "organization_risk": org_risk,
            }
        )
        digest = await self._weekly_digest_stub(hygiene, access_review)

        return {
            "access_review": access_review,
            "identity_hygiene": hygiene,
            "compliance": compliance,
            "organization_risk": org_risk,
            "unified_report": report,
            "weekly_digest_preview": digest,
        }

    async def _run_access_review(self) -> dict[str, Any]:
        result = await self._call_mcp(
            "sola_access_review",
            {
                "platforms": ["aws", "okta", "github", "gcp"],
                "include_dormant": True,
                "dormant_threshold_days": 90,
                "include_overprivileged": True,
                "include_sod_violations": True,
                "output_format": "html",
            },
        )
        if result.get("status") == "error":
            return {
                "status": "error",
                "error": result.get("error", "access_review_failed"),
            }

        data = _mcp_data(result)
        raw_findings = data.get("findings") or []
        enhanced: list[dict[str, Any]] = []
        for finding in raw_findings:
            if not isinstance(finding, dict):
                continue
            row = dict(finding)
            user = str(row.get("user", "") or "")
            if user:
                user_ctx = await self.memory.find_entities(
                    entity_type="user",
                    name_pattern=user,
                    limit=1,
                )
                if user_ctx:
                    props = user_ctx[0].get("properties") or {}
                    row["organizational_context"] = {
                        "department": props.get("department"),
                        "role": props.get("role"),
                        "manager": props.get("manager"),
                    }
            enhanced.append(row)

        stats = data.get("statistics") or {}
        return {
            "status": "completed",
            "findings": enhanced,
            "statistics": stats,
            "risk_score": data.get("risk_score", 0),
            "report_url": data.get("report_url"),
            "executive_summary": self._generate_access_review_summary(enhanced, stats),
        }

    async def _run_hygiene_check(self) -> dict[str, Any]:
        result = await self._call_mcp(
            "sola_identity_hygiene",
            {
                "platforms": ["aws", "okta", "github", "gcp", "google_workspace"],
                "checks": [
                    "orphaned_accounts",
                    "stale_passwords",
                    "mfa_gaps",
                    "offboarding_issues",
                    "privilege_creep",
                ],
            },
        )
        if result.get("status") == "error":
            return {
                "status": "error",
                "error": result.get("error", "hygiene_failed"),
                "findings": [],
                "hygiene_score": 0,
                "by_platform": {},
                "recommendations": [],
            }

        data = _mcp_data(result)
        return {
            "status": "completed",
            "findings": data.get("findings") or [],
            "hygiene_score": data.get("hygiene_score", 0),
            "by_platform": data.get("by_platform") or {},
            "recommendations": data.get("recommendations") or [],
        }

    async def _collect_compliance_evidence(self) -> dict[str, Any]:
        result = await self._call_mcp(
            "sola_compliance_evidence",
            {
                "framework": "soc2",
                "platforms": ["aws", "okta", "github"],
            },
        )
        if result.get("status") == "error":
            return {
                "status": "error",
                "error": result.get("error", "compliance_failed"),
                "evidence": {},
                "coverage": 0,
                "missing_controls": [],
            }

        data = _mcp_data(result)
        return {
            "status": "completed",
            "evidence": data.get("evidence_package") or {},
            "coverage": data.get("coverage_percentage", 0),
            "missing_controls": data.get("missing_controls") or [],
            "report_url": data.get("report_url"),
        }

    async def _document_incident(
        self,
        incident: Incident | None,
        findings: list[Any] | None,
        actions: list[Any] | None,
    ) -> dict[str, Any]:
        if incident is None:
            return {"incident_documentation": None, "note": "no_incident"}

        rows = [_finding_row(f) for f in (findings or [])]
        summaries = [str(r.get("description", "")) for r in rows if r.get("description")]

        action_types: list[str] = []
        for a in actions or []:
            if hasattr(a, "action_type"):
                action_types.append(str(a.action_type))
            elif isinstance(a, dict) and "action_type" in a:
                action_types.append(str(a["action_type"]))

        memory_hits = await self._query_memory(
            f"compliance context incident {incident.title} {incident.description}",
            limit=5,
        )

        doc = {
            "incident_id": incident.id,
            "title": incident.title,
            "severity": str(incident.severity),
            "status": str(incident.status),
            "source": incident.source,
            "findings_summary": summaries[:50],
            "actions_taken": action_types,
            "timeline": {
                "detected": incident.created_at.isoformat() if incident.created_at else None,
                "resolved": incident.resolved_at.isoformat() if incident.resolved_at else None,
            },
            "compliance_impact": await self._assess_compliance_impact(incident, rows),
            "memory_snippets": memory_hits,
        }

        return {"incident_documentation": doc}

    async def _assess_compliance_impact(
        self,
        incident: Incident,
        findings: list[dict[str, Any]] | None,
    ) -> dict[str, Any]:
        frameworks: dict[str, Any] = {
            "soc2": {"relevant_controls": [], "impact": "none"},
            "iso27001": {"relevant_controls": [], "impact": "none"},
        }
        if not findings:
            return frameworks

        for finding in findings:
            ftype = str(
                finding.get("type") or finding.get("finding_type") or "",
            ).lower()
            desc = str(finding.get("description", "")).lower()
            blob = f"{ftype} {desc}"
            if "data" in blob or "exfil" in blob:
                frameworks["soc2"]["relevant_controls"].extend(["CC6.1", "CC7.2"])
                frameworks["soc2"]["impact"] = "high"
            if "access" in blob or "privilege" in blob:
                frameworks["soc2"]["relevant_controls"].extend(["CC6.2", "CC6.3"])
                if frameworks["soc2"]["impact"] != "high":
                    frameworks["soc2"]["impact"] = "medium"

        for key in ("soc2", "iso27001"):
            ctrls = frameworks[key]["relevant_controls"]
            frameworks[key]["relevant_controls"] = sorted(set(ctrls))

        return frameworks

    async def _weekly_digest_stub(
        self,
        hygiene: dict[str, Any],
        access_review: dict[str, Any],
    ) -> dict[str, Any]:
        """Shape for weekly identity hygiene email / Slack digest (deterministic)."""
        window_end = datetime.now(UTC)
        window_start = window_end - timedelta(days=7)
        return {
            "window_start": window_start.isoformat(),
            "window_end": window_end.isoformat(),
            "hygiene_score": hygiene.get("hygiene_score"),
            "access_risk_score": access_review.get("risk_score"),
            "top_recommendations": (hygiene.get("recommendations") or [])[:5],
            "new_accounts_placeholder": "Wire HRIS → Sola for automated new-hire detection",
            "privilege_changes_placeholder": "Compare to last week's Sola export",
        }

    async def _generate_unified_report(self, results: dict[str, Any]) -> dict[str, Any]:
        access_review = results.get("access_review") or {}
        hygiene = results.get("identity_hygiene") or {}
        compliance = results.get("compliance") or {}
        org_risk = results.get("organization_risk") or {}

        generated = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
        stats = access_review.get("statistics") or {}
        issues = stats.get("issues_found", 0)
        total_acct = stats.get("total_accounts_reviewed", 0)
        dormant = stats.get("dormant_accounts", 0)
        overpriv = stats.get("overprivileged_accounts", 0)
        cov = compliance.get("coverage", 0)
        missing = compliance.get("missing_controls") or []
        miss_txt = ", ".join(str(m) for m in missing[:12])
        recs = hygiene.get("recommendations") or []
        rec_lines = "\n".join(f"- {r}" for r in recs[:8])

        summary = f"""# SPECTER Security Audit Report
**Generated:** {generated}

## Executive Summary
- **Access review risk score:** {access_review.get("risk_score", "N/A")}/100
- **Identity hygiene score:** {hygiene.get("hygiene_score", "N/A")}/100
- **SOC2 evidence coverage:** {cov}%
- **Organization risk (Sola):** {org_risk.get("risk_score", "N/A")}
  ({org_risk.get("risk_level", "n/a")})

## Access review
- Issues found: **{issues}** across **{total_acct}** accounts
- Dormant accounts: **{dormant}**; over-privileged: **{overpriv}**

## Identity hygiene
- Top recommendations:
{rec_lines or "- No recommendations returned"}

## Compliance
- Missing controls: {miss_txt or "(none listed)"}
"""

        narrative = await self._optional_executive_narrative(
            access_review, hygiene, compliance, org_risk
        )
        if narrative:
            summary += f"\n## LLM narrative\n{narrative}\n"

        return {
            "markdown": summary,
            "html": self._markdown_to_html(summary),
            "metrics": {
                "access_risk_score": access_review.get("risk_score", 0),
                "hygiene_score": hygiene.get("hygiene_score", 0),
                "compliance_coverage": compliance.get("coverage", 0),
                "org_risk_score": org_risk.get("risk_score", 0),
            },
        }

    async def _optional_executive_narrative(
        self,
        access_review: dict[str, Any],
        hygiene: dict[str, Any],
        compliance: dict[str, Any],
        org_risk: dict[str, Any],
    ) -> str:
        if self._llm is None:
            return ""
        blob = json.dumps(
            {
                "access": {
                    "risk_score": access_review.get("risk_score"),
                    "issues": (access_review.get("statistics") or {}).get("issues_found"),
                },
                "hygiene": {"score": hygiene.get("hygiene_score")},
                "compliance": {"coverage": compliance.get("coverage")},
                "org_risk": {
                    "score": org_risk.get("risk_score"),
                    "level": org_risk.get("risk_level"),
                },
            },
        )
        messages = [
            SystemMessage(content=self.get_system_prompt()),
            HumanMessage(
                content=(
                    "Write 3 short bullets for a CISO: what to fix first. Data:\n" + blob
                ),
            ),
        ]
        try:
            resp = await self._llm.ainvoke(messages)
            return str(resp.content).strip()[:1200]
        except Exception:  # noqa: BLE001
            return ""

    def _generate_access_review_summary(
        self,
        findings: list[dict[str, Any]],
        stats: dict[str, Any],
    ) -> str:
        if not findings:
            return "No issues found in access review. All clear."
        n = stats.get("issues_found", len(findings))
        lines = [f"Found {n} access issues:", ""]
        for f in findings[:5]:
            user = f.get("user", "Unknown")
            plat = f.get("platform", "?")
            issue = f.get("issue", "Unknown issue")
            rec = f.get("recommendation", "")
            lines.append(f"- **{user}** ({plat}): {issue} — {rec}")
        if len(findings) > 5:
            lines.append(f"- … and {len(findings) - 5} more")
        return "\n".join(lines)

    def _markdown_to_html(self, markdown: str) -> str:
        """Lightweight markdown → HTML (no third-party deps)."""
        text = markdown.rstrip("\n")
        blocks: list[str] = []
        for para in re.split(r"\n{2,}", text):
            lines = para.split("\n")
            chunk: list[str] = []
            in_list = False
            for line in lines:
                stripped = line.strip()
                if stripped.startswith("- "):
                    if not in_list:
                        chunk.append("<ul>")
                        in_list = True
                    item = html.escape(stripped[2:].strip())
                    item = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", item)
                    chunk.append(f"<li>{item}</li>")
                else:
                    if in_list:
                        chunk.append("</ul>")
                        in_list = False
                    if stripped.startswith("# "):
                        chunk.append(f"<h1>{html.escape(stripped[2:].strip())}</h1>")
                    elif stripped.startswith("## "):
                        chunk.append(f"<h2>{html.escape(stripped[3:].strip())}</h2>")
                    elif stripped.startswith("### "):
                        chunk.append(f"<h3>{html.escape(stripped[4:].strip())}</h3>")
                    elif stripped:
                        esc = html.escape(stripped)
                        esc = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", esc)
                        chunk.append(f"<p>{esc}</p>")
            if in_list:
                chunk.append("</ul>")
            blocks.append("\n".join(chunk))
        body = "\n".join(blocks)
        return (
            "<!DOCTYPE html><html><head><meta charset=\"utf-8\"/>"
            "<title>SPECTER — Audit report</title></head><body>"
            f"{body}</body></html>"
        )
