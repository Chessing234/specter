"""Sola Security MCP adapter for SPECTER (Boring Security / hackathon).

Typed tools for access reviews, compliance evidence, identity hygiene, cloud
assets, and risk scoring. Uses the Sola HTTP API when reachable; otherwise
returns structured mock payloads suitable for demos and tests.
"""

from __future__ import annotations

import tempfile
import time
from pathlib import Path
from typing import Any

import httpx

from specter.config import get_settings
from specter.mcp.adapters.base import MCPAdapter
from specter.models.mcp import MCPAdapterType, MCPToolCall, MCPToolDefinition, MCPToolResult


class SolaAdapter(MCPAdapter):
    """Sola Security — access reviews, compliance, identity hygiene, assets, risk."""

    SUPPORTED_PLATFORMS = [
        "aws",
        "azure",
        "gcp",
        "okta",
        "google_workspace",
        "github",
        "crowdstrike",
        "sentinelone",
        "jamf",
    ]

    COMPLIANCE_FRAMEWORKS: dict[str, list[str]] = {
        "soc2": ["CC6.1", "CC6.2", "CC6.3", "CC7.1", "CC7.2"],
        "iso27001": ["A.9.1", "A.9.2", "A.9.3", "A.12.1", "A.12.4"],
        "pci_dss": ["7.1", "7.2", "8.1", "8.2"],
    }

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str | None = None,
    ) -> None:
        super().__init__()
        settings = get_settings()
        self.api_key = (api_key if api_key is not None else settings.sola_api_key) or ""
        self.base_url = (base_url or settings.sola_base_url).rstrip("/")
        self._client: httpx.AsyncClient | None = None
        self._mock_mode = False
        self._tools = self._define_tools()

    @property
    def adapter_type(self) -> MCPAdapterType:
        return MCPAdapterType.SOLA

    @property
    def adapter_name(self) -> str:
        return "Sola Security"

    def _define_tools(self) -> list[MCPToolDefinition]:
        plat = list(self.SUPPORTED_PLATFORMS)
        return [
            MCPToolDefinition(
                name="sola_access_review",
                description=(
                    "Automated access review across connected platforms: overprivileged roles, "
                    "dormant access, SoD issues; optional HTML/JSON/CSV-style structured output."
                ),
                adapter=MCPAdapterType.SOLA,
                parameters={
                    "platforms": {
                        "type": "array",
                        "items": {"type": "string", "enum": plat},
                        "description": "Platforms to review",
                    },
                    "include_dormant": {
                        "type": "boolean",
                        "description": "Flag dormant accounts",
                        "default": True,
                    },
                    "dormant_threshold_days": {
                        "type": "integer",
                        "description": "Inactivity days for dormant",
                        "default": 90,
                    },
                    "include_overprivileged": {
                        "type": "boolean",
                        "default": True,
                    },
                    "include_sod_violations": {
                        "type": "boolean",
                        "default": True,
                    },
                    "output_format": {
                        "type": "string",
                        "enum": ["json", "html", "csv"],
                        "default": "html",
                    },
                },
                returns={
                    "report_url": {"type": "string"},
                    "findings": {"type": "array"},
                    "statistics": {"type": "object"},
                    "risk_score": {"type": "number"},
                },
                read_only=True,
            ),
            MCPToolDefinition(
                name="sola_compliance_evidence",
                description=(
                    "Collect compliance-oriented evidence for SOC2 / ISO 27001 / PCI-DSS "
                    "style control coverage (structured bundle; HTML report path when mocked)."
                ),
                adapter=MCPAdapterType.SOLA,
                parameters={
                    "framework": {
                        "type": "string",
                        "enum": ["soc2", "iso27001", "pci_dss"],
                        "description": "Compliance framework",
                    },
                    "controls": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Specific controls (empty = auto subset)",
                        "default": [],
                    },
                    "platforms": {
                        "type": "array",
                        "items": {"type": "string", "enum": plat},
                        "description": "Platforms to gather evidence from",
                    },
                },
                returns={
                    "evidence_package": {"type": "object"},
                    "coverage_percentage": {"type": "number"},
                    "missing_controls": {"type": "array"},
                    "report_url": {"type": "string"},
                },
                read_only=True,
            ),
            MCPToolDefinition(
                name="sola_identity_hygiene",
                description=(
                    "Identity hygiene: orphaned accounts, stale credentials, MFA gaps, "
                    "offboarding and privilege creep signals."
                ),
                adapter=MCPAdapterType.SOLA,
                parameters={
                    "platforms": {"type": "array", "items": {"type": "string", "enum": plat}},
                    "checks": {
                        "type": "array",
                        "items": {
                            "type": "string",
                            "enum": [
                                "orphaned_accounts",
                                "stale_passwords",
                                "mfa_gaps",
                                "offboarding_issues",
                                "privilege_creep",
                            ],
                        },
                        "default": [
                            "orphaned_accounts",
                            "mfa_gaps",
                            "offboarding_issues",
                        ],
                    },
                },
                returns={
                    "findings": {"type": "array"},
                    "hygiene_score": {"type": "number"},
                    "by_platform": {"type": "object"},
                    "recommendations": {"type": "array"},
                },
                read_only=True,
            ),
            MCPToolDefinition(
                name="sola_get_assets",
                description=(
                    "Asset inventory from Sola-connected clouds (AWS/Azure/GCP) with "
                    "encryption posture hints."
                ),
                adapter=MCPAdapterType.SOLA,
                parameters={
                    "platform": {"type": "string", "enum": ["aws", "azure", "gcp"]},
                    "asset_types": {
                        "type": "array",
                        "items": {
                            "type": "string",
                            "enum": ["compute", "database", "storage", "network", "iam"],
                        },
                        "default": ["compute", "database", "storage"],
                    },
                    "include_unencrypted": {
                        "type": "boolean",
                        "description": "Flag unencrypted resources",
                        "default": True,
                    },
                },
                returns={
                    "assets": {"type": "array"},
                    "unencrypted_assets": {"type": "array"},
                    "statistics": {"type": "object"},
                },
                read_only=True,
            ),
            MCPToolDefinition(
                name="sola_risk_score",
                description="Aggregate risk score for a user, asset, or organization scope.",
                adapter=MCPAdapterType.SOLA,
                parameters={
                    "entity_type": {"type": "string", "enum": ["user", "asset", "organization"]},
                    "entity_id": {
                        "type": "string",
                        "description": "Entity id or 'all' for organization",
                        "default": "all",
                    },
                    "factors": {
                        "type": "array",
                        "items": {
                            "type": "string",
                            "enum": [
                                "access_scope",
                                "activity_level",
                                "compliance_gaps",
                                "threat_exposure",
                            ],
                        },
                        "default": [
                            "access_scope",
                            "activity_level",
                            "compliance_gaps",
                        ],
                    },
                },
                returns={
                    "risk_score": {"type": "number"},
                    "risk_level": {"type": "string"},
                    "factors": {"type": "array"},
                    "trend": {"type": "string"},
                },
                read_only=True,
            ),
        ]

    async def connect(self) -> bool:
        self._mock_mode = False
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            headers=headers,
            timeout=httpx.Timeout(45.0),
        )

        if not self.api_key.strip():
            await self._enter_mock_client()
            return True

        try:
            assert self._client is not None
            response = await self._client.get("/v1/health")
            if response.status_code == 200:
                self._connected = True
                return True
        except Exception:  # noqa: BLE001
            pass

        await self._enter_mock_client()
        return True

    async def _enter_mock_client(self) -> None:
        """Keep a client for optional live calls later; mark mock for handlers."""
        if self._client is not None:
            await self._client.aclose()
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=httpx.Timeout(45.0),
        )
        self._mock_mode = True
        self._connected = True

    async def disconnect(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None
        self._connected = False

    async def discover_tools(self) -> list[MCPToolDefinition]:
        return list(self._tools)

    async def execute(self, call: MCPToolCall) -> MCPToolResult:
        start = time.perf_counter()
        handlers: dict[str, Any] = {
            "sola_access_review": self._handle_access_review,
            "sola_compliance_evidence": self._handle_compliance,
            "sola_identity_hygiene": self._handle_hygiene,
            "sola_get_assets": self._handle_assets,
            "sola_risk_score": self._handle_risk_score,
        }
        handler = handlers.get(call.tool_name)
        if not handler:
            return self._create_error_result(call, f"Unknown Sola tool: {call.tool_name}")
        try:
            data = await handler(call.parameters)
            ms = int((time.perf_counter() - start) * 1000)
            return self._create_success_result(call, data, ms)
        except Exception as exc:  # noqa: BLE001
            return self._create_error_result(call, str(exc))

    async def health_check(self) -> dict[str, Any]:
        return {
            "status": "healthy" if self._connected else "unhealthy",
            "adapter": "sola",
            "base_url": self.base_url,
            "mock_mode": self._mock_mode,
            "tools_available": len(self._tools),
        }

    async def _handle_access_review(self, params: dict[str, Any]) -> dict[str, Any]:
        if self._mock_mode:
            return self._mock_access_review(params)
        assert self._client is not None
        response = await self._client.post("/v1/access-review", json=params)
        response.raise_for_status()
        return response.json()

    async def _handle_compliance(self, params: dict[str, Any]) -> dict[str, Any]:
        if self._mock_mode:
            return self._mock_compliance(params)
        assert self._client is not None
        response = await self._client.post("/v1/compliance/evidence", json=params)
        response.raise_for_status()
        return response.json()

    async def _handle_hygiene(self, params: dict[str, Any]) -> dict[str, Any]:
        if self._mock_mode:
            return self._mock_hygiene(params)
        assert self._client is not None
        response = await self._client.post("/v1/identity/hygiene", json=params)
        response.raise_for_status()
        return response.json()

    async def _handle_assets(self, params: dict[str, Any]) -> dict[str, Any]:
        if self._mock_mode:
            return self._mock_assets(params)
        assert self._client is not None
        response = await self._client.get("/v1/assets", params=params)
        response.raise_for_status()
        return response.json()

    async def _handle_risk_score(self, params: dict[str, Any]) -> dict[str, Any]:
        if self._mock_mode:
            return self._mock_risk(params)
        assert self._client is not None
        response = await self._client.post("/v1/risk/score", json=params)
        response.raise_for_status()
        return response.json()

    def _temp_report_path(self, prefix: str, suffix: str) -> str:
        base = Path(tempfile.gettempdir()) / "specter_sola"
        base.mkdir(parents=True, exist_ok=True)
        path = base / f"{prefix}_{int(time.time())}.{suffix}"
        if suffix == "html":
            path.write_text(
                "<!DOCTYPE html><html><head><title>SPECTER — Sola report</title></head>"
                "<body><h1>Automated access review</h1><p>Generated by SPECTER Sola adapter."
                "</p></body></html>\n",
                encoding="utf-8",
            )
        else:
            path.write_text("{}", encoding="utf-8")
        return str(path)

    def _mock_access_review(self, params: dict[str, Any]) -> dict[str, Any]:
        platforms = params.get("platforms") or ["aws", "okta", "github"]
        fmt = str(params.get("output_format", "html"))
        suffix = "html" if fmt == "html" else "json"
        return {
            "report_url": self._temp_report_path("access_review", suffix),
            "findings": [
                {
                    "platform": "aws",
                    "user": "alice@company.com",
                    "issue": "dormant_access",
                    "details": "IAM admin access unused for 120 days",
                    "recommendation": "Remove admin; retain read-only",
                    "severity": "medium",
                },
                {
                    "platform": "okta",
                    "user": "bob@company.com",
                    "issue": "overprivileged",
                    "details": "Super Admin where Group Admin suffices",
                    "recommendation": "Downgrade role",
                    "severity": "high",
                },
                {
                    "platform": "github",
                    "user": "charlie@company.com",
                    "issue": "sod_violation",
                    "details": "Merge + production deploy on same principal",
                    "recommendation": "Split duties",
                    "severity": "critical",
                },
            ],
            "statistics": {
                "total_accounts_reviewed": 150,
                "issues_found": 23,
                "by_platform": dict.fromkeys(platforms, 8),
                "dormant_accounts": 12,
                "overprivileged_accounts": 7,
                "sod_violations": 4,
            },
            "risk_score": 35.0,
        }

    def _mock_compliance(self, params: dict[str, Any]) -> dict[str, Any]:
        framework = str(params.get("framework", "soc2"))
        controls = params.get("controls") or []
        default_controls = self.COMPLIANCE_FRAMEWORKS.get(framework, ["CC6.1", "CC6.2"])
        use_controls = controls if controls else default_controls[:2]
        package: dict[str, Any] = {}
        for code in use_controls:
            package[code] = {
                "control": f"{framework.upper()} {code}",
                "evidence": [
                    {
                        "type": "screenshot",
                        "description": "MFA enforcement (Okta)",
                        "path": f"/evidence/{code}_mfa.png",
                    },
                ],
                "status": "compliant" if code.endswith("1") else "partial",
            }
        suffix = "html"
        return {
            "evidence_package": package,
            "coverage_percentage": 78.0,
            "missing_controls": [c for c in default_controls if c not in package],
            "report_url": self._temp_report_path(f"compliance_{framework}", suffix),
        }

    def _mock_hygiene(self, params: dict[str, Any]) -> dict[str, Any]:
        platforms = params.get("platforms") or ["aws", "okta", "github"]
        return {
            "findings": [
                {
                    "platform": "aws",
                    "check": "orphaned_accounts",
                    "finding": "5 IAM users for terminated employees",
                    "severity": "high",
                    "users": ["former1@company.com", "former2@company.com"],
                },
                {
                    "platform": "okta",
                    "check": "mfa_gaps",
                    "finding": "12 users without enforced MFA",
                    "severity": "medium",
                    "count": 12,
                },
            ],
            "hygiene_score": 72.0,
            "by_platform": {
                "aws": {"score": 65, "issues": 3},
                "okta": {"score": 80, "issues": 1},
                "github": {"score": 85, "issues": 0},
            },
            "recommendations": [
                f"Review platforms: {', '.join(platforms)}",
                "Remove orphaned IAM users",
                "Enforce MFA for all Okta users",
            ],
        }

    def _mock_assets(self, params: dict[str, Any]) -> dict[str, Any]:
        platform = str(params.get("platform", "aws"))
        return {
            "assets": [
                {
                    "id": "i-12345",
                    "type": "compute",
                    "name": "prod-web-01",
                    "platform": platform,
                    "encrypted": True,
                },
                {
                    "id": "i-67890",
                    "type": "compute",
                    "name": "dev-web-01",
                    "platform": platform,
                    "encrypted": False,
                },
                {
                    "id": "db-001",
                    "type": "database",
                    "name": "prod-postgres",
                    "platform": platform,
                    "encrypted": True,
                },
            ],
            "unencrypted_assets": [
                {
                    "id": "i-67890",
                    "type": "compute",
                    "name": "dev-web-01",
                    "platform": platform,
                    "risk": "medium",
                },
            ],
            "statistics": {
                "total": 45,
                "encrypted": 44,
                "unencrypted": 1,
                "by_type": {"compute": 20, "database": 10, "storage": 15},
                "platform": platform,
            },
        }

    def _mock_risk(self, params: dict[str, Any]) -> dict[str, Any]:
        entity_id = str(params.get("entity_id", "all"))
        entity_type = str(params.get("entity_type", "organization"))
        return {
            "entity_type": entity_type,
            "entity_id": entity_id,
            "risk_score": 42.0,
            "risk_level": "medium",
            "factors": [
                {"name": "access_scope", "score": 35, "weight": 0.3},
                {"name": "activity_level", "score": 50, "weight": 0.2},
                {"name": "compliance_gaps", "score": 40, "weight": 0.3},
                {"name": "threat_exposure", "score": 45, "weight": 0.2},
            ],
            "trend": "stable",
        }
