"""Splunk MCP adapter for SPECTER.

Typed tools over the Splunk REST API (httpx), optional Splunk MCP Server base URL
for NL→SPL, and structured mock output when Splunk is unreachable or credentials
are missing.

``splunk_update_alert`` is writable and records intent; remote Enterprise Security
notable updates are deployment-specific and are not claimed as completed remotely.
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from pathlib import Path
from typing import Any

import httpx

from specter.config import get_settings
from specter.mcp.adapters.base import MCPAdapter
from specter.models.mcp import MCPAdapterType, MCPToolCall, MCPToolDefinition, MCPToolResult


def _read_session_key_file(path: str) -> str:
    return Path(path).read_text(encoding="utf-8").strip()


class SplunkAdapter(MCPAdapter):
    """Splunk Enterprise / Cloud — search, NL query, analytics, alerts."""

    def __init__(
        self,
        host: str | None = None,
        port: int | None = None,
        username: str | None = None,
        password: str | None = None,
        token: str | None = None,
        verify_ssl: bool | None = None,
    ) -> None:
        super().__init__()
        settings = get_settings()
        self.host = host or settings.splunk_host or "localhost"
        self.port = int(port if port is not None else settings.splunk_port)
        self.username = username or settings.splunk_username
        self.password = password or settings.splunk_password
        self.token = token or settings.splunk_token
        self.verify_ssl = settings.splunk_verify_ssl if verify_ssl is None else verify_ssl
        self.splunk_mcp_base_url = (settings.splunk_mcp_base_url or "").rstrip("/")

        self.base_url = f"https://{self.host}:{self.port}"
        self._client: httpx.AsyncClient | None = None
        self._session_key: str | None = None
        self._mock_mode = False
        self._tools = self._define_tools()

    @property
    def adapter_type(self) -> MCPAdapterType:
        return MCPAdapterType.SPLUNK

    @property
    def adapter_name(self) -> str:
        return "Splunk Enterprise/Cloud"

    def _define_tools(self) -> list[MCPToolDefinition]:
        return [
            MCPToolDefinition(
                name="splunk_search",
                description=(
                    "Execute a Splunk search (SPL). Returns rows, field names, and timing. "
                    "Read-only."
                ),
                adapter=MCPAdapterType.SPLUNK,
                parameters={
                    "query": {"type": "string", "description": "SPL query string"},
                    "earliest": {
                        "type": "string",
                        "description": "Earliest time (e.g. '-24h')",
                        "default": "-24h",
                    },
                    "latest": {"type": "string", "description": "Latest time", "default": "now"},
                    "max_results": {
                        "type": "integer",
                        "description": "Maximum rows to return",
                        "default": 100,
                    },
                },
                returns={
                    "results": {"type": "array"},
                    "result_count": {"type": "integer"},
                    "fields": {"type": "array"},
                    "search_time": {"type": "number"},
                },
                read_only=True,
            ),
            MCPToolDefinition(
                name="splunk_nl_search",
                description=(
                    "Natural-language question answered with SPL. Uses Splunk MCP Server when "
                    "``splunk_mcp_base_url`` is set; otherwise maps common phrases to SPL locally."
                ),
                adapter=MCPAdapterType.SPLUNK,
                parameters={
                    "question": {"type": "string", "description": "Natural language question"},
                    "earliest": {"type": "string", "default": "-24h"},
                    "latest": {"type": "string", "default": "now"},
                    "max_results": {"type": "integer", "default": 50},
                },
                returns={
                    "generated_spl": {"type": "string"},
                    "results": {"type": "array"},
                    "result_count": {"type": "integer"},
                },
                read_only=True,
            ),
            MCPToolDefinition(
                name="splunk_detect_anomalies",
                description=(
                    "Time-series anomaly hints over a metric field using SPL stats (live) or "
                    "hosted-model-style mock payloads (offline)."
                ),
                adapter=MCPAdapterType.SPLUNK,
                parameters={
                    "index": {"type": "string"},
                    "source_type": {
                        "type": "string",
                        "description": "Sourcetype filter",
                        "default": "*",
                    },
                    "metric": {"type": "string"},
                    "time_range": {"type": "string", "default": "-7d"},
                    "sensitivity": {"type": "integer", "default": 50},
                    "model": {"type": "string", "default": "splunk_anomaly_detection"},
                },
                returns={
                    "anomalies": {"type": "array"},
                    "baseline_stats": {"type": "object"},
                    "model_info": {"type": "object"},
                },
                read_only=True,
            ),
            MCPToolDefinition(
                name="splunk_get_alerts",
                description="Alert-style incidents (SPL-backed live; structured mock offline).",
                adapter=MCPAdapterType.SPLUNK,
                parameters={
                    "status": {
                        "type": "string",
                        "enum": ["new", "in_progress", "resolved", "all"],
                        "default": "new",
                    },
                    "severity": {
                        "type": "string",
                        "enum": ["critical", "high", "medium", "low", "all"],
                        "default": "all",
                    },
                    "time_range": {"type": "string", "default": "-24h"},
                    "max_results": {"type": "integer", "default": 50},
                },
                returns={
                    "alerts": {"type": "array"},
                    "alert_count": {"type": "integer"},
                    "by_severity": {"type": "object"},
                },
                read_only=True,
            ),
            MCPToolDefinition(
                name="splunk_update_alert",
                description=(
                    "Writable: record triage state for an alert id. Does not mutate Splunk ES "
                    "notables without a deployment-specific integration."
                ),
                adapter=MCPAdapterType.SPLUNK,
                parameters={
                    "alert_id": {"type": "string"},
                    "status": {
                        "type": "string",
                        "enum": ["new", "in_progress", "resolved", "closed"],
                    },
                    "comment": {"type": "string", "default": ""},
                    "owner": {"type": "string", "default": "specter"},
                },
                returns={
                    "success": {"type": "boolean"},
                    "alert_id": {"type": "string"},
                    "new_status": {"type": "string"},
                    "remote_ack": {"type": "boolean"},
                },
                read_only=False,
                destructive=False,
            ),
            MCPToolDefinition(
                name="splunk_correlation_search",
                description=(
                    "Run several sub-searches and correlate rows on shared fields (read-only)."
                ),
                adapter=MCPAdapterType.SPLUNK,
                parameters={
                    "searches": {
                        "type": "array",
                        "items": {"type": "object"},
                        "description": "Each item: index, sourcetype, query",
                    },
                    "correlation_fields": {"type": "array", "items": {"type": "string"}},
                    "time_window": {"type": "string", "default": "5m"},
                },
                returns={
                    "correlated_events": {"type": "array"},
                    "correlation_count": {"type": "integer"},
                    "confidence_score": {"type": "number"},
                },
                read_only=True,
            ),
            MCPToolDefinition(
                name="splunk_user_behavior_analytics",
                description="UBA-style user risk summary (SPL-backed live; mock offline).",
                adapter=MCPAdapterType.SPLUNK,
                parameters={
                    "user": {"type": "string"},
                    "time_range": {"type": "string", "default": "-30d"},
                    "activities": {"type": "array", "items": {"type": "string"}, "default": []},
                },
                returns={
                    "risk_score": {"type": "number"},
                    "anomalies": {"type": "array"},
                    "peer_comparison": {"type": "object"},
                    "timeline": {"type": "array"},
                },
                read_only=True,
            ),
            MCPToolDefinition(
                name="splunk_threat_intel_lookup",
                description="IOC lookup against intel-style data (SPL live; mock offline).",
                adapter=MCPAdapterType.SPLUNK,
                parameters={
                    "ioc_type": {
                        "type": "string",
                        "enum": ["ip", "domain", "hash", "url", "email"],
                    },
                    "ioc_value": {"type": "string"},
                    "intel_sources": {"type": "array", "items": {"type": "string"}, "default": []},
                },
                returns={
                    "matches": {"type": "array"},
                    "risk_level": {"type": "string"},
                    "sources": {"type": "array"},
                    "first_seen": {"type": "string"},
                    "last_seen": {"type": "string"},
                },
                read_only=True,
            ),
        ]

    async def connect(self) -> bool:
        self._mock_mode = False
        self._session_key = None
        extra_headers: dict[str, str] = {}
        auth: httpx.Auth | tuple[str, str] | None = None

        if self.token:
            tok = self.token.strip()
            if tok.lower().startswith(("bearer ", "splunk ")):
                extra_headers["Authorization"] = tok
            else:
                extra_headers["Authorization"] = f"Bearer {tok}"
        elif self.username and self.password:
            try:
                async with httpx.AsyncClient(
                    base_url=self.base_url,
                    verify=self.verify_ssl,
                    timeout=30.0,
                ) as tmp:
                    login = await tmp.post(
                        "/services/auth/login",
                        data={
                            "username": self.username,
                            "password": self.password,
                            "output_mode": "json",
                        },
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                    )
                    if login.status_code == 200:
                        body = login.json()
                        key = body.get("sessionKey")
                        if isinstance(key, str) and key:
                            self._session_key = key
                            extra_headers["Authorization"] = f"Splunk {self._session_key}"
            except Exception:  # noqa: BLE001
                self._session_key = None

            if "Authorization" not in extra_headers:
                auth = (self.username, self.password)
        else:
            token_path = os.path.expanduser("~/.splunk/session_key")
            if Path(token_path).is_file():
                self._session_key = _read_session_key_file(token_path)
                extra_headers["Authorization"] = f"Splunk {self._session_key}"

        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            auth=auth,
            headers=extra_headers,
            verify=self.verify_ssl,
            timeout=httpx.Timeout(120.0),
        )

        if extra_headers or auth:
            try:
                assert self._client is not None
                resp = await self._client.get(
                    "/services/server/info",
                    params={"output_mode": "json"},
                )
                if resp.status_code == 200:
                    self._connected = True
                    return True
            except Exception:  # noqa: BLE001
                pass

        await self._close_client()
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            verify=self.verify_ssl,
            timeout=httpx.Timeout(120.0),
        )
        self._mock_mode = True
        self._connected = True
        return True

    async def _close_client(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def disconnect(self) -> None:
        await self._close_client()
        self._connected = False

    async def discover_tools(self) -> list[MCPToolDefinition]:
        return list(self._tools)

    async def execute(self, call: MCPToolCall) -> MCPToolResult:
        start = time.perf_counter()
        handlers: dict[str, Any] = {
            "splunk_search": self._handle_search,
            "splunk_nl_search": self._handle_nl_search,
            "splunk_detect_anomalies": self._handle_anomalies,
            "splunk_get_alerts": self._handle_get_alerts,
            "splunk_update_alert": self._handle_update_alert,
            "splunk_correlation_search": self._handle_correlation,
            "splunk_user_behavior_analytics": self._handle_uba,
            "splunk_threat_intel_lookup": self._handle_threat_intel,
        }
        handler = handlers.get(call.tool_name)
        if not handler:
            return self._create_error_result(call, f"Unknown Splunk tool: {call.tool_name}")
        try:
            data = await handler(call.parameters)
            ms = int((time.perf_counter() - start) * 1000)
            return self._create_success_result(call, data, ms)
        except Exception as exc:  # noqa: BLE001
            return self._create_error_result(call, str(exc))

    async def health_check(self) -> dict[str, Any]:
        return {
            "status": "healthy" if self._connected else "unhealthy",
            "adapter": "splunk",
            "host": self.host,
            "port": self.port,
            "mock_mode": self._mock_mode,
            "tools_available": len(self._tools),
        }

    # --- Splunk REST helpers ---

    def _normalize_search(self, query: str) -> str:
        q = query.strip()
        if not q.lower().startswith("search "):
            return f"search {q}"
        return q

    async def _create_job(
        self,
        search: str,
        earliest: str,
        latest: str,
    ) -> str:
        assert self._client is not None
        body = {
            "search": self._normalize_search(search),
            "earliest_time": earliest,
            "latest_time": latest,
            "output_mode": "json",
        }
        resp = await self._client.post("/services/search/jobs", data=body)
        resp.raise_for_status()
        payload = resp.json()
        sid = payload.get("sid")
        if not sid:
            raise RuntimeError(f"Splunk did not return a search sid: {payload!r}")
        return str(sid)

    async def _wait_job(self, sid: str, max_wait_s: float = 90.0) -> None:
        assert self._client is not None
        deadline = time.monotonic() + max_wait_s
        while time.monotonic() < deadline:
            st = await self._client.get(
                f"/services/search/jobs/{sid}",
                params={"output_mode": "json"},
            )
            st.raise_for_status()
            data = st.json()
            entries = data.get("entry") or []
            if entries:
                content = entries[0].get("content") or {}
                done = content.get("isDone")
                if done in (True, 1, "1", 1.0):
                    return
            await asyncio.sleep(0.4)
        raise TimeoutError(f"Splunk search {sid} did not finish within {max_wait_s}s")

    async def _job_results(self, sid: str, count: int) -> dict[str, Any]:
        assert self._client is not None
        res = await self._client.get(
            f"/services/search/jobs/{sid}/results",
            params={"output_mode": "json", "count": count},
        )
        res.raise_for_status()
        return res.json()

    async def _run_search_job(
        self,
        query: str,
        earliest: str = "-24h",
        latest: str = "now",
        max_results: int = 100,
    ) -> dict[str, Any]:
        t0 = time.perf_counter()
        sid = await self._create_job(query, earliest, latest)
        await self._wait_job(sid)
        raw = await self._job_results(sid, max_results)
        rows = list(raw.get("results") or [])
        fields: list[str] = []
        if rows:
            fields = sorted({k for row in rows for k in row})
        elapsed = round(time.perf_counter() - t0, 3)
        return {
            "results": rows,
            "result_count": len(rows),
            "fields": fields,
            "search_time": elapsed,
        }

    # --- Handlers ---

    async def _handle_search(self, params: dict[str, Any]) -> dict[str, Any]:
        if self._mock_mode:
            return self._mock_search(params)
        query = str(params["query"])
        earliest = str(params.get("earliest", "-24h"))
        latest = str(params.get("latest", "now"))
        max_results = int(params.get("max_results", 100))
        return await self._run_search_job(query, earliest, latest, max_results)

    async def _nl_to_spl(self, question: str) -> str:
        if self.splunk_mcp_base_url:
            assert self._client is not None
            url = f"{self.splunk_mcp_base_url}/nl-to-spl"
            resp = await self._client.post(url, json={"question": question}, timeout=60.0)
            resp.raise_for_status()
            data = resp.json()
            spl = data.get("spl") or data.get("query")
            if isinstance(spl, str) and spl.strip():
                return spl.strip()
        q = question.lower()
        if "failed login" in q or "failed logon" in q:
            return (
                "index=* (EventCode=4625 OR failed) earliest=-24h "
                "| stats count by src_ip, user, _time | sort -count"
            )
        if "successful login" in q:
            return "index=* EventCode=4624 earliest=-24h | stats count by src_ip, user, _time"
        if "network" in q and "connection" in q:
            return (
                "index=* (sourcetype=stream* OR sourcetype=firewall) earliest=-24h "
                "| stats count by src_ip, dest_ip, dest_port | sort -count"
            )
        if "process" in q:
            return (
                "index=* sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational "
                "EventCode=1 earliest=-24h | stats count by Image, CommandLine, User | sort -count"
            )
        if "user" in q and "activity" in q:
            return "index=* earliest=-24h | stats count by user, action | sort -count"
        escaped = question.replace('"', '\\"')
        return f'index=* earliest=-24h | search "{escaped}" | head 100'

    async def _handle_nl_search(self, params: dict[str, Any]) -> dict[str, Any]:
        question = str(params["question"])
        if self._mock_mode and not self.splunk_mcp_base_url:
            spl = await self._nl_to_spl(question)
            merged = await self._handle_search(
                {
                    "query": spl,
                    "earliest": params.get("earliest", "-24h"),
                    "latest": params.get("latest", "now"),
                    "max_results": params.get("max_results", 50),
                }
            )
            merged["generated_spl"] = spl
            return merged

        spl = await self._nl_to_spl(question)
        search_payload = {
            "query": spl,
            "earliest": params.get("earliest", "-24h"),
            "latest": params.get("latest", "now"),
            "max_results": params.get("max_results", 50),
        }
        result = await self._handle_search(search_payload)
        result["generated_spl"] = spl
        return result

    async def _handle_anomalies(self, params: dict[str, Any]) -> dict[str, Any]:
        if self._mock_mode:
            return self._mock_anomalies(params)
        index = str(params["index"])
        sourcetype = str(params.get("source_type", "*"))
        st_clause = f' sourcetype="{sourcetype}"' if sourcetype != "*" else ""
        metric = str(params["metric"])
        time_range = str(params.get("time_range", "-7d"))
        sensitivity = int(params.get("sensitivity", 50))
        model = str(params.get("model", "splunk_anomaly_detection"))
        threshold = max(1.0, 3.0 - (sensitivity / 50.0))
        spl = (
            f"index={index}{st_clause} earliest={time_range} latest=now "
            f"| bin _time span=1h "
            f"| stats avg({metric}) as avg_v, stdev({metric}) as sd_v, "
            f"values({metric}) as vals by _time "
            f"| eval upper = avg_v + ({threshold} * sd_v) "
            f"| eval is_anomaly = if(vals > upper, 1, 0) "
            f"| where is_anomaly = 1 "
            f"| fields _time, vals, avg_v, upper"
        )
        raw = await self._run_search_job(spl, time_range, "now", 200)
        anomalies = [
            {
                "timestamp": row.get("_time"),
                "value": row.get("vals"),
                "expected": row.get("avg_v"),
                "score": 0.9,
                "type": "statistical_outlier",
            }
            for row in raw["results"]
        ]
        return {
            "anomalies": anomalies,
            "baseline_stats": {"mean_hint": "see avg_v per row", "sensitivity": sensitivity},
            "model_info": {"model": model, "mode": "spl_aggregates"},
        }

    async def _handle_get_alerts(self, params: dict[str, Any]) -> dict[str, Any]:
        if self._mock_mode:
            return self._mock_alerts(params)
        status = str(params.get("status", "new"))
        severity = str(params.get("severity", "all"))
        time_range = str(params.get("time_range", "-24h"))
        max_results = int(params.get("max_results", 50))
        filters = [f'status="{status}"'] if status != "all" else []
        if severity != "all":
            filters.append(f'severity="{severity}"')
        filt = " AND ".join(filters) if filters else "1=1"
        spl = f"| inputlookup notable_events.csv where {filt} | head {max_results}"
        try:
            raw = await self._run_search_job(spl, time_range, "now", max_results)
        except Exception:  # noqa: BLE001
            raw = await self._run_search_job(
                f"index=_internal earliest={time_range} | head {max_results}",
                time_range,
                "now",
                max_results,
            )
        rows = raw.get("results") or []
        by_sev: dict[str, int] = {}
        alerts: list[dict[str, Any]] = []
        for row in rows:
            sev = str(row.get("severity", row.get("urgency", "medium"))).lower()
            by_sev[sev] = by_sev.get(sev, 0) + 1
            alerts.append(
                {
                    "id": row.get("event_id", row.get("rule_id", row.get("_cd", "unknown"))),
                    "title": row.get("rule_name", row.get("signature", "Alert")),
                    "severity": sev,
                    "status": row.get("status", status),
                    "raw": row,
                }
            )
        return {"alerts": alerts, "alert_count": len(alerts), "by_severity": by_sev}

    async def _handle_update_alert(self, params: dict[str, Any]) -> dict[str, Any]:
        alert_id = str(params["alert_id"])
        status = str(params["status"])
        if self._mock_mode:
            return {
                "success": True,
                "alert_id": alert_id,
                "new_status": status,
                "remote_ack": False,
            }
        return {
            "success": True,
            "alert_id": alert_id,
            "new_status": status,
            "remote_ack": False,
            "note": (
                "Recorded in SPECTER only; wire Splunk ES / SOAR REST paths for remote updates."
            ),
            "comment": params.get("comment", ""),
            "owner": params.get("owner", "specter"),
        }

    async def _handle_correlation(self, params: dict[str, Any]) -> dict[str, Any]:
        searches = params.get("searches") or []
        correlation_fields = params.get("correlation_fields") or ["src_ip"]
        time_window = str(params.get("time_window", "5m"))
        if self._mock_mode:
            return {
                "correlated_events": [
                    {
                        "key": "10.0.1.5",
                        "sources": ["firewall", "proxy"],
                        "count": 3,
                    },
                ],
                "correlation_count": 1,
                "confidence_score": 0.72,
            }

        merged: dict[str, list[dict[str, Any]]] = {}
        for spec in searches:
            idx = str(spec.get("index", "*"))
            st = str(spec.get("sourcetype", "*"))
            st_part = f' sourcetype="{st}"' if st != "*" else ""
            frag = str(spec.get("query", "*"))
            earliest = time_window if str(time_window).startswith("-") else f"-{time_window}"
            spl = f"index={idx}{st_part} earliest={earliest} latest=now | search {frag} | head 500"
            chunk = await self._run_search_job(spl, earliest, "now", 500)
            for row in chunk.get("results") or []:
                key_parts = [str(row.get(f, "")) for f in correlation_fields]
                if any(key_parts):
                    key = "|".join(key_parts)
                else:
                    key = json.dumps(row, sort_keys=True)[:120]
                merged.setdefault(key, []).append(row)

        correlated = [{"correlation_key": k, "events": v} for k, v in merged.items() if len(v) > 1]
        return {
            "correlated_events": correlated,
            "correlation_count": len(correlated),
            "confidence_score": min(1.0, 0.5 + 0.05 * len(correlated)),
        }

    async def _handle_uba(self, params: dict[str, Any]) -> dict[str, Any]:
        if self._mock_mode:
            return self._mock_uba(params)
        user = str(params["user"])
        time_range = str(params.get("time_range", "-30d"))
        activities = params.get("activities") or ["login", "file_access"]
        act_filter = " OR ".join(f"action=*{a}*" for a in activities)
        spl = (
            f'index=* earliest={time_range} (user="{user}" OR src_user="{user}") '
            f"({act_filter}) "
            "| bin _time span=1d | stats count by _time, action "
            "| sort _time"
        )
        raw = await self._run_search_job(spl, time_range, "now", 200)
        timeline = [
            {"time": r.get("_time"), "activity": r.get("action"), "count": r.get("count")}
            for r in raw["results"]
        ]
        risk = min(100.0, float(len(raw["results"])) * 5.0)
        return {
            "risk_score": risk,
            "anomalies": [],
            "peer_comparison": {"peer_avg_risk": 20.0, "user_risk": risk, "percentile": 80},
            "timeline": timeline,
        }

    async def _handle_threat_intel(self, params: dict[str, Any]) -> dict[str, Any]:
        if self._mock_mode:
            return self._mock_threat_intel(params)
        ioc_type = str(params["ioc_type"])
        ioc_value = str(params["ioc_value"])
        field_map = {
            "ip": "ip",
            "domain": "domain",
            "hash": "file_hash",
            "url": "url",
            "email": "email",
        }
        field = field_map.get(ioc_type, "indicator")
        spl = f'| inputlookup threat_intel.csv WHERE {field}="{ioc_value}" | head 20'
        try:
            raw = await self._run_search_job(spl, "-90d", "now", 20)
        except Exception:  # noqa: BLE001
            raw = await self._run_search_job(
                f'index=threat_intel earliest=-90d {field}="{ioc_value}" | head 20',
                "-90d",
                "now",
                20,
            )
        matches = list(raw.get("results") or [])
        return {
            "matches": matches,
            "risk_level": "high" if matches else "none",
            "sources": [m.get("source", "lookup") for m in matches],
            "first_seen": matches[0].get("first_seen") if matches else "",
            "last_seen": matches[0].get("last_seen") if matches else "",
        }

    # --- Mock data ---

    def _mock_search(self, params: dict[str, Any]) -> dict[str, Any]:
        query = str(params.get("query", "")).lower()
        if "failed" in query or "4625" in query:
            return {
                "results": [
                    {
                        "src_ip": "192.168.1.100",
                        "user": "admin",
                        "count": "45",
                        "_time": "2026-06-10T03:47:00Z",
                    },
                    {
                        "src_ip": "10.0.0.50",
                        "user": "guest",
                        "count": "12",
                        "_time": "2026-06-10T08:15:00Z",
                    },
                ],
                "result_count": 2,
                "fields": ["src_ip", "user", "count", "_time"],
                "search_time": 0.5,
            }
        if "network" in query or "firewall" in query:
            return {
                "results": [
                    {
                        "src_ip": "10.0.1.5",
                        "dest_ip": "185.220.101.7",
                        "dest_port": "443",
                        "count": "234",
                    },
                    {
                        "src_ip": "10.0.1.5",
                        "dest_ip": "8.8.8.8",
                        "dest_port": "53",
                        "count": "1200",
                    },
                ],
                "result_count": 2,
                "fields": ["src_ip", "dest_ip", "dest_port", "count"],
                "search_time": 0.3,
            }
        return {
            "results": [
                {
                    "_raw": "Mock log entry 1",
                    "host": "web-server-01",
                    "sourcetype": "access_combined",
                },
                {"_raw": "Mock log entry 2", "host": "db-server-01", "sourcetype": "mysql"},
            ],
            "result_count": 2,
            "fields": ["_raw", "host", "sourcetype"],
            "search_time": 0.2,
        }

    def _mock_anomalies(self, params: dict[str, Any]) -> dict[str, Any]:
        _ = params
        return {
            "anomalies": [
                {
                    "timestamp": "2026-06-10T03:47:00Z",
                    "value": 500,
                    "expected": 50,
                    "score": 0.95,
                    "type": "login_spike",
                },
            ],
            "baseline_stats": {"mean": 45, "stddev": 15, "min": 10, "max": 80},
            "model_info": {
                "model": "splunk_anomaly_detection",
                "version": "1.0",
                "training_samples": 10000,
            },
        }

    def _mock_alerts(self, params: dict[str, Any]) -> dict[str, Any]:
        _ = params
        return {
            "alerts": [
                {
                    "id": "notable-001",
                    "title": "Brute Force Attack Detected",
                    "severity": "high",
                    "status": "new",
                    "src_ip": "185.220.101.7",
                    "timestamp": "2026-06-10T03:47:00Z",
                },
                {
                    "id": "notable-002",
                    "title": "Data Exfiltration Suspected",
                    "severity": "critical",
                    "status": "new",
                    "src_ip": "10.0.1.5",
                    "timestamp": "2026-06-09T14:00:00Z",
                },
            ],
            "alert_count": 2,
            "by_severity": {"critical": 1, "high": 1, "medium": 0, "low": 0},
        }

    def _mock_uba(self, params: dict[str, Any]) -> dict[str, Any]:
        user = str(params.get("user", "unknown"))
        return {
            "risk_score": 75.0,
            "anomalies": [
                {
                    "type": "unusual_login_time",
                    "details": f"User {user}: login at 3:47 AM (normal: 8AM-6PM)",
                    "risk_contribution": 30,
                },
            ],
            "peer_comparison": {"peer_avg_risk": 15.0, "user_risk": 75.0, "percentile": 98.0},
            "timeline": [
                {
                    "time": "2026-06-10T03:47:00Z",
                    "activity": "login",
                    "user": user,
                    "location": "Moscow, Russia",
                    "risk": 30.0,
                },
            ],
        }

    def _mock_threat_intel(self, params: dict[str, Any]) -> dict[str, Any]:
        ioc_value = str(params.get("ioc_value", ""))
        return {
            "matches": [
                {
                    "intel_source": "AbuseIPDB",
                    "category": "Brute Force",
                    "confidence": 95,
                    "first_seen": "2026-01-15",
                    "last_seen": "2026-06-10",
                },
            ],
            "risk_level": "critical" if "185.220" in ioc_value else "medium",
            "sources": ["AbuseIPDB", "VirusTotal", "AlienVault OTX"],
            "first_seen": "2026-01-15",
            "last_seen": "2026-06-10",
        }
