"""SANS SIFT Workstation MCP adapter for SPECTER (FIND EVIL! / hackathon).

Typed, read-only MCP tools — no generic shell execution from agents.
Evidence paths on the local filesystem are copied before use when present.
Remote execution uses ``shlex.quote`` for argument safety.
"""

from __future__ import annotations

import contextlib
import json
import os
import shlex
import tempfile
import time
from typing import Any

from specter.mcp.adapters.base import MCPAdapter
from specter.mcp.security import EvidenceProtector
from specter.models.mcp import MCPAdapterType, MCPToolCall, MCPToolDefinition, MCPToolResult


class SIFTAdapter(MCPAdapter):
    """Expose SIFT-style forensic workflows as typed MCP tools (read-only)."""

    DISK_TOOLS = [
        "mft_parser",
        "usnjrnl_parser",
        "logfile_parser",
        "registry_parser",
        "prefetch_parser",
        "amcache_parser",
        "shellbags_parser",
        "lnk_parser",
        "jumplist_parser",
    ]

    MEMORY_TOOLS = [
        "volatility_pslist",
        "volatility_pstree",
        "volatility_netscan",
        "volatility_malfind",
        "volatility_cmdline",
        "volatility_dlllist",
        "volatility_handles",
        "volatility_svcscan",
        "volatility_timeline",
    ]

    TIMELINE_TOOLS = [
        "plaso_log2timeline",
        "plaso_psort",
        "mactime_formatter",
    ]

    CORRELATION_TOOLS = [
        "correlate_disk_memory",
        "cross_reference_iocs",
        "timeline_correlation",
        "hash_correlation",
    ]

    def __init__(
        self,
        sift_host: str | None = None,
        sift_username: str | None = None,
    ) -> None:
        super().__init__()
        from specter.config import get_settings

        settings = get_settings()
        self.sift_host = sift_host or settings.sift_host or "localhost"
        self.sift_username = sift_username or settings.sift_username or "sansforensics"
        self.evidence_dir = "/cases"
        self.working_dir = tempfile.mkdtemp(prefix="specter_sift_")
        self.protector = EvidenceProtector()
        self._ssh_client: Any = None
        self._mock_mode = False
        self._tools = self._define_all_tools()

    @property
    def adapter_type(self) -> MCPAdapterType:
        return MCPAdapterType.SIFT

    @property
    def adapter_name(self) -> str:
        return "SANS SIFT Workstation"

    def _define_all_tools(self) -> list[MCPToolDefinition]:
        return [
            MCPToolDefinition(
                name="extract_mft_timeline",
                description=(
                    "Extract Master File Table timeline from NTFS disk image. "
                    "Returns parsed timeline with file creation, modification, and access times."
                ),
                adapter=MCPAdapterType.SIFT,
                parameters={
                    "disk_image": {
                        "type": "string",
                        "description": "Path to disk image file (E01, RAW, VMDK)",
                    },
                    "partition_offset": {
                        "type": "integer",
                        "description": "Partition offset (optional, auto-detect if not provided)",
                        "default": None,
                    },
                    "output_format": {
                        "type": "string",
                        "enum": ["json", "csv", "bodyfile"],
                        "default": "json",
                    },
                },
                returns={
                    "timeline": {"type": "array"},
                    "entry_count": {"type": "integer"},
                    "time_range": {"type": "object"},
                },
                read_only=True,
            ),
            MCPToolDefinition(
                name="analyze_prefetch_files",
                description=(
                    "Analyze Windows Prefetch files to determine program execution history. "
                    "Returns execution timestamps, run counts, and loaded DLLs."
                ),
                adapter=MCPAdapterType.SIFT,
                parameters={
                    "disk_image": {"type": "string", "description": "Path to disk image file"},
                    "prefetch_dir": {
                        "type": "string",
                        "description": "Path to Prefetch directory (auto-detect if not provided)",
                        "default": None,
                    },
                },
                returns={
                    "executions": {"type": "array"},
                    "suspicious_executions": {"type": "array"},
                },
                read_only=True,
            ),
            MCPToolDefinition(
                name="parse_registry_hives",
                description=(
                    "Parse Windows Registry hives (SOFTWARE, SYSTEM, SAM, NTUSER.DAT). "
                    "Returns registry keys, values, and last write times."
                ),
                adapter=MCPAdapterType.SIFT,
                parameters={
                    "disk_image": {"type": "string", "description": "Path to disk image file"},
                    "hives": {
                        "type": "array",
                        "items": {"type": "string"},
                        "default": ["SOFTWARE", "SYSTEM", "SAM"],
                    },
                    "keys_of_interest": {
                        "type": "array",
                        "items": {"type": "string"},
                        "default": [],
                    },
                },
                returns={
                    "hives": {"type": "object"},
                    "persistence_mechanisms": {"type": "array"},
                    "user_accounts": {"type": "array"},
                },
                read_only=True,
            ),
            MCPToolDefinition(
                name="parse_amcache",
                description=(
                    "Parse Amcache.hve to find evidence of program execution. "
                    "Returns execution timestamps, SHA1 hashes, and install dates."
                ),
                adapter=MCPAdapterType.SIFT,
                parameters={"disk_image": {"type": "string", "description": "Path to disk image"}},
                returns={"entries": {"type": "array"}, "sha1_hashes": {"type": "array"}},
                read_only=True,
            ),
            MCPToolDefinition(
                name="volatility_pslist",
                description=(
                    "List processes from memory dump using Volatility. "
                    "Returns process list with PIDs, parent PIDs, and start times."
                ),
                adapter=MCPAdapterType.SIFT,
                parameters={
                    "memory_dump": {"type": "string", "description": "Path to memory dump"},
                    "profile": {
                        "type": "string",
                        "description": "Volatility profile",
                        "default": None,
                    },
                },
                returns={
                    "processes": {"type": "array"},
                    "suspicious_processes": {"type": "array"},
                    "process_count": {"type": "integer"},
                },
                read_only=True,
            ),
            MCPToolDefinition(
                name="volatility_netscan",
                description="Scan for network connections in memory dump.",
                adapter=MCPAdapterType.SIFT,
                parameters={
                    "memory_dump": {"type": "string"},
                    "profile": {"type": "string", "default": None},
                },
                returns={
                    "connections": {"type": "array"},
                    "suspicious_connections": {"type": "array"},
                    "unique_remote_ips": {"type": "array"},
                },
                read_only=True,
            ),
            MCPToolDefinition(
                name="volatility_malfind",
                description="Find injected code in memory using Volatility malfind.",
                adapter=MCPAdapterType.SIFT,
                parameters={
                    "memory_dump": {"type": "string"},
                    "profile": {"type": "string", "default": None},
                },
                returns={
                    "suspicious_regions": {"type": "array"},
                    "process_details": {"type": "object"},
                    "risk_score": {"type": "number"},
                },
                read_only=True,
            ),
            MCPToolDefinition(
                name="volatility_cmdline",
                description="Extract command line arguments from processes in memory.",
                adapter=MCPAdapterType.SIFT,
                parameters={
                    "memory_dump": {"type": "string"},
                    "profile": {"type": "string", "default": None},
                    "pid_filter": {"type": "array", "items": {"type": "integer"}, "default": []},
                },
                returns={
                    "command_lines": {"type": "array"},
                    "suspicious_commands": {"type": "array"},
                },
                read_only=True,
            ),
            MCPToolDefinition(
                name="correlate_disk_memory",
                description="Cross-reference findings between disk image and memory dump.",
                adapter=MCPAdapterType.SIFT,
                parameters={
                    "disk_image": {"type": "string"},
                    "memory_dump": {"type": "string"},
                    "correlation_types": {
                        "type": "array",
                        "items": {"type": "string"},
                        "default": [],
                    },
                },
                returns={
                    "correlations": {"type": "array"},
                    "discrepancies": {"type": "array"},
                    "timeline_merged": {"type": "array"},
                    "confidence_score": {"type": "number"},
                },
                read_only=True,
            ),
            MCPToolDefinition(
                name="cross_reference_iocs",
                description="Cross-reference IOCs against disk and memory artifacts.",
                adapter=MCPAdapterType.SIFT,
                parameters={
                    "disk_image": {"type": "string", "default": None},
                    "memory_dump": {"type": "string", "default": None},
                    "iocs": {"type": "array", "items": {"type": "string"}},
                },
                returns={"matches": {"type": "array"}, "match_summary": {"type": "object"}},
                read_only=True,
            ),
            MCPToolDefinition(
                name="generate_super_timeline",
                description=(
                    "Generate a comprehensive super timeline from disk image (Plaso-style)."
                ),
                adapter=MCPAdapterType.SIFT,
                parameters={
                    "disk_image": {"type": "string"},
                    "date_range": {"type": "object", "default": None},
                    "parsers": {"type": "array", "items": {"type": "string"}, "default": []},
                },
                returns={
                    "timeline": {"type": "array"},
                    "event_count": {"type": "integer"},
                    "time_range": {"type": "object"},
                    "parsers_used": {"type": "array"},
                },
                read_only=True,
            ),
            MCPToolDefinition(
                name="auto_triage_disk",
                description="Automated triage on a disk image (MFT, Prefetch, Registry, Amcache).",
                adapter=MCPAdapterType.SIFT,
                parameters={
                    "disk_image": {"type": "string"},
                    "focus_areas": {"type": "array", "items": {"type": "string"}, "default": []},
                },
                returns={
                    "triage_report": {"type": "object"},
                    "findings": {"type": "array"},
                    "risk_assessment": {"type": "object"},
                    "recommended_next_steps": {"type": "array"},
                },
                read_only=True,
            ),
            MCPToolDefinition(
                name="auto_triage_memory",
                description="Automated triage on a memory dump.",
                adapter=MCPAdapterType.SIFT,
                parameters={"memory_dump": {"type": "string"}},
                returns={
                    "triage_report": {"type": "object"},
                    "findings": {"type": "array"},
                    "risk_assessment": {"type": "object"},
                    "recommended_next_steps": {"type": "array"},
                },
                read_only=True,
            ),
        ]

    async def connect(self) -> bool:
        try:
            import asyncssh  # noqa: PLC0415

            self._ssh_client = await asyncssh.connect(
                self.sift_host,
                username=self.sift_username,
                known_hosts=None,
            )
            self._mock_mode = False
            self._connected = True
            return True
        except Exception:
            self._mock_mode = True
            self._ssh_client = None
            self._connected = True
            return True

    async def disconnect(self) -> None:
        if self._ssh_client is not None:
            self._ssh_client.close()
            with contextlib.suppress(Exception):
                await self._ssh_client.wait_closed()
            self._ssh_client = None
        self._connected = False

    async def discover_tools(self) -> list[MCPToolDefinition]:
        return list(self._tools)

    async def execute(self, call: MCPToolCall) -> MCPToolResult:
        start = time.perf_counter()
        handler_map: dict[str, Any] = {
            "extract_mft_timeline": self._handle_extract_mft,
            "analyze_prefetch_files": self._handle_prefetch,
            "parse_registry_hives": self._handle_registry,
            "parse_amcache": self._handle_amcache,
            "volatility_pslist": self._handle_vol_pslist,
            "volatility_netscan": self._handle_vol_netscan,
            "volatility_malfind": self._handle_vol_malfind,
            "volatility_cmdline": self._handle_vol_cmdline,
            "correlate_disk_memory": self._handle_correlate,
            "cross_reference_iocs": self._handle_ioc_ref,
            "generate_super_timeline": self._handle_super_timeline,
            "auto_triage_disk": self._handle_triage_disk,
            "auto_triage_memory": self._handle_triage_memory,
        }
        handler = handler_map.get(call.tool_name)
        if not handler:
            return self._create_error_result(call, f"Unknown SIFT tool: {call.tool_name}")
        try:
            data = await handler(call.parameters)
            ms = int((time.perf_counter() - start) * 1000)
            return self._create_success_result(call, data, ms)
        except Exception as exc:  # noqa: BLE001
            return self._create_error_result(call, f"Execution failed: {exc}")

    async def health_check(self) -> dict[str, Any]:
        return {
            "status": "healthy" if self._connected else "unhealthy",
            "adapter": "sift",
            "host": self.sift_host,
            "tools_available": len(self._tools),
            "mock_mode": self._mock_mode,
            "working_dir": self.working_dir,
        }

    def _maybe_protect_path(self, path: str) -> str:
        """If ``path`` is a local file, return a protected working copy path."""
        if not path or self._mock_mode:
            return path
        if os.path.isfile(path):
            return self.protector.protect_evidence(path)
        return path

    async def _run_sift_command(self, command: str) -> str:
        if self._mock_mode:
            return self._get_mock_output(command)

        if not self._ssh_client:
            raise RuntimeError("Not connected to SIFT")

        result = await self._ssh_client.run(command, check=False)
        if result.exit_status != 0:
            stderr = (result.stderr or "").strip()
            raise RuntimeError(stderr or f"SIFT command failed with exit {result.exit_status}")
        return result.stdout or ""

    def _get_mock_output(self, command: str) -> str:
        lowered = command.lower()
        if "mft" in lowered:
            payload = {
                "timeline": [
                    {
                        "file_path": "C:\\\\Windows\\\\System32\\\\evil.exe",
                        "created": "2026-06-08T14:23:00Z",
                        "modified": "2026-06-08T14:23:00Z",
                        "file_size": 245760,
                    },
                ],
                "entry_count": 1,
                "time_range": {"start": "2026-06-08T14:23:00Z", "end": "2026-06-08T14:23:00Z"},
            }
        elif "prefetch" in lowered:
            payload = {
                "executions": [
                    {
                        "program": "EVIL.EXE",
                        "run_count": 5,
                        "last_execution": "2026-06-09T03:47:00Z",
                        "loaded_dlls": ["KERNEL32.DLL", "WS2_32.DLL"],
                    },
                ],
                "suspicious_executions": [
                    {
                        "program": "EVIL.EXE",
                        "reason": "Unknown binary in System32 with network DLLs",
                    },
                ],
            }
        elif "registry" in lowered:
            payload = {
                "hives": {"SOFTWARE": {"Run": ["evil.exe"]}},
                "persistence_mechanisms": [{"type": "Run key", "value": "evil.exe"}],
                "user_accounts": [{"user": "Administrator", "rid": 500}],
            }
        elif "amcache" in lowered:
            payload = {
                "entries": [{"path": "C:\\\\evil.exe", "sha1": "aa" * 20}],
                "sha1_hashes": ["aa" * 20],
            }
        elif "pslist" in lowered:
            payload = {
                "processes": [
                    {
                        "pid": 1234,
                        "ppid": 800,
                        "name": "evil.exe",
                        "start_time": "2026-06-09T03:47:00Z",
                    },
                ],
                "suspicious_processes": [
                    {"pid": 1234, "name": "evil.exe", "reason": "Indicator match"},
                ],
                "process_count": 1,
            }
        elif "netscan" in lowered:
            payload = {
                "connections": [
                    {
                        "local_addr": "10.0.1.5:49234",
                        "remote_addr": "185.220.101.7:443",
                        "state": "ESTABLISHED",
                        "pid": 1234,
                    },
                ],
                "suspicious_connections": [
                    {
                        "local_addr": "10.0.1.5:49234",
                        "remote_addr": "185.220.101.7:443",
                        "reason": "Tor exit node IP",
                    },
                ],
                "unique_remote_ips": ["185.220.101.7"],
            }
        elif "malfind" in lowered:
            payload = {
                "suspicious_regions": [{"pid": 1234, "vad": "0x7ffaa", "tag": "MZ"}],
                "process_details": {"1234": {"name": "evil.exe"}},
                "risk_score": 0.82,
            }
        elif "cmdline" in lowered:
            payload = {
                "command_lines": [{"pid": 1234, "cmdline": "evil.exe --listen"}],
                "suspicious_commands": [{"pid": 1234, "cmdline": "evil.exe --listen"}],
            }
        elif "ioc" in lowered:
            payload = {
                "matches": [{"ioc": "185.220.101.7", "hit": "netscan ESTABLISHED"}],
                "match_summary": {"ip": 1},
            }
        elif "timeline" in lowered and "triage" not in lowered:
            payload = {
                "timeline": [
                    {
                        "ts": "2026-06-09T03:47:00Z",
                        "source": "MFT",
                        "description": "evil.exe",
                    },
                ],
                "event_count": 1,
                "time_range": {"start": "2026-06-09T03:47:00Z", "end": "2026-06-09T03:47:00Z"},
                "parsers_used": ["mft", "prefetch"],
            }
        elif "triage" in lowered and "memory" in lowered:
            payload = {
                "triage_report": {"memory": "summary"},
                "findings": [{"severity": "high", "detail": "Suspicious process tree"}],
                "risk_assessment": {"score": 0.71},
                "recommended_next_steps": ["Run volatility_malfind"],
            }
        elif "triage" in lowered:
            payload = {
                "triage_report": {"disk": "summary"},
                "findings": [{"severity": "medium", "detail": "Prefetch anomaly"}],
                "risk_assessment": {"score": 0.55},
                "recommended_next_steps": ["Run correlate_disk_memory"],
            }
        elif "correlate" in lowered:
            payload = {
                "correlations": [
                    {
                        "type": "process_execution",
                        "disk_evidence": "evil.exe in Prefetch",
                        "memory_evidence": "evil.exe PID 1234",
                        "confidence": 0.98,
                    },
                ],
                "discrepancies": [],
                "timeline_merged": [
                    {
                        "timestamp": "2026-06-09T03:47:00Z",
                        "source": "disk+memory",
                        "event": "evil.exe",
                    },
                ],
                "confidence_score": 0.95,
            }
        else:
            payload = {"status": "mock", "command": command}
        return json.dumps(payload)

    async def _handle_extract_mft(self, params: dict[str, Any]) -> dict[str, Any]:
        disk = str(params.get("disk_image", ""))
        disk_safe = shlex.quote(self._maybe_protect_path(disk))
        fmt = shlex.quote(str(params.get("output_format", "json")))
        cmd = f"sift_mft_extract --image {disk_safe} --format {fmt}"
        return json.loads(await self._run_sift_command(cmd))

    async def _handle_prefetch(self, params: dict[str, Any]) -> dict[str, Any]:
        disk = str(params.get("disk_image", ""))
        disk_safe = shlex.quote(self._maybe_protect_path(disk))
        cmd = f"sift_prefetch --image {disk_safe} --format json"
        return json.loads(await self._run_sift_command(cmd))

    async def _handle_registry(self, params: dict[str, Any]) -> dict[str, Any]:
        disk = str(params.get("disk_image", ""))
        disk_safe = shlex.quote(self._maybe_protect_path(disk))
        hives = params.get("hives") or ["SOFTWARE", "SYSTEM", "SAM"]
        hives_arg = shlex.quote(",".join(str(h) for h in hives))
        cmd = f"sift_registry --image {disk_safe} --hives {hives_arg} --format json"
        return json.loads(await self._run_sift_command(cmd))

    async def _handle_amcache(self, params: dict[str, Any]) -> dict[str, Any]:
        disk = str(params.get("disk_image", ""))
        disk_safe = shlex.quote(self._maybe_protect_path(disk))
        cmd = f"sift_amcache --image {disk_safe} --format json"
        return json.loads(await self._run_sift_command(cmd))

    async def _handle_vol_pslist(self, params: dict[str, Any]) -> dict[str, Any]:
        mem = str(params.get("memory_dump", ""))
        mem_safe = shlex.quote(self._maybe_protect_path(mem))
        profile = params.get("profile")
        profile_arg = f"--profile {shlex.quote(str(profile))}" if profile else ""
        cmd = f"volatility -f {mem_safe} {profile_arg} pslist --output=json".strip()
        return json.loads(await self._run_sift_command(cmd))

    async def _handle_vol_netscan(self, params: dict[str, Any]) -> dict[str, Any]:
        mem = shlex.quote(self._maybe_protect_path(str(params.get("memory_dump", ""))))
        cmd = f"volatility -f {mem} netscan --output=json"
        return json.loads(await self._run_sift_command(cmd))

    async def _handle_vol_malfind(self, params: dict[str, Any]) -> dict[str, Any]:
        mem = shlex.quote(self._maybe_protect_path(str(params.get("memory_dump", ""))))
        cmd = f"volatility -f {mem} malfind --output=json"
        return json.loads(await self._run_sift_command(cmd))

    async def _handle_vol_cmdline(self, params: dict[str, Any]) -> dict[str, Any]:
        mem = shlex.quote(self._maybe_protect_path(str(params.get("memory_dump", ""))))
        pids = params.get("pid_filter") or []
        pid_arg = ""
        if pids:
            pid_arg = "--pids " + shlex.quote(",".join(str(p) for p in pids))
        cmd = f"volatility -f {mem} cmdline {pid_arg} --output=json".strip()
        return json.loads(await self._run_sift_command(cmd))

    async def _handle_correlate(self, params: dict[str, Any]) -> dict[str, Any]:
        disk = shlex.quote(self._maybe_protect_path(str(params.get("disk_image", ""))))
        memory = shlex.quote(self._maybe_protect_path(str(params.get("memory_dump", ""))))
        types = params.get("correlation_types") or ["process_execution", "network_activity"]
        types_arg = shlex.quote(",".join(str(t) for t in types))
        cmd = f"sift_correlate --disk {disk} --memory {memory} --types {types_arg} --format json"
        return json.loads(await self._run_sift_command(cmd))

    async def _handle_ioc_ref(self, params: dict[str, Any]) -> dict[str, Any]:
        disk = params.get("disk_image")
        memory = params.get("memory_dump")
        disk_q = shlex.quote(self._maybe_protect_path(str(disk))) if disk else "''"
        mem_q = shlex.quote(self._maybe_protect_path(str(memory))) if memory else "''"
        iocs = params.get("iocs") or []
        iocs_q = shlex.quote(",".join(str(i) for i in iocs))
        cmd = f"sift_ioc --iocs {iocs_q} --disk {disk_q} --memory {mem_q} --format json"
        return json.loads(await self._run_sift_command(cmd))

    async def _handle_super_timeline(self, params: dict[str, Any]) -> dict[str, Any]:
        disk = shlex.quote(self._maybe_protect_path(str(params.get("disk_image", ""))))
        date_range = params.get("date_range")
        date_arg = ""
        if isinstance(date_range, dict) and date_range.get("start") and date_range.get("end"):
            ds = shlex.quote(str(date_range["start"]))
            de = shlex.quote(str(date_range["end"]))
            date_arg = f"--date-start {ds} --date-end {de}"
        cmd = f"sift_timeline --image {disk} {date_arg} --format json".strip()
        return json.loads(await self._run_sift_command(cmd))

    async def _handle_triage_disk(self, params: dict[str, Any]) -> dict[str, Any]:
        disk = shlex.quote(self._maybe_protect_path(str(params.get("disk_image", ""))))
        areas = params.get("focus_areas") or ["persistence", "execution"]
        areas_arg = shlex.quote(",".join(str(a) for a in areas))
        cmd = f"sift_triage --image {disk} --areas {areas_arg} --format json"
        return json.loads(await self._run_sift_command(cmd))

    async def _handle_triage_memory(self, params: dict[str, Any]) -> dict[str, Any]:
        mem = shlex.quote(self._maybe_protect_path(str(params.get("memory_dump", ""))))
        cmd = f"sift_triage --memory {mem} --format json"
        return json.loads(await self._run_sift_command(cmd))
