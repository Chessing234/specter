"""MCP Security Guardrails — architectural enforcement (not prompt-based)."""

from __future__ import annotations

import hashlib
import os
import shutil
import stat
import tempfile
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from specter.models.mcp import MCPToolDefinition


class ToolPermission(StrEnum):
    """Permission levels for MCP tools."""

    READ_ONLY = "read_only"
    WRITABLE = "writable"
    DESTRUCTIVE = "destructive"
    BLOCKED = "blocked"


class SecurityPolicy:
    """
    Security policy for MCP tool execution.

    Policies are evaluated by the MCP router before any adapter runs.
    Destructive tools are denied unless explicitly allowlisted.
    """

    DEFAULT_POLICY: dict[str, Any] = {
        "mode": "denylist",
        "allowed_destructive": [],
        "blocked_tools": [
            "rm",
            "del",
            "delete",
            "format",
            "mkfs",
            "drop",
            "truncate",
            "shred",
            "dd",
        ],
        "require_approval_for": [
            "quarantine",
            "isolate",
            "block_ip",
            "disable_account",
        ],
        "max_execution_time": 300,
        "max_concurrent_executions": 10,
    }

    def __init__(self, policy_config: dict[str, Any] | None = None) -> None:
        self.config = dict(policy_config or self.DEFAULT_POLICY)

    def can_execute(self, tool: MCPToolDefinition) -> tuple[bool, str]:
        """Return whether the tool may run under this policy."""
        tool_name_lower = tool.name.lower()
        for blocked in self.config.get("blocked_tools", []):
            if blocked in tool_name_lower:
                return False, f"Tool '{tool.name}' matches blocked pattern '{blocked}'"

        if tool.destructive:
            allowed_destructive = self.config.get("allowed_destructive", [])
            if tool.name not in allowed_destructive:
                return (
                    False,
                    f"Destructive tool '{tool.name}' not in allowed_destructive list. "
                    f"Allowed: {allowed_destructive}",
                )

        return True, "OK"

    def requires_approval(self, tool: MCPToolDefinition) -> bool:
        """Whether execution should be blocked until human approval exists."""
        tool_name_lower = tool.name.lower()
        requires_approval = self.config.get("require_approval_for", [])
        return any(req in tool_name_lower for req in requires_approval)

    def get_permission_level(self, tool: MCPToolDefinition) -> ToolPermission:
        """Derive coarse permission level for auditing / UI."""
        if not self.can_execute(tool)[0]:
            return ToolPermission.BLOCKED
        if tool.destructive:
            return ToolPermission.DESTRUCTIVE
        if not tool.read_only:
            return ToolPermission.WRITABLE
        return ToolPermission.READ_ONLY


class EvidenceProtector:
    """Evidence handling helpers — work on copies, preserve manifests."""

    @staticmethod
    def protect_evidence(evidence_path: str) -> str:
        """Copy evidence to a read-only working file and write a hash manifest."""
        path = Path(evidence_path)
        with path.open("rb") as handle:
            original_hash = hashlib.sha256(handle.read()).hexdigest()

        temp_dir = tempfile.mkdtemp(prefix="specter_evidence_")
        suffix = hashlib.md5(str(path).encode(), usedforsecurity=False).hexdigest()[:8]
        copy_path = os.path.join(temp_dir, f"{suffix}_copy")
        shutil.copy2(path, copy_path)
        os.chmod(copy_path, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)

        manifest_path = f"{copy_path}.manifest"
        with open(manifest_path, "w", encoding="utf-8") as manifest:
            manifest.write(f"original_path: {evidence_path}\n")
            manifest.write(f"original_hash: {original_hash}\n")
            manifest.write(f"copy_path: {copy_path}\n")
            manifest.write(f"protection_time: {datetime.now(UTC).isoformat()}\n")

        return copy_path

    @staticmethod
    def verify_integrity(evidence_path: str, expected_hash: str | None = None) -> bool:
        """Verify SHA-256 of a file against an expected hash or sidecar manifest."""
        try:
            path = Path(evidence_path)
            with path.open("rb") as handle:
                current_hash = hashlib.sha256(handle.read()).hexdigest()

            if expected_hash:
                return current_hash == expected_hash

            manifest_path = Path(f"{evidence_path}.manifest")
            if manifest_path.exists():
                for line in manifest_path.read_text(encoding="utf-8").splitlines():
                    if line.startswith("original_hash:"):
                        stored = line.split(":", 1)[1].strip()
                        return current_hash == stored

            return True
        except OSError:
            return False
