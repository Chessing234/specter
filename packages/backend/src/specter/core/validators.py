"""Reasoning validation and self-correction logic."""

from __future__ import annotations

import re
from typing import Any

from specter.models.evidence import Evidence, EvidenceType


class ReasoningValidator:
    """
    Validates agent reasoning for logical consistency.

    This is the key to reducing hallucinations. Every agent output
    is validated before being accepted into the shared state.
    """

    HALLUCINATION_PATTERNS = [
        r"\b(maybe|possibly|perhaps|might|could be)\b.*\b(certain|definite|sure)\b",
        r"\bI (think|believe|assume)\b.*\b(is definitely|is certainly)\b",
        r"\b(probably|likely)\b.*\b(confirmed|verified|proven)\b",
        r"\bno evidence\b.*\b(however|but|nevertheless)\b.*\b(conclude|determine)\b",
    ]

    REQUIRED_EVIDENCE_FIELDS: dict[str, list[str]] = {
        EvidenceType.TOOL_OUTPUT.value: ["command", "raw_output"],
        EvidenceType.LOG_ENTRY.value: ["timestamp", "source", "message"],
        EvidenceType.FILE_HASH.value: ["hash_type", "hash_value", "file_path"],
        EvidenceType.NETWORK_CAPTURE.value: ["protocol", "src_ip", "dst_ip"],
        EvidenceType.AGENT_REASONING.value: ["reasoning_steps", "conclusion"],
        EvidenceType.CORRELATION.value: ["correlated_entities", "correlation_type", "confidence"],
    }

    @classmethod
    def validate_agent_output(
        cls,
        agent_name: str,
        output: dict[str, Any],
        previous_actions: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """
        Validate an agent's output for consistency and completeness.

        Returns: {"valid": bool, "errors": list[str], "warnings": list[str]}
        """
        _ = agent_name
        errors: list[str] = []
        warnings: list[str] = []

        reasoning_text = str(output.get("reasoning", ""))
        for pattern in cls.HALLUCINATION_PATTERNS:
            if re.search(pattern, reasoning_text, re.IGNORECASE):
                warnings.append(
                    "Potential hallucination detected: uncertain language combined "
                    "with definitive conclusions"
                )

        if "findings" in output:
            for i, finding in enumerate(output["findings"]):
                if not finding.get("evidence_refs"):
                    errors.append(
                        f"Finding {i} has no evidence references; "
                        "every finding must be backed by evidence"
                    )
                if float(finding.get("confidence", 0)) > 0.8 and not finding.get("verified"):
                    warnings.append(
                        f"Finding {i} has high confidence ({finding.get('confidence')}) "
                        "but is not verified"
                    )

        if "timeline" in output:
            timeline = output["timeline"]
            for i in range(1, len(timeline)):
                if timeline[i].get("timestamp") < timeline[i - 1].get("timestamp"):
                    warnings.append(
                        f"Timeline entry {i} timestamp is before the previous entry; "
                        "verify temporal ordering"
                    )

        if previous_actions and "references" in output:
            ref_ids = {ref.get("action_id") for ref in output["references"]}
            action_ids = {a.get("id") for a in previous_actions}
            missing_refs = ref_ids - action_ids
            if missing_refs:
                errors.append(f"References to non-existent actions: {missing_refs}")

        return {
            "valid": len(errors) == 0,
            "errors": errors,
            "warnings": warnings,
        }

    @classmethod
    def validate_evidence(cls, evidence: Evidence) -> dict[str, Any]:
        """Validate a piece of evidence for completeness."""
        errors: list[str] = []

        etype = (
            evidence.evidence_type.value
            if isinstance(evidence.evidence_type, EvidenceType)
            else str(evidence.evidence_type)
        )
        required = cls.REQUIRED_EVIDENCE_FIELDS.get(etype, [])
        for field in required:
            if field not in evidence.raw_data:
                errors.append(f"Missing required field '{field}' for {etype}")

        if not evidence.chain_of_custody:
            errors.append("Evidence has no chain of custody entries")

        return {
            "valid": len(errors) == 0,
            "errors": errors,
        }

    @classmethod
    def detect_contradictions(cls, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Detect contradictions between findings."""
        contradictions: list[dict[str, Any]] = []

        for i, finding_a in enumerate(findings):
            for finding_b in findings[i + 1 :]:
                conclusion_a = str(finding_a.get("conclusion", "")).lower()
                conclusion_b = str(finding_b.get("conclusion", "")).lower()

                if ("compromised" in conclusion_a and "not compromised" in conclusion_b) or (
                    "not compromised" in conclusion_a and "compromised" in conclusion_b
                ):
                    contradictions.append(
                        {
                            "finding_a": finding_a.get("id"),
                            "finding_b": finding_b.get("id"),
                            "type": "direct_contradiction",
                            "description": "Contradictory compromise assessments",
                            "suggested_action": "Re-run forensic analysis with cross-validation",
                        }
                    )

                timeline_a = finding_a.get("timeline", {})
                timeline_b = finding_b.get("timeline", {})
                if timeline_a and timeline_b:
                    start_a = timeline_a.get("start")
                    start_b = timeline_b.get("start")
                    if (
                        start_a is not None
                        and start_b is not None
                        and abs(float(start_a) - float(start_b)) > 3600
                    ):
                        contradictions.append(
                            {
                                "finding_a": finding_a.get("id"),
                                "finding_b": finding_b.get("id"),
                                "type": "timeline_mismatch",
                                "description": "Timeline start times differ by >1 hour",
                                "suggested_action": "Correlate with additional log sources",
                            }
                        )

        return contradictions
