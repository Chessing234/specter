"""Main LangGraph agent orchestration engine."""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any, cast

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph

from specter.core.bus import AgentCommunicationBus
from specter.core.state import Phase, SpecterState
from specter.core.validators import ReasoningValidator
from specter.models.agent import AgentMessage, AgentType
from specter.models.incident import Incident


def _coerce_state(state: SpecterState | dict[str, Any]) -> SpecterState:
    return state if isinstance(state, SpecterState) else SpecterState.model_validate(state)


class SpecterEngine:
    """
    Main orchestration engine for SPECTER.

    Uses LangGraph to coordinate agents:
    SENTRY → TRIAGE → (validate loop) → SHERLOCK → COMMANDER → PATCH? → AUDIT.
    """

    def __init__(self) -> None:
        self.bus = AgentCommunicationBus()
        self.validator = ReasoningValidator()
        self.graph = self._build_graph()
        self._agent_instances: dict[str, Any] = {}

    def register_agent(self, agent_type: AgentType, agent_instance: Any) -> None:
        """Register an agent implementation."""
        self._agent_instances[agent_type.value] = agent_instance

    def _build_graph(self) -> Any:
        workflow = StateGraph(SpecterState)

        workflow.add_node("sentry", self._run_sentry)
        workflow.add_node("triage", self._run_triage)
        workflow.add_node("sherlock", self._run_sherlock)
        workflow.add_node("commander", self._run_commander)
        workflow.add_node("patch", self._run_patch)
        workflow.add_node("audit", self._run_audit)
        workflow.add_node("validate", self._validate_phase)
        workflow.add_node("correct", self._self_correct)

        workflow.add_edge(START, "sentry")
        workflow.add_edge("sentry", "triage")
        workflow.add_edge("triage", "validate")

        workflow.add_conditional_edges(
            "validate",
            self._decide_after_validation,
            {
                "sherlock": "sherlock",
                "commander": "commander",
                "audit": "audit",
                "correct": "correct",
                "error": END,
            },
        )

        workflow.add_edge("sherlock", "validate")

        workflow.add_conditional_edges(
            "correct",
            self._decide_correction_target,
            {
                "sentry": "sentry",
                "triage": "triage",
                "sherlock": "sherlock",
                "commander": "commander",
                "audit": "audit",
                "complete": END,
            },
        )

        workflow.add_conditional_edges(
            "commander",
            self._decide_after_commander,
            {
                "patch": "patch",
                "audit": "audit",
                "validate": "validate",
            },
        )

        workflow.add_edge("patch", "audit")
        workflow.add_edge("audit", END)

        memory = MemorySaver()
        return workflow.compile(checkpointer=memory)

    async def _run_sentry(self, state: SpecterState | dict[str, Any]) -> dict[str, Any]:
        state = _coerce_state(state)
        agent = self._agent_instances.get("sentry")
        if not agent:
            raise RuntimeError("SENTRY agent not registered")

        result = await agent.process(state.incident, state.memory_context)

        validation = ReasoningValidator.validate_agent_output(
            "sentry", result, [a.model_dump(mode="python") for a in state.actions]
        )

        message = self.bus.create_message(
            from_agent=AgentType.SENTRY,
            to_agent=AgentType.TRIAGE,
            message_type="alert",
            content={"detection_result": result, "validation": validation},
            priority=1,
        )

        await self.bus.publish(message)
        await self.bus.broadcast_to_websocket(message)

        return {
            **state.set_phase("detection"),
            **state.increment_iteration(),
            **state.add_message(message),
        }

    async def _run_triage(self, state: SpecterState | dict[str, Any]) -> dict[str, Any]:
        state = _coerce_state(state)
        agent = self._agent_instances.get("triage")
        if not agent:
            raise RuntimeError("TRIAGE agent not registered")

        detection_msg = [m for m in state.messages if m.from_agent == AgentType.SENTRY]
        detection_result = detection_msg[-1].content if detection_msg else {}

        result = await agent.process(state.incident, detection_result, state.memory_context)

        validation = ReasoningValidator.validate_agent_output(
            "triage", result, [a.model_dump(mode="python") for a in state.actions]
        )

        priority_score = int(result.get("priority_score", 3))
        message = self.bus.create_message(
            from_agent=AgentType.TRIAGE,
            to_agent=AgentType.SHERLOCK,
            message_type="task",
            content={
                "triage_result": result,
                "validation": validation,
                "priority": result.get("priority", "medium"),
            },
            priority=priority_score,
        )

        await self.bus.publish(message)
        await self.bus.broadcast_to_websocket(message)

        return {
            **state.set_phase(cast(Phase, "triage")),
            **state.increment_iteration(),
            **state.add_message(message),
        }

    async def _run_sherlock(self, state: SpecterState | dict[str, Any]) -> dict[str, Any]:
        state = _coerce_state(state)
        agent = self._agent_instances.get("sherlock")
        if not agent:
            raise RuntimeError("SHERLOCK agent not registered")

        triage_msg = [m for m in state.messages if m.from_agent == AgentType.TRIAGE]
        triage_result = triage_msg[-1].content if triage_msg else {}

        result = await agent.process(
            state.incident,
            triage_result,
            state.evidence,
            state.memory_context,
        )

        existing_findings = [f.model_dump(mode="python") for f in state.findings]
        raw_new = result.get("new_findings") or []
        new_findings: list[dict[str, Any]] = []
        for item in raw_new:
            if hasattr(item, "model_dump"):
                new_findings.append(item.model_dump(mode="python"))
            else:
                new_findings.append(cast(dict[str, Any], item))

        contradictions = ReasoningValidator.detect_contradictions(existing_findings + new_findings)
        if contradictions:
            result = {**result, "contradictions": contradictions, "requires_correction": True}

        validation = ReasoningValidator.validate_agent_output(
            "sherlock", result, [a.model_dump(mode="python") for a in state.actions]
        )

        message = self.bus.create_message(
            from_agent=AgentType.SHERLOCK,
            to_agent=AgentType.COMMANDER,
            message_type="evidence",
            content={
                "investigation_result": result,
                "validation": validation,
                "contradictions": contradictions,
            },
            priority=1,
        )

        await self.bus.publish(message)
        await self.bus.broadcast_to_websocket(message)

        return {
            **state.set_phase(cast(Phase, "investigation")),
            **state.increment_iteration(),
            **state.add_message(message),
        }

    async def _run_commander(self, state: SpecterState | dict[str, Any]) -> dict[str, Any]:
        state = _coerce_state(state)
        agent = self._agent_instances.get("commander")
        if not agent:
            raise RuntimeError("COMMANDER agent not registered")

        result = await agent.process(
            state.incident,
            state.findings,
            state.evidence,
        )

        message = self.bus.create_message(
            from_agent=AgentType.COMMANDER,
            to_agent=None,
            message_type="status",
            content={"command_result": result},
            priority=2,
        )

        await self.bus.publish(message)
        await self.bus.broadcast_to_websocket(message)

        return {
            **state.set_phase(cast(Phase, "command")),
            **state.increment_iteration(),
            **state.add_message(message),
        }

    async def _run_patch(self, state: SpecterState | dict[str, Any]) -> dict[str, Any]:
        state = _coerce_state(state)
        agent = self._agent_instances.get("patch")
        if not agent:
            return {**state.set_phase(cast(Phase, "audit"))}

        result = await agent.process(state.incident, state.findings)

        message = self.bus.create_message(
            from_agent=AgentType.PATCH,
            to_agent=AgentType.AUDIT,
            message_type="status",
            content={"remediation_result": result},
            priority=3,
        )

        await self.bus.publish(message)
        await self.bus.broadcast_to_websocket(message)

        return {
            **state.set_phase(cast(Phase, "remediation")),
            **state.increment_iteration(),
            **state.add_message(message),
        }

    async def _run_audit(self, state: SpecterState | dict[str, Any]) -> dict[str, Any]:
        state = _coerce_state(state)
        agent = self._agent_instances.get("audit")
        if not agent:
            return {**state.mark_complete()}

        result = await agent.process(
            state.incident,
            state.findings,
            state.actions,
        )

        message = self.bus.create_message(
            from_agent=AgentType.AUDIT,
            to_agent=None,
            message_type="status",
            content={"audit_result": result},
            priority=5,
        )

        await self.bus.publish(message)
        await self.bus.broadcast_to_websocket(message)

        return {
            **state.set_phase(cast(Phase, "audit")),
            **state.increment_iteration(),
            **state.add_message(message),
            **state.mark_complete(),
        }

    async def _validate_phase(self, state: SpecterState | dict[str, Any]) -> dict[str, Any]:
        state = _coerce_state(state)

        if state.iteration_count >= state.max_iterations:
            return {
                "validation_errors": ["Max iterations reached"],
                "requires_human_review": True,
                "current_phase": cast(Phase, "error"),
            }

        errors: list[str] = []
        last_msg: AgentMessage | None = state.messages[-1] if state.messages else None
        if last_msg:
            validation = last_msg.content.get("validation")
            if isinstance(validation, dict) and validation.get("errors"):
                errors = list(map(str, validation["errors"]))

        return {"validation_errors": errors}

    async def _self_correct(self, state: SpecterState | dict[str, Any]) -> dict[str, Any]:
        state = _coerce_state(state)
        correction = {
            "timestamp": datetime.now(UTC).isoformat(),
            "original_phase": state.current_phase,
            "validation_errors": list(state.validation_errors),
            "iteration": state.iteration_count,
        }

        return {
            "corrections_made": [correction],
            "validation_errors": [],
        }

    def _decide_after_validation(self, state: SpecterState | dict[str, Any]) -> str:
        state = _coerce_state(state)

        if state.current_phase == "error" or state.requires_human_review:
            return "error"

        if state.validation_errors:
            return "correct" if state.iteration_count < state.max_iterations else "error"

        phase = state.current_phase
        if phase == "triage":
            return "sherlock"
        if phase == "investigation":
            return "commander"
        if phase == "command":
            return "audit"
        if phase == "audit":
            return "audit"

        return "sherlock"

    def _decide_correction_target(self, state: SpecterState | dict[str, Any]) -> str:
        state = _coerce_state(state)
        last_correction = state.corrections_made[-1] if state.corrections_made else {}
        original_phase = str(last_correction.get("original_phase", "detection"))

        if state.iteration_count >= state.max_iterations:
            return "complete"

        phase_map = {
            "detection": "sentry",
            "triage": "triage",
            "investigation": "sherlock",
            "command": "commander",
            "remediation": "commander",
            "audit": "audit",
        }
        return phase_map.get(original_phase, "sherlock")

    def _decide_after_commander(self, state: SpecterState | dict[str, Any]) -> str:
        state = _coerce_state(state)
        last_msgs = [m for m in state.messages if m.from_agent == AgentType.COMMANDER]
        if not last_msgs:
            return "audit"

        command_result = last_msgs[-1].content.get("command_result", {})
        if isinstance(command_result, dict) and command_result.get("requires_containment"):
            return "patch"
        if isinstance(command_result, dict) and command_result.get("needs_revalidation"):
            return "validate"
        return "audit"

    async def process_incident(self, incident: Incident) -> SpecterState:
        """Run the compiled LangGraph workflow for an incident."""
        initial_state = SpecterState(incident=incident, current_phase="detection")
        config = {"configurable": {"thread_id": incident.id}}
        result = await self.graph.ainvoke(initial_state, config)
        return _coerce_state(result)

    async def process_incident_stream(
        self, incident: Incident
    ) -> AsyncIterator[SpecterState | dict[str, Any]]:
        """Stream LangGraph state updates."""
        initial_state = SpecterState(incident=incident)
        config = {"configurable": {"thread_id": incident.id}}

        async for update in self.graph.astream(initial_state, config):
            yield update


class OrchestrationEngine(SpecterEngine):
    """Backwards-compatible alias."""
