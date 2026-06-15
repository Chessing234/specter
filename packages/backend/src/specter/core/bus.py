"""Agent Communication Bus - async message passing between agents."""

from __future__ import annotations

import asyncio
import uuid
from collections import deque
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Literal

from specter.models.agent import AgentMessage, AgentType

MessageType = Literal["task", "response", "alert", "status", "evidence"]


class AgentCommunicationBus:
    """
    Async message bus for inter-agent communication.

    Features:
    - Priority-ordered message queue
    - Subscribe/unsubscribe pattern
    - Message persistence for audit trails
    - Correlation ID tracking for request-response patterns
    """

    def __init__(self, max_queue_size: int = 10000) -> None:
        self._queue: asyncio.PriorityQueue[tuple[int, datetime, AgentMessage]] = (
            asyncio.PriorityQueue(maxsize=max_queue_size)
        )
        self._subscribers: dict[AgentType, list[Callable[[AgentMessage], Awaitable[None]]]] = {}
        self._history: deque[AgentMessage] = deque(maxlen=10000)

    async def publish(self, message: AgentMessage) -> None:
        """
        Publish a message to the bus.

        Priority: lower number = higher priority (1 = urgent, 10 = background)
        """
        await self._queue.put((message.priority, datetime.now(UTC), message))
        self._history.append(message)

    async def subscribe(
        self,
        agent: AgentType,
        handler: Callable[[AgentMessage], Awaitable[None]],
    ) -> None:
        """Subscribe an agent to receive messages."""
        self._subscribers.setdefault(agent, []).append(handler)

    async def unsubscribe(
        self,
        agent: AgentType,
        handler: Callable[[AgentMessage], Awaitable[None]],
    ) -> None:
        """Unsubscribe an agent."""
        if agent in self._subscribers:
            self._subscribers[agent] = [h for h in self._subscribers[agent] if h != handler]

    async def get_message(self, timeout: float | None = None) -> AgentMessage | None:
        """Get the next message from the queue."""
        try:
            _, _, message = await asyncio.wait_for(self._queue.get(), timeout=timeout)
            return message
        except TimeoutError:
            return None

    async def dispatch(self, message: AgentMessage) -> None:
        """Dispatch a message to all subscribed handlers for the target agent."""
        target = message.to_agent

        if target and target in self._subscribers:
            handlers = list(self._subscribers[target])
        else:
            handlers = []
            for agent_handlers in self._subscribers.values():
                handlers.extend(agent_handlers)

        if handlers:
            await asyncio.gather(
                *[handler(message) for handler in handlers],
                return_exceptions=True,
            )

    async def broadcast_to_websocket(self, message: AgentMessage) -> None:
        """Broadcast message to WebSocket connections for UI updates."""
        from specter.api.websocket import broadcast_event

        await broadcast_event(
            {
                "type": "agent_message",
                "from": message.from_agent.value,
                "to": message.to_agent.value if message.to_agent else None,
                "message_type": message.message_type,
                "content": message.content,
                "timestamp": message.timestamp.isoformat(),
                "correlation_id": message.correlation_id,
            }
        )

    def get_history(
        self,
        agent: AgentType | None = None,
        correlation_id: str | None = None,
        limit: int = 100,
    ) -> list[AgentMessage]:
        """Get message history with optional filters."""
        messages = list(self._history)

        if agent:
            messages = [m for m in messages if m.from_agent == agent or m.to_agent == agent]

        if correlation_id:
            messages = [m for m in messages if m.correlation_id == correlation_id]

        return messages[-limit:]

    def create_message(
        self,
        from_agent: AgentType,
        to_agent: AgentType | None,
        message_type: MessageType,
        content: dict,
        priority: int = 5,
        correlation_id: str | None = None,
    ) -> AgentMessage:
        """Helper to create a properly formatted message."""
        safe_priority = max(1, min(10, int(priority)))
        return AgentMessage(
            id=str(uuid.uuid4()),
            from_agent=from_agent,
            to_agent=to_agent,
            message_type=message_type,
            content=content,
            priority=safe_priority,
            correlation_id=correlation_id or str(uuid.uuid4()),
        )
