"use client";

import { useCallback, useEffect, useRef, useState } from "react";

function defaultWsBase(): string {
  if (process.env.NEXT_PUBLIC_WS_URL) {
    return process.env.NEXT_PUBLIC_WS_URL.replace(/\/$/, "");
  }
  return "ws://localhost:8000";
}

export interface AgentEvent {
  type: string;
  from: string;
  to: string | null;
  message_type: string;
  content: Record<string, unknown>;
  timestamp: string;
  correlation_id: string | null;
}

const MAX_EVENTS = 100;

export function useWebSocket() {
  const [connected, setConnected] = useState(false);
  const [events, setEvents] = useState<AgentEvent[]>([]);
  const wsRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    const base = defaultWsBase();
    const ws = new WebSocket(`${base}/ws/events`);
    wsRef.current = ws;

    ws.onopen = () => {
      setConnected(true);
      ws.send(JSON.stringify({ type: "subscribe", channels: ["agent_events"] }));
    };

    ws.onclose = () => setConnected(false);
    ws.onerror = () => setConnected(false);

    ws.onmessage = (msg) => {
      try {
        const data = JSON.parse(msg.data as string) as Record<string, unknown>;
        if (data.type === "agent_message") {
          setEvents((prev) => {
            const next: AgentEvent = {
              type: String(data.type),
              from: String(data.from ?? ""),
              to: (data.to as string | null) ?? null,
              message_type: String(data.message_type ?? ""),
              content:
                typeof data.content === "object" && data.content !== null
                  ? (data.content as Record<string, unknown>)
                  : {},
              timestamp: String(data.timestamp ?? ""),
              correlation_id: (data.correlation_id as string | null) ?? null,
            };
            return [...prev.slice(-(MAX_EVENTS - 1)), next];
          });
        } else if (data.type === "incident_complete") {
          setEvents((prev) => {
            const next: AgentEvent = {
              type: "incident_complete",
              from: "specter",
              to: null,
              message_type: "status",
              content: data as Record<string, unknown>,
              timestamp: new Date().toISOString(),
              correlation_id: (data.incident_id as string | null) ?? null,
            };
            return [...prev.slice(-(MAX_EVENTS - 1)), next];
          });
        }
      } catch {
        /* ignore malformed */
      }
    };

    return () => {
      ws.close();
      wsRef.current = null;
    };
  }, []);

  const send = useCallback((data: unknown) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(data));
    }
  }, []);

  return { connected, events, send };
}
