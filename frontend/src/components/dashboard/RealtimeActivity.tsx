"use client";

import { Radio, Zap } from "lucide-react";

import { useWebSocket } from "@/lib/websocket";

export function RealtimeActivity() {
  const { connected, events } = useWebSocket();

  return (
    <div className="rounded-lg border border-border bg-card p-4 shadow-sm">
      <div className="mb-4 flex items-center justify-between gap-4">
        <h2 className="flex items-center gap-2 text-lg font-semibold">
          <Radio
            className={`h-5 w-5 ${connected ? "text-emerald-400" : "text-destructive"}`}
          />
          Live activity
        </h2>
        <span
          className={`rounded px-2 py-1 text-xs ${
            connected
              ? "bg-emerald-500/15 text-emerald-400"
              : "bg-destructive/15 text-destructive"
          }`}
        >
          {connected ? "Connected" : "Disconnected"}
        </span>
      </div>

      <div className="max-h-64 space-y-2 overflow-y-auto">
        {events.length === 0 ? (
          <p className="py-4 text-center text-sm text-muted-foreground">
            Waiting for agent activity… Run an incident through the engine to see
            bus messages here.
          </p>
        ) : (
          events
            .slice(-20)
            .reverse()
            .map((event, i) => (
              <div
                key={`${event.timestamp}-${event.correlation_id ?? i}`}
                className="flex items-start gap-3 rounded-md bg-muted/30 p-2 text-sm"
              >
                <Zap className="mt-0.5 h-4 w-4 shrink-0 text-sky-400" />
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-medium text-sky-300">{event.from}</span>
                    {event.to ? (
                      <>
                        <span className="text-muted-foreground">→</span>
                        <span className="font-medium">{event.to}</span>
                      </>
                    ) : null}
                    <span className="ml-auto text-xs text-muted-foreground">
                      {event.timestamp
                        ? new Date(event.timestamp).toLocaleTimeString()
                        : ""}
                    </span>
                  </div>
                  <p className="mt-0.5 truncate text-xs text-muted-foreground capitalize">
                    {event.message_type}:{" "}
                    {JSON.stringify(event.content).slice(0, 120)}
                  </p>
                </div>
              </div>
            ))
        )}
      </div>
    </div>
  );
}
