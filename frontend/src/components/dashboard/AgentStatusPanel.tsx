import { Bot, Circle } from "lucide-react";

import type { AgentStatus } from "@/lib/api";

interface Props {
  agents: AgentStatus[];
}

const statusColors: Record<string, string> = {
  idle: "text-emerald-400",
  running: "text-sky-400",
  error: "text-destructive",
  disabled: "text-muted-foreground",
};

const statusBg: Record<string, string> = {
  idle: "bg-emerald-500/10",
  running: "bg-sky-500/10",
  error: "bg-destructive/10",
  disabled: "bg-muted/50",
};

const defaultAgents: AgentStatus[] = [
  {
    name: "sentry",
    status: "idle",
    last_action: null,
    capabilities: ["detection", "monitoring"],
  },
  {
    name: "triage",
    status: "idle",
    last_action: null,
    capabilities: ["prioritization"],
  },
  {
    name: "sherlock",
    status: "idle",
    last_action: null,
    capabilities: ["forensics", "SIFT", "Splunk"],
  },
  {
    name: "commander",
    status: "idle",
    last_action: null,
    capabilities: ["orchestration", "SLA"],
  },
  {
    name: "patch",
    status: "disabled",
    last_action: null,
    capabilities: ["remediation"],
  },
  {
    name: "audit",
    status: "idle",
    last_action: null,
    capabilities: ["compliance", "Sola"],
  },
];

export function AgentStatusPanel({ agents }: Props) {
  const displayAgents = agents.length > 0 ? agents : defaultAgents;

  return (
    <div className="rounded-lg border border-border bg-card p-4 shadow-sm">
      <h2 className="mb-4 text-lg font-semibold">Agent team</h2>

      <div className="space-y-2">
        {displayAgents.map((agent) => (
          <div
            key={agent.name}
            className={`flex items-center gap-3 rounded-lg p-3 ${
              statusBg[agent.status] ?? statusBg.idle
            }`}
          >
            <Bot
              className={`h-5 w-5 shrink-0 ${
                statusColors[agent.status] ?? statusColors.idle
              }`}
            />
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2">
                <span className="text-sm font-medium uppercase">
                  {agent.name}
                </span>
                <Circle
                  className={`h-2 w-2 fill-current ${
                    statusColors[agent.status] ?? statusColors.idle
                  }`}
                />
              </div>
              <p className="text-xs capitalize text-muted-foreground">
                {agent.status}
                {agent.last_action ? ` · ${agent.last_action}` : ""}
              </p>
            </div>
            <div className="hidden flex-wrap justify-end gap-1 sm:flex">
              {(agent.capabilities ?? []).slice(0, 3).map((cap) => (
                <span
                  key={cap}
                  className="rounded bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground"
                >
                  {cap}
                </span>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
