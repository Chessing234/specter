import { Activity, AlertTriangle, Bot, Shield } from "lucide-react";

import type { AgentStatus, Incident } from "@/lib/api";

interface Props {
  incidents: Incident[];
  agents: AgentStatus[];
}

export function DashboardStats({ incidents, agents }: Props) {
  const critical = incidents.filter((i) => i.severity === "critical").length;
  const high = incidents.filter((i) => i.severity === "high").length;
  const active = agents.filter((a) => a.status === "running").length;
  const total = incidents.length;

  const stats = [
    { label: "Total incidents", value: total, icon: Shield, color: "text-primary" },
    { label: "Critical", value: critical, icon: AlertTriangle, color: "text-destructive" },
    { label: "High priority", value: high, icon: Activity, color: "text-orange-400" },
    { label: "Active agents", value: active, icon: Bot, color: "text-emerald-400" },
  ];

  return (
    <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
      {stats.map((stat) => (
        <div
          key={stat.label}
          className="rounded-lg border border-border bg-card p-4 shadow-sm"
        >
          <div className="flex items-center justify-between">
            <stat.icon className={`h-6 w-6 ${stat.color}`} />
            <span className="text-2xl font-bold tabular-nums">{stat.value}</span>
          </div>
          <p className="mt-2 text-sm text-muted-foreground">{stat.label}</p>
        </div>
      ))}
    </div>
  );
}
