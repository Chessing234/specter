import { AgentStatusPanel } from "@/components/dashboard/AgentStatusPanel";
import { DashboardStats } from "@/components/dashboard/DashboardStats";
import { RealtimeActivity } from "@/components/dashboard/RealtimeActivity";
import { RecentIncidents } from "@/components/dashboard/RecentIncidents";
import { api } from "@/lib/api";

export default async function DashboardPage() {
  const [incidents, agents] = await Promise.all([
    api.listIncidents().catch(() => []),
    api.listAgents().catch(() => []),
  ]);

  return (
    <div className="space-y-8">
      <header>
        <h1 className="text-3xl font-bold tracking-tight">SPECTER</h1>
        <p className="mt-2 max-w-3xl text-muted-foreground">
          Security Protocol for Executable Contextual Threat Evaluation &amp; Response —
          operations overview with incidents, agent fleet, and live bus activity.
        </p>
      </header>

      <DashboardStats incidents={incidents} agents={agents} />

      <div className="grid gap-6 lg:grid-cols-2">
        <RecentIncidents incidents={incidents} />
        <AgentStatusPanel agents={agents} />
      </div>

      <RealtimeActivity />
    </div>
  );
}
