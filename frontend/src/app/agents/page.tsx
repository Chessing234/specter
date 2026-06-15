import { AgentStatusPanel } from "@/components/dashboard/AgentStatusPanel";
import { RealtimeActivity } from "@/components/dashboard/RealtimeActivity";
import { api } from "@/lib/api";

export default async function AgentsPage() {
  const agents = await api.listAgents().catch(() => []);

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-2xl font-semibold">Agents</h1>
        <p className="mt-2 text-muted-foreground">
          LangGraph fleet status from{" "}
          <code className="rounded bg-muted px-1 py-0.5 text-sm">
            GET /api/v1/agents/
          </code>
          . Live bus traffic uses{" "}
          <code className="rounded bg-muted px-1 py-0.5 text-sm">/ws/events</code>{" "}
          (set <code className="rounded bg-muted px-1">NEXT_PUBLIC_WS_URL</code> on
          Vercel if the API is on another host).
        </p>
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <AgentStatusPanel agents={agents} />
        <RealtimeActivity />
      </div>
    </div>
  );
}
