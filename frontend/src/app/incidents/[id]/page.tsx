import Link from "next/link";

import { IncidentDetailView } from "@/components/incidents/IncidentDetailView";
import { api } from "@/lib/api";

interface PageProps {
  params: Promise<{ id: string }>;
}

export default async function IncidentDetailPage({ params }: PageProps) {
  const { id } = await params;

  try {
    const incident = await api.getIncident(id);

    return (
      <div className="space-y-6">
        <div className="flex flex-wrap items-center gap-4 text-sm text-muted-foreground">
          <Link href="/incidents" className="text-primary hover:underline">
            ← Incidents
          </Link>
          <span className="font-mono text-xs">{incident.id}</span>
        </div>

        <IncidentDetailView initial={incident} />
      </div>
    );
  } catch {
    return (
      <div className="space-y-6">
        <Link href="/incidents" className="text-sm text-primary hover:underline">
          ← Incidents
        </Link>
        <div className="rounded-lg border border-border bg-card p-6 shadow-sm">
          <h1 className="text-xl font-semibold">Incident {id}</h1>
          <p className="mt-3 text-sm text-muted-foreground">
            Incident not found. Start a demo from the dashboard or create one via{" "}
            <code className="rounded bg-muted px-1">POST /api/v1/incidents/demo</code>.
          </p>
        </div>
      </div>
    );
  }
}
