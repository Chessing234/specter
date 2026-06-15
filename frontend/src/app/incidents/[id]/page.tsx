import Link from "next/link";

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

        <div className="rounded-lg border border-border bg-card p-6 shadow-sm">
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div>
              <h1 className="text-2xl font-semibold">{incident.title}</h1>
              <p className="mt-2 text-muted-foreground">{incident.description}</p>
            </div>
            <div className="flex flex-wrap gap-2">
              <span className="rounded border border-border px-2 py-1 text-xs capitalize">
                {incident.severity}
              </span>
              <span className="rounded border border-border px-2 py-1 text-xs capitalize">
                {incident.status}
              </span>
            </div>
          </div>

          <dl className="mt-6 grid gap-4 text-sm sm:grid-cols-2">
            <div>
              <dt className="text-muted-foreground">Created</dt>
              <dd>{new Date(incident.created_at).toLocaleString()}</dd>
            </div>
            {incident.updated_at ? (
              <div>
                <dt className="text-muted-foreground">Updated</dt>
                <dd>{new Date(incident.updated_at).toLocaleString()}</dd>
              </div>
            ) : null}
            <div>
              <dt className="text-muted-foreground">Assigned agent</dt>
              <dd>{incident.assigned_agent ?? "—"}</dd>
            </div>
            <div>
              <dt className="text-muted-foreground">Source</dt>
              <dd>{incident.source ?? "—"}</dd>
            </div>
          </dl>
        </div>

        <section className="rounded-lg border border-border bg-card p-6 shadow-sm">
          <h2 className="text-lg font-semibold">Timeline &amp; findings</h2>
          <p className="mt-2 text-sm text-muted-foreground">
            When the incidents API returns findings and agent reasoning (LangGraph
            state), this panel will render the investigation timeline.
          </p>
        </section>
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
            Detail view is not available yet from the API (store integration pending).
            Use the list page or connect{" "}
            <code className="rounded bg-muted px-1">GET /api/v1/incidents/{"{id}"}</code>{" "}
            to Aurora DSQL for full records.
          </p>
        </div>
      </div>
    );
  }
}
