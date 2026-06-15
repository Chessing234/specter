import { Clock } from "lucide-react";
import Link from "next/link";

import type { Incident } from "@/lib/api";

interface Props {
  incidents: Incident[];
}

const severityColors: Record<string, string> = {
  critical: "bg-destructive/15 text-destructive border-destructive/30",
  high: "bg-orange-500/15 text-orange-400 border-orange-500/30",
  medium: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
  low: "bg-primary/10 text-primary border-border",
};

export function RecentIncidents({ incidents }: Props) {
  return (
    <div className="rounded-lg border border-border bg-card p-4 shadow-sm">
      <h2 className="mb-4 text-lg font-semibold">Recent incidents</h2>

      {incidents.length === 0 ? (
        <p className="py-8 text-center text-sm text-muted-foreground">
          No incidents yet. Create one via the API or incident intake.
        </p>
      ) : (
        <div className="space-y-3">
          {incidents.slice(0, 10).map((incident) => (
            <Link
              key={incident.id}
              href={`/incidents/${incident.id}`}
              className="block rounded-lg border border-transparent bg-muted/30 p-3 transition hover:border-border hover:bg-muted/50"
            >
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0 flex-1">
                  <h3 className="truncate text-sm font-medium">{incident.title}</h3>
                  <div className="mt-1 flex flex-wrap items-center gap-2">
                    <span
                      className={`rounded border px-2 py-0.5 text-xs capitalize ${
                        severityColors[incident.severity] ?? severityColors.low
                      }`}
                    >
                      {incident.severity}
                    </span>
                    {incident.source ? (
                      <span className="text-xs text-muted-foreground">
                        {incident.source}
                      </span>
                    ) : null}
                    <span className="flex items-center gap-1 text-xs text-muted-foreground">
                      <Clock className="h-3 w-3 shrink-0" />
                      {new Date(incident.created_at).toLocaleDateString()}
                    </span>
                  </div>
                </div>
                <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-muted text-xs font-medium">
                  {Math.round((incident.confidence_score ?? 0) * 100)}%
                </div>
              </div>
            </Link>
          ))}
        </div>
      )}
    </div>
  );
}
