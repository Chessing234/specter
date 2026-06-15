import Link from "next/link";

import { api } from "@/lib/api";

export default async function IncidentsPage() {
  const incidents = await api.listIncidents().catch(() => []);

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold">Incidents</h1>

      <div className="overflow-hidden rounded-lg border border-border bg-card shadow-sm">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border bg-muted/40">
              <th className="p-4 text-left font-medium text-muted-foreground">
                Title
              </th>
              <th className="p-4 text-left font-medium text-muted-foreground">
                Severity
              </th>
              <th className="p-4 text-left font-medium text-muted-foreground">
                Status
              </th>
              <th className="hidden p-4 text-left font-medium text-muted-foreground md:table-cell">
                Source
              </th>
              <th className="p-4 text-left font-medium text-muted-foreground">
                Date
              </th>
            </tr>
          </thead>
          <tbody>
            {incidents.length === 0 ? (
              <tr>
                <td
                  colSpan={5}
                  className="p-8 text-center text-muted-foreground"
                >
                  No incidents loaded. Backend{" "}
                  <code className="rounded bg-muted px-1">GET /api/v1/incidents/</code>{" "}
                  returns data when wired to Aurora DSQL / store.
                </td>
              </tr>
            ) : (
              incidents.map((incident) => (
                <tr
                  key={incident.id}
                  className="border-b border-border/60 last:border-0 hover:bg-muted/30"
                >
                  <td className="p-4">
                    <Link
                      href={`/incidents/${incident.id}`}
                      className="font-medium text-primary hover:underline"
                    >
                      {incident.title}
                    </Link>
                  </td>
                  <td className="p-4">
                    <span
                      className={`rounded px-2 py-1 text-xs capitalize ${
                        incident.severity === "critical"
                          ? "bg-destructive/15 text-destructive"
                          : incident.severity === "high"
                            ? "bg-orange-500/15 text-orange-400"
                            : incident.severity === "medium"
                              ? "bg-yellow-500/15 text-yellow-400"
                              : "bg-primary/10 text-primary"
                      }`}
                    >
                      {incident.severity}
                    </span>
                  </td>
                  <td className="p-4 capitalize text-muted-foreground">
                    {incident.status}
                  </td>
                  <td className="hidden p-4 text-muted-foreground md:table-cell">
                    {incident.source ?? "—"}
                  </td>
                  <td className="p-4 text-muted-foreground">
                    {new Date(incident.created_at).toLocaleDateString()}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
