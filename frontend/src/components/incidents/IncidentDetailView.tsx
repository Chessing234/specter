"use client";

import { useEffect, useState } from "react";

import { IncidentTimeline } from "@/components/incidents/IncidentTimeline";
import type { Incident } from "@/lib/api";
import { api } from "@/lib/api";

interface Props {
  initial: Incident;
}

export function IncidentDetailView({ initial }: Props) {
  const [incident, setIncident] = useState(initial);
  const processing =
    incident.status === "new" ||
    incident.status === "triaging" ||
    incident.status === "investigating";

  useEffect(() => {
    if (!processing) return;

    const interval = setInterval(async () => {
      try {
        const updated = await api.getIncident(incident.id);
        setIncident(updated);
        if (
          updated.status === "resolved" ||
          updated.status === "closed" ||
          updated.status === "contained" ||
          updated.status === "error"
        ) {
          clearInterval(interval);
        }
      } catch {
        /* keep polling */
      }
    }, 2000);

    return () => clearInterval(interval);
  }, [incident.id, processing]);

  return (
    <>
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
            <span
              className={`rounded border px-2 py-1 text-xs capitalize ${
                processing
                  ? "border-sky-500/50 bg-sky-500/10 text-sky-400"
                  : "border-border"
              }`}
            >
              {incident.status}
              {processing ? " · live" : ""}
            </span>
            {incident.confidence_score != null && incident.confidence_score > 0 ? (
              <span className="rounded border border-border px-2 py-1 text-xs">
                Confidence {(incident.confidence_score * 100).toFixed(0)}%
              </span>
            ) : null}
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
        <div className="mt-4">
          <IncidentTimeline
            messages={incident.messages ?? []}
            findings={incident.findings ?? []}
            memoryContext={incident.memory_context ?? {}}
            currentPhase={incident.current_phase ?? null}
          />
        </div>
      </section>
    </>
  );
}
