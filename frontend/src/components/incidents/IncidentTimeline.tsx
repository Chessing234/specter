import { Bot } from "lucide-react";

import type { WorkflowMessage } from "@/lib/api";

interface Props {
  messages: WorkflowMessage[];
  findings: Record<string, unknown>[];
  memoryContext: Record<string, unknown>;
  currentPhase: string | null;
}

const agentColors: Record<string, string> = {
  sentry: "text-orange-400",
  triage: "text-yellow-400",
  sherlock: "text-sky-400",
  commander: "text-violet-400",
  patch: "text-emerald-400",
  audit: "text-pink-400",
};

function summarizeContent(content: Record<string, unknown>): string {
  for (const key of [
    "detection_result",
    "triage_result",
    "investigation_result",
    "command_result",
    "remediation_result",
    "audit_result",
  ]) {
    const block = content[key];
    if (typeof block === "object" && block !== null) {
      const obj = block as Record<string, unknown>;
      if (typeof obj.reasoning === "string") return obj.reasoning;
      if (typeof obj.status === "string") return `Status: ${obj.status}`;
    }
  }
  const text = JSON.stringify(content);
  return text.length > 200 ? `${text.slice(0, 200)}…` : text;
}

export function IncidentTimeline({
  messages,
  findings,
  memoryContext,
  currentPhase,
}: Props) {
  const memoryEntries = Object.entries(memoryContext).filter(
    ([, v]) => v !== null && v !== undefined,
  );

  return (
    <div className="space-y-6">
      {currentPhase ? (
        <div className="flex items-center gap-2 text-sm">
          <span className="text-muted-foreground">Current phase:</span>
          <span className="rounded bg-muted px-2 py-0.5 font-mono text-xs uppercase">
            {currentPhase}
          </span>
        </div>
      ) : null}

      {memoryEntries.length > 0 ? (
        <section>
          <h3 className="mb-2 text-sm font-medium text-muted-foreground">
            Organizational context used
          </h3>
          <div className="rounded-md bg-muted/30 p-3 text-xs font-mono">
            {memoryEntries.slice(0, 6).map(([key, value]) => (
              <div key={key} className="truncate">
                <span className="text-primary">{key}:</span>{" "}
                {typeof value === "string"
                  ? value
                  : JSON.stringify(value).slice(0, 120)}
              </div>
            ))}
          </div>
        </section>
      ) : null}

      <section>
        <h3 className="mb-3 text-sm font-medium">Agent timeline</h3>
        {messages.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            Pipeline running… agent messages will appear here when processing
            completes. Watch the live activity panel for real-time bus traffic.
          </p>
        ) : (
          <ol className="relative space-y-4 border-l border-border pl-6">
            {messages.map((msg) => {
              const agent = msg.from_agent.toLowerCase();
              return (
                <li key={msg.id} className="relative">
                  <span className="absolute -left-[1.6rem] top-1 flex h-5 w-5 items-center justify-center rounded-full bg-card ring-2 ring-border">
                    <Bot
                      className={`h-3 w-3 ${agentColors[agent] ?? "text-muted-foreground"}`}
                    />
                  </span>
                  <div className="rounded-md border border-border/60 bg-muted/20 p-3">
                    <div className="flex flex-wrap items-center gap-2 text-sm">
                      <span
                        className={`font-semibold uppercase ${agentColors[agent] ?? ""}`}
                      >
                        {agent}
                      </span>
                      <span className="text-xs capitalize text-muted-foreground">
                        {msg.message_type}
                      </span>
                      {msg.timestamp ? (
                        <span className="ml-auto text-xs text-muted-foreground">
                          {new Date(msg.timestamp).toLocaleTimeString()}
                        </span>
                      ) : null}
                    </div>
                    <p className="mt-1 text-sm text-muted-foreground">
                      {summarizeContent(msg.content)}
                    </p>
                  </div>
                </li>
              );
            })}
          </ol>
        )}
      </section>

      {findings.length > 0 ? (
        <section>
          <h3 className="mb-2 text-sm font-medium">Findings ({findings.length})</h3>
          <ul className="space-y-2">
            {findings.map((f, i) => (
              <li
                key={i}
                className="rounded-md border border-border/60 bg-muted/20 p-3 text-sm"
              >
                <span className="font-medium capitalize">
                  {String(f.type ?? f.finding_type ?? "finding")}
                </span>
                {f.description ? (
                  <p className="mt-1 text-muted-foreground">{String(f.description)}</p>
                ) : null}
              </li>
            ))}
          </ul>
        </section>
      ) : null}
    </div>
  );
}
