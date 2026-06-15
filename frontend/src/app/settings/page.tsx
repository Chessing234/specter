import { Database, Globe, Network, Radio, ShieldCheck } from "lucide-react";

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";
const WS_URL = process.env.NEXT_PUBLIC_WS_URL ?? "ws://localhost:8000";

function isConfigured(value: string) {
  return !value.includes("localhost");
}

interface Endpoint {
  label: string;
  value: string;
  icon: typeof Globe;
  description: string;
}

const endpoints: Endpoint[] = [
  {
    label: "API origin",
    value: API_URL,
    icon: Globe,
    description: "REST base for incidents, agents, and memory queries.",
  },
  {
    label: "WebSocket origin",
    value: WS_URL,
    icon: Radio,
    description: "Live event bus stream consumed by the dashboard.",
  },
];

const envVars: { name: string; example: string; note: string }[] = [
  {
    name: "NEXT_PUBLIC_API_URL",
    example: "https://api.your-domain.com",
    note: "Deployed SPECTER API origin. Defaults to http://localhost:8000 for local dev.",
  },
  {
    name: "NEXT_PUBLIC_WS_URL",
    example: "wss://api.your-domain.com",
    note: "WebSocket origin. Use wss:// in production for secure streams.",
  },
  {
    name: "API_PROXY_TARGET",
    example: "https://api.your-domain.com",
    note: "Optional. Rewrites /api/* to the backend (next.config.js) to avoid cross-origin calls.",
  },
];

export default function SettingsPage() {
  return (
    <div className="space-y-8">
      <header>
        <h1 className="text-2xl font-semibold tracking-tight">Settings</h1>
        <p className="mt-2 max-w-2xl text-muted-foreground">
          Connection and environment configuration for the SPECTER dashboard.
          The dashboard is a stateless client — all data is served by the
          FastAPI backend over REST and WebSocket.
        </p>
      </header>

      <section className="grid gap-4 sm:grid-cols-2">
        {endpoints.map((endpoint) => {
          const configured = isConfigured(endpoint.value);
          return (
            <div
              key={endpoint.label}
              className="rounded-lg border border-border bg-card p-5 shadow-sm"
            >
              <div className="flex items-start justify-between gap-3">
                <div className="flex items-center gap-2">
                  <endpoint.icon className="h-5 w-5 text-primary" />
                  <span className="font-medium">{endpoint.label}</span>
                </div>
                <span
                  className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-medium ${
                    configured
                      ? "bg-emerald-500/10 text-emerald-400"
                      : "bg-amber-500/10 text-amber-400"
                  }`}
                >
                  <span className="h-1.5 w-1.5 rounded-full bg-current" />
                  {configured ? "Configured" : "Local default"}
                </span>
              </div>
              <code className="mt-4 block truncate rounded-md bg-muted px-3 py-2 font-mono text-sm">
                {endpoint.value}
              </code>
              <p className="mt-3 text-sm text-muted-foreground">
                {endpoint.description}
              </p>
            </div>
          );
        })}
      </section>

      <section className="rounded-lg border border-border bg-card p-5 shadow-sm">
        <div className="flex items-center gap-2">
          <Network className="h-5 w-5 text-primary" />
          <h2 className="text-lg font-semibold">Environment variables</h2>
        </div>
        <p className="mt-1 text-sm text-muted-foreground">
          Set these in your hosting provider (e.g. Vercel project settings),
          then redeploy so the client picks them up.
        </p>
        <div className="mt-4 divide-y divide-border">
          {envVars.map((env) => (
            <div
              key={env.name}
              className="flex flex-col gap-2 py-3 sm:flex-row sm:items-start sm:justify-between sm:gap-6"
            >
              <code className="shrink-0 font-mono text-sm font-medium text-foreground">
                {env.name}
              </code>
              <div className="sm:text-right">
                <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs text-muted-foreground">
                  {env.example}
                </code>
                <p className="mt-1 text-sm text-muted-foreground">{env.note}</p>
              </div>
            </div>
          ))}
        </div>
      </section>

      <section className="grid gap-4 sm:grid-cols-2">
        <div className="rounded-lg border border-border bg-card p-5 shadow-sm">
          <div className="flex items-center gap-2">
            <Database className="h-5 w-5 text-primary" />
            <h2 className="font-medium">Persistence</h2>
          </div>
          <p className="mt-2 text-sm text-muted-foreground">
            The API stores incidents, memory entities, and vector embeddings in
            PostgreSQL-compatible storage (pgvector / Aurora DSQL). The dashboard
            never connects to the database directly.
          </p>
        </div>
        <div className="rounded-lg border border-border bg-card p-5 shadow-sm">
          <div className="flex items-center gap-2">
            <ShieldCheck className="h-5 w-5 text-primary" />
            <h2 className="font-medium">Transport</h2>
          </div>
          <p className="mt-2 text-sm text-muted-foreground">
            Production traffic should use HTTPS for REST and WSS for the event
            stream. The backend accepts cross-origin requests from approved
            dashboard origins.
          </p>
        </div>
      </section>
    </div>
  );
}
