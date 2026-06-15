export default function SettingsPage() {
  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold">Settings</h1>
      <div className="prose prose-invert max-w-none text-sm text-muted-foreground">
        <p>
          <strong className="text-foreground">Vercel + FastAPI</strong>: set{" "}
          <code className="rounded bg-muted px-1 py-0.5">NEXT_PUBLIC_API_URL</code>{" "}
          to your deployed SPECTER API origin (e.g.{" "}
          <code className="rounded bg-muted px-1 py-0.5">
            https://api.your-domain.com
          </code>
          ).
        </p>
        <p>
          <strong className="text-foreground">WebSocket</strong>: set{" "}
          <code className="rounded bg-muted px-1 py-0.5">NEXT_PUBLIC_WS_URL</code>{" "}
          to the WS origin (e.g. <code className="rounded bg-muted px-1 py-0.5">wss://api…</code>
          ). Defaults to <code className="rounded bg-muted px-1 py-0.5">ws://localhost:8000</code>{" "}
          for local dev.
        </p>
        <p>
          <strong className="text-foreground">Same-origin proxy</strong>:{" "}
          <code className="rounded bg-muted px-1 py-0.5">next.config.js</code> rewrites{" "}
          <code className="rounded bg-muted px-1 py-0.5">/api/*</code> to your backend when{" "}
          <code className="rounded bg-muted px-1 py-0.5">API_PROXY_TARGET</code> or{" "}
          <code className="rounded bg-muted px-1 py-0.5">NEXT_PUBLIC_API_URL</code> is set — useful
          for avoiding CORS during demos.
        </p>
        <p>
          <strong className="text-foreground">Aurora DSQL</strong>: the API persists incidents,
          memory entities, and embeddings in PostgreSQL-compatible storage; the dashboard only
          consumes REST + WS.
        </p>
      </div>
    </div>
  );
}
