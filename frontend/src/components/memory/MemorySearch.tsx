"use client";

import { useState } from "react";

import { api, type MemoryEntity } from "@/lib/api";

export function MemorySearch() {
  const [query, setQuery] = useState("");
  const [entityType, setEntityType] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [rows, setRows] = useState<MemoryEntity[]>([]);

  async function onSearch(e: React.FormEvent) {
    e.preventDefault();
    if (!query.trim()) return;
    setLoading(true);
    setError(null);
    try {
      const out = await api.queryMemory(
        query.trim(),
        entityType.trim() || undefined,
        12,
      );
      setRows(out);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Query failed");
      setRows([]);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="space-y-4">
      <form onSubmit={onSearch} className="flex flex-col gap-3 sm:flex-row sm:items-end">
        <div className="min-w-0 flex-1 space-y-1">
          <label htmlFor="mq" className="text-sm text-muted-foreground">
            Semantic query
          </label>
          <input
            id="mq"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="e.g. admin lateral movement Okta"
            className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
          />
        </div>
        <div className="w-full space-y-1 sm:w-40">
          <label htmlFor="et" className="text-sm text-muted-foreground">
            Entity type (optional)
          </label>
          <input
            id="et"
            value={entityType}
            onChange={(e) => setEntityType(e.target.value)}
            placeholder="user"
            className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
          />
        </div>
        <button
          type="submit"
          disabled={loading}
          className="rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:opacity-90 disabled:opacity-50"
        >
          {loading ? "Searching…" : "Search"}
        </button>
      </form>

      {error ? (
        <p className="text-sm text-destructive">{error}</p>
      ) : null}

      {rows.length > 0 ? (
        <ul className="space-y-2">
          {rows.map((r) => (
            <li
              key={r.id}
              className="rounded-lg border border-border bg-muted/20 p-3 text-sm"
            >
              <div className="font-medium">
                {r.name}{" "}
                <span className="text-xs font-normal text-muted-foreground">
                  ({r.entity_type})
                </span>
              </div>
              {r.similarity != null ? (
                <div className="mt-1 text-xs text-muted-foreground">
                  similarity: {r.similarity.toFixed(3)}
                </div>
              ) : null}
            </li>
          ))}
        </ul>
      ) : null}
    </div>
  );
}
