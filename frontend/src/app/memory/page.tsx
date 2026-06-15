import { MemorySearch } from "@/components/memory/MemorySearch";

export default function MemoryPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">Organizational memory</h1>
        <p className="mt-2 text-muted-foreground">
          Vector search against the knowledge graph (Aurora DSQL + pgvector). Uses{" "}
          <code className="rounded bg-muted px-1 py-0.5 text-sm">
            POST /api/v1/memory/query
          </code>
          .
        </p>
      </div>
      <MemorySearch />
    </div>
  );
}
