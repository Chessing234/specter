/** API client for SPECTER FastAPI backend. */

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

export interface AgentStatus {
  name: string;
  status: "idle" | "running" | "error" | "disabled";
  last_action: string | null;
  capabilities: string[];
}

export interface WorkflowMessage {
  id: string;
  from_agent: string;
  to_agent: string | null;
  message_type: string;
  content: Record<string, unknown>;
  timestamp: string;
  priority?: number;
}

export interface Incident {
  id: string;
  title: string;
  description: string;
  severity: "low" | "medium" | "high" | "critical";
  status: string;
  source?: string;
  created_at: string;
  updated_at?: string;
  assigned_agent: string | null;
  confidence_score?: number;
  raw_data?: Record<string, unknown>;
  current_phase?: string | null;
  messages?: WorkflowMessage[];
  findings?: Record<string, unknown>[];
  memory_context?: Record<string, unknown>;
  actions?: Record<string, unknown>[];
}

export interface MemoryEntity {
  id: string;
  entity_type: string;
  name: string;
  properties: Record<string, unknown>;
  similarity?: number;
  source: string;
  confidence: number;
  timestamp?: string;
}

/** Raw row from POST /api/v1/memory/query */
interface MemoryEntryApi {
  id: string;
  entity_type: string;
  content: {
    name?: string;
    properties?: Record<string, unknown>;
    similarity?: number;
  };
  confidence: number;
  source: string;
  timestamp: string;
}

async function fetchApi<T>(path: string, options?: RequestInit): Promise<T> {
  const url = `${API_URL.replace(/\/$/, "")}${path}`;
  const response = await fetch(url, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...options?.headers,
    },
  });

  if (!response.ok) {
    throw new Error(`API error: ${response.status} ${response.statusText}`);
  }

  return response.json() as Promise<T>;
}

function mapMemoryEntry(row: MemoryEntryApi): MemoryEntity {
  const props = row.content.properties ?? {};
  return {
    id: row.id,
    entity_type: row.entity_type,
    name: row.content.name ?? row.id,
    properties: props,
    similarity: row.content.similarity,
    source: row.source,
    confidence: row.confidence,
    timestamp: row.timestamp,
  };
}

export const api = {
  listAgents: () => fetchApi<AgentStatus[]>("/api/v1/agents/"),

  invokeAgent: (
    name: string,
    action: string,
    context?: Record<string, unknown>,
  ) =>
    fetchApi<unknown>(`/api/v1/agents/${encodeURIComponent(name)}/invoke`, {
      method: "POST",
      body: JSON.stringify({ agent_name: name, action, context }),
    }),

  listIncidents: () => fetchApi<Incident[]>("/api/v1/incidents/"),

  getIncident: (id: string) =>
    fetchApi<Incident>(`/api/v1/incidents/${encodeURIComponent(id)}`),

  createIncident: (data: {
    title: string;
    description: string;
    severity: Incident["severity"];
    source: string;
    raw_data?: Record<string, unknown>;
  }) =>
    fetchApi<Incident>("/api/v1/incidents/", {
      method: "POST",
      body: JSON.stringify(data),
    }),

  createDemoIncident: () =>
    fetchApi<Incident>("/api/v1/incidents/demo", {
      method: "POST",
      body: JSON.stringify({}),
    }),

  queryMemory: (query: string, entityType?: string, limit?: number) =>
    fetchApi<MemoryEntryApi[]>("/api/v1/memory/query", {
      method: "POST",
      body: JSON.stringify({
        query,
        entity_type: entityType,
        limit: limit ?? 10,
      }),
    }).then((rows) => rows.map(mapMemoryEntry)),

  health: () => fetchApi<{ status: string; service?: string }>("/health"),
};
