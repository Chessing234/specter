/** Shared types — prefer `@/lib/api` for API-aligned shapes. */

export type { AgentStatus, Incident, MemoryEntity } from "@/lib/api";

export type AgentStatusState = "idle" | "running" | "error" | "disabled";

export interface ServiceInfo {
  name: string;
  version: string;
  status: string;
  environment: string;
}
