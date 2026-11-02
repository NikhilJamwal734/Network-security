/** Typed read-only log API. Operational levels are NOT security-finding severity. */
export type LogStream = "application" | "api_access" | "upload_audit" | "security_analysis" | "error";
export type LogLevel = "error" | "warning" | "success" | "info";
export interface LogEntry {
  timestamp_utc?: string;
  event: string;
  level: LogLevel;
  filename?: string;
  platform?: string;
  route?: string;
  method?: string;
  status_code?: number;
  duration_ms?: number;
  finding_count?: number;
  size_bytes?: number;
  error_type?: string;
  code?: string;
  request_id?: string;
}
export interface LogResponse {
  stream: LogStream;
  count: number;
  generated_at_utc: string;
  entries: LogEntry[];
}

const API_BASE = (import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000").replace(/\/+$/, "");

export async function loadAuditLogs(stream: LogStream, signal?: AbortSignal, limit = 200): Promise<LogResponse> {
  const url = new URL(`${API_BASE}/api/v1/logs`);
  url.searchParams.set("stream", stream);
  url.searchParams.set("limit", String(limit));
  const res = await fetch(url.toString(), { signal, cache: "no-store" });
  if (!res.ok) {
    throw new Error(res.status === 403
      ? "Log access is restricted to local connections."
      : `Log API returned HTTP ${res.status}. Check that the backend is running.`);
  }
  const json: unknown = await res.json();
  if (!json || typeof json !== "object" || !('entries' in json) || !Array.isArray(json.entries)) {
    throw new Error("Unexpected response from the audit logs API.");
  }
  return json as LogResponse;
}
