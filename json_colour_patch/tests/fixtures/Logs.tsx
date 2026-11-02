import { useEffect, useMemo, useState } from "react";
import { loadAuditLogs, type LogEntry, type LogLevel, type LogStream } from "../api/logs";
import "./Logs.css";

const STREAMS: { value: LogStream; label: string }[] = [
  { value: "security_analysis", label: "Security Analysis" },
  { value: "upload_audit", label: "Upload Audit" },
  { value: "api_access", label: "API Access" },
  { value: "error", label: "Errors" },
  { value: "application", label: "Application" },
];
const LABELS: Record<LogLevel, string> = {
  error: "ERROR", warning: "WARNING", success: "SUCCESS", info: "INFO",
};
const allLevels: (LogLevel | "all")[] = ["all", "error", "warning", "success", "info"];

function prettyTime(value?: string) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}
function exportRows(rows: LogEntry[], stream: string) {
  const blob = new Blob([JSON.stringify(rows, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `FirewallAnalyzer-${stream}-filtered.json`;
  link.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/** Operations logs are distinct from configuration vulnerability findings. */
export default function Logs() {
  const [stream, setStream] = useState<LogStream>("security_analysis");
  const [entries, setEntries] = useState<LogEntry[]>([]);
  const [query, setQuery] = useState("");
  const [level, setLevel] = useState<LogLevel | "all">("all");
  const [live, setLive] = useState(true);
  const [refreshId, setRefreshId] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    let controller: AbortController | null = null;
    async function refresh() {
      controller?.abort();
      const current = new AbortController();
      controller = current;
      try {
        const data = await loadAuditLogs(stream, current.signal);
        if (!active || current.signal.aborted) return;
        setEntries(data.entries);
        setLastUpdated(data.generated_at_utc);
        setError(null);
      } catch (reason) {
        if (!active || current.signal.aborted) return;
        setError(reason instanceof Error ? reason.message : "Unable to load logs.");
      } finally {
        if (active && !current.signal.aborted) setLoading(false);
      }
    }
    setLoading(true);
    setEntries([]);
    void refresh();
    const timer = live ? window.setInterval(() => void refresh(), 5000) : null;
    return () => {
      active = false;
      if (timer !== null) window.clearInterval(timer);
      controller?.abort();
    };
  }, [stream, live, refreshId]);

  const filtered = useMemo(() => entries.filter((entry) => {
    if (level !== "all" && entry.level !== level) return false;
    const haystack = [entry.event, entry.filename, entry.platform, entry.route, entry.code,
      entry.error_type, entry.method, String(entry.status_code ?? "")].join(" ").toLowerCase();
    return haystack.includes(query.trim().toLowerCase());
  }), [entries, level, query]);
  const counts = useMemo(() => entries.reduce<Record<LogLevel, number>>((acc, e) => {
    if (e.level in acc) acc[e.level] += 1;
    return acc;
  }, { error: 0, warning: 0, success: 0, info: 0 }), [entries]);

  return <section className="fa-logs" aria-label="Application log viewer">
    <div className="fa-logs-title">
      <div>
        <p className="fa-logs-eyebrow">OPERATIONS / AUDIT TRAIL</p>
        <h1>Log Viewer</h1>
        <p>Colour-coded application, upload, API, and analysis events. These are not firewall traffic logs.</p>
      </div>
      <div className="fa-logs-actions">
        <button type="button" onClick={() => setRefreshId((n) => n + 1)}>Refresh</button>
        <button type="button" onClick={() => exportRows(filtered, stream)} disabled={!filtered.length}>Export JSON</button>
      </div>
    </div>
    <div className="fa-logs-summary" aria-label="Operational event counts">
      {(["error", "warning", "success", "info"] as const).map((name) =>
        <div key={name} className={`fa-logs-counter is-${name}`}>
          <span>{LABELS[name]}</span><strong>{counts[name]}</strong>
        </div>)}
    </div>
    <div className="fa-logs-controls">
      <label>Log category
        <select value={stream} onChange={e => setStream(e.target.value as LogStream)}>
          {STREAMS.map((s) => <option key={s.value} value={s.value}>{s.label}</option>)}
        </select>
      </label>
      <label>Event level
        <select value={level} onChange={e => setLevel(e.target.value as LogLevel | "all")}>
          {allLevels.map(l => <option value={l} key={l}>{l === "all" ? "All levels" : LABELS[l]}</option>)}
        </select>
      </label>
      <label>Search filename, event, or status
        <input type="search" value={query} onChange={e => setQuery(e.target.value)} placeholder="e.g. ASA-FIREWALL.cfg" />
      </label>
      <label className="fa-logs-live">
        <input type="checkbox" checked={live} onChange={e => setLive(e.target.checked)} /> Refresh every 5 seconds
      </label>
    </div>
    <div className="fa-logs-caption" role="status">
      <span>{loading ? "Loading…" : `Showing ${filtered.length} of ${entries.length} recent events`}</span>
      {lastUpdated && <span>Last updated {prettyTime(lastUpdated)}</span>}
    </div>
    {error && <div role="alert" className="fa-logs-error">{error}</div>}
    <div className="fa-logs-list" role="list" aria-label="Log entries">
      {!loading && !filtered.length && <p className="fa-logs-empty">No matching entries yet. Try a different log category or remove filters.</p>}
      {filtered.map((entry, index) =>
        <article role="listitem" className={`fa-log-row is-${entry.level}`} key={`${entry.timestamp_utc ?? ""}-${entry.event}-${index}`}>
          <span className="fa-log-dot" aria-hidden="true" />
          <div className="fa-log-body">
            <div className="fa-log-topline">
              <span className="fa-log-level">{LABELS[entry.level] ?? "INFO"}</span>
              <strong>{entry.event.replace(/_/g, " ")}</strong>
              <time>{prettyTime(entry.timestamp_utc)}</time>
            </div>
            <div className="fa-log-details">
              {entry.filename && <span><b>File</b> {entry.filename}</span>}
              {entry.platform && <span><b>Platform</b> {entry.platform}</span>}
              {entry.route && <span><b>Route</b> {entry.route}</span>}
              {entry.status_code !== undefined && <span><b>Status</b> {entry.status_code}</span>}
              {entry.finding_count !== undefined && <span><b>Findings</b> {entry.finding_count}</span>}
              {entry.duration_ms !== undefined && <span><b>Time</b> {entry.duration_ms} ms</span>}
              {entry.code && <span><b>Code</b> {entry.code}</span>}
              {entry.error_type && <span><b>Error type</b> {entry.error_type}</span>}
            </div>
          </div>
        </article>)}
    </div>
    <p className="fa-logs-footer">Local access only · Up to 200 recent entries per category · JSON files are not modified · Finding severity remains in the Findings page.</p>
  </section>;
}
