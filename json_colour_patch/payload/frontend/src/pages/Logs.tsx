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
const ALL_LEVELS: (LogLevel | "all")[] = ["all", "error", "warning", "success", "info"];

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

/**
 * Render each log record as ONE compact JSON object on ONE line.
 * React escapes all values automatically: no HTML injection or unsafe innerHTML.
 * Only the presentation changes; underlying JSONL log files are untouched.
 */
function JsonLogLine({ entry }: { entry: LogEntry }) {
  const pairs = Object.entries(entry).filter(([, value]) => value !== undefined);
  return (
    <code className="fa-json-line">
      <span className="fa-json-punctuation">{"{"}</span>
      {pairs.map(([key, value], index) => {
        let valueClass = "fa-json-value";
        if (key === "event" || key === "level") {
          valueClass += ` fa-json-event-${entry.level}`;
        } else if (key === "status_code" && typeof value === "number") {
          valueClass += value >= 500 ? " fa-json-event-error"
            : value >= 400 ? " fa-json-event-warning"
            : " fa-json-event-success";
        } else if (typeof value === "string") {
          valueClass += " fa-json-string";
        } else if (typeof value === "number") {
          valueClass += " fa-json-number";
        } else {
          valueClass += " fa-json-literal";
        }
        return (
          <span key={key}>
            {index > 0 && <span className="fa-json-punctuation">, </span>}
            <span className="fa-json-key">{JSON.stringify(key)}</span>
            <span className="fa-json-punctuation">: </span>
            <span className={valueClass}>{JSON.stringify(value)}</span>
          </span>
        );
      })}
      <span className="fa-json-punctuation">{"}"}</span>
    </code>
  );
}

/** Same log viewer and controls, but raw-looking syntax-coloured JSON instead of cards. */
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

  return (
    <section className="fa-logs" aria-label="Application log viewer">
      <div className="fa-logs-title">
        <div>
          <h1>Logs</h1>
          <p>Original JSON-style events with colour highlighting only.</p>
        </div>
        <div className="fa-logs-actions">
          <button type="button" onClick={() => setRefreshId((n) => n + 1)}>Refresh</button>
          <button type="button" onClick={() => exportRows(filtered, stream)} disabled={!filtered.length}>Export JSON</button>
        </div>
      </div>
      <div className="fa-logs-controls">
        <label>Log category
          <select value={stream} onChange={e => setStream(e.target.value as LogStream)}>
            {STREAMS.map((s) => <option key={s.value} value={s.value}>{s.label}</option>)}
          </select>
        </label>
        <label>Event level
          <select value={level} onChange={e => setLevel(e.target.value as LogLevel | "all")}>
            {ALL_LEVELS.map(l => <option value={l} key={l}>{l === "all" ? "All levels" : LABELS[l]}</option>)}
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
      <div className="fa-json-scroll" aria-label="JSON log events">
        <pre className="fa-json-output">
          {loading ? "Loading logs…" : filtered.length === 0
            ? "No matching JSON log events yet."
            : filtered.map((entry, index) => (
              <JsonLogLine key={`${entry.timestamp_utc ?? ""}-${entry.event}-${index}`} entry={entry} />
            ))}
        </pre>
      </div>
      <p className="fa-logs-footer">JSON log files are unchanged · Display colours are not stored in the files · Local access only.</p>
    </section>
  );
}
