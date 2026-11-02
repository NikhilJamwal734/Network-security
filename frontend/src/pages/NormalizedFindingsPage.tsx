import { useState, type ChangeEvent } from "react";
import type { NormalizedReport, Severity } from "../api/universal";
import "./NormalizedPlatformPages.css";

const severities: Severity[] = ["critical", "high", "medium", "low", "info", "unknown"];
const label = (text: string) => text.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());

export default function NormalizedFindingsPage({ report }: { report: NormalizedReport }) {
  const [severity, setSeverity] = useState<Severity | "all">("all");
  const [search, setSearch] = useState("");
  const filtered = report.findings.filter((finding) =>
    (severity === "all" || finding.severity === severity) &&
    [finding.title, finding.description, finding.code, finding.recommendation]
      .some((text) => text.toLowerCase().includes(search.trim().toLowerCase()))
  );
  return (
    <div className="np-page">
      <header className="np-header"><p className="np-kicker">{report.platform.display_name}</p><h1>Security Findings</h1><p>Findings detected by supported static checks.</p></header>
      <section className="np-panel">
        <div className="np-toolbar">
          <label>Severity<select value={severity} onChange={(event: ChangeEvent<HTMLSelectElement>) => setSeverity(event.target.value as Severity | "all")}>
            <option value="all">All severity levels</option>
            {severities.map((s) => <option key={s} value={s}>{label(s)} ({report.summary.severity_counts[s]})</option>)}
          </select></label>
          <label>Search findings<input type="search" value={search} onChange={(event: ChangeEvent<HTMLInputElement>) => setSearch(event.target.value)} placeholder="Search title, description, code…" /></label>
        </div>
        <p className="np-muted">Showing {filtered.length} of {report.summary.total_findings} findings</p>
        <div className="np-stack">
          {filtered.map((finding) => (
            <article className="np-finding" key={finding.finding_id}>
              <div className="np-tags"><span className={`np-tag np-${finding.severity}`}>{label(finding.severity)}</span><code>{finding.code}</code></div>
              <h2>{finding.title}</h2><p>{finding.description}</p>
              {finding.recommendation && <p><strong>Recommendation: </strong>{finding.recommendation}</p>}
              <p className="np-muted np-evidence">{finding.evidence.line_number !== null ? `Line ${finding.evidence.line_number} · ` : ""}{finding.evidence.rule_id !== null ? `Rule ${finding.evidence.rule_id} · ` : ""}Finding ID: {finding.finding_id}</p>
            </article>
          ))}
          {!filtered.length && <p className="np-muted">No findings match the current filters.</p>}
        </div>
      </section>
    </div>
  );
}
