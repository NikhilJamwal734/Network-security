import { useState } from "react";
import type { FirewallReport } from "../types/report";
const severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
export default function Findings({report}: {report: FirewallReport}) {
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState("ALL");
  const [page, setPage] = useState(0);
  const filtered = report.findings.filter(f => (severity === "ALL" || f.severity === severity) && `${f.code} ${f.title} ${f.description} ${f.rule_id ?? ""} ${f.line_number ?? ""}`.toLowerCase().includes(query.toLowerCase()));
  const pages = Math.max(1, Math.ceil(filtered.length / 25));
  const current = Math.min(page, pages - 1);
  return <section className="review-page">
    <div className="page-header"><div><div className="breadcrumb">Security Analysis / Findings</div><h1>Security findings</h1><p>Review every finding, its evidence, and the suggested action.</p></div></div>
    <div className="filter-bar"><label>Search<input value={query} onChange={e => {setQuery(e.target.value); setPage(0);}} placeholder="Code, title, rule, or line" /></label><label>Severity<select value={severity} onChange={e => {setSeverity(e.target.value); setPage(0);}}><option value="ALL">All severities</option>{severities.map(s => <option key={s}>{s}</option>)}</select></label><span className="result-count">{filtered.length} of {report.findings.length} findings</span></div>
    <div className="finding-details-list">{filtered.slice(current * 25, (current + 1) * 25).map((f, i) => <article className="panel finding-detail" key={`${f.code}-${f.rule_id}-${i}`}><div className="finding-title-row"><span className={`severity-badge severity-${f.severity.toLowerCase()}`}>{f.severity}</span><span className="finding-code">{f.code}</span><h2>{f.title}</h2></div><div className="finding-meta"><span>Rule: {f.rule_id ?? "N/A"}</span><span>Line: {f.line_number ?? "N/A"}</span>{f.related_rule_id !== null && <span>Related rule: {f.related_rule_id}</span>}</div><p>{f.description}</p><div className="recommendation"><strong>Recommended action</strong><p>{f.recommendation}</p></div></article>)}</div>
    {filtered.length === 0 && <div className="panel empty-state">No findings match these filters.</div>}
    <div className="pagination"><button className="action" disabled={current === 0} onClick={() => setPage(current - 1)}>Previous</button><span>Page {current + 1} of {pages}</span><button className="action" disabled={current + 1 >= pages} onClick={() => setPage(current + 1)}>Next</button></div>
  </section>;
}
