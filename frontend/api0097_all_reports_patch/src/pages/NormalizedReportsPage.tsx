import type { NormalizedReport } from "../api/universal";
import NormalizedReportDownloads from "../components/NormalizedReportDownloads";
import "./NormalizedPlatformPages.css";

const severities = ["critical", "high", "medium", "low", "info", "unknown"] as const;
export default function NormalizedReportsPage({ report, filename }: { report: NormalizedReport; filename: string }) {
  return <div className="np-page">
    <header className="np-header"><p className="np-kicker">{report.platform.display_name}</p><h1>Security Reports</h1><p>Download a report for this uploaded configuration.</p></header>
    <section className="np-panel"><h2>Export this assessment</h2><p className="np-muted">Both files contain the same normalized findings and coverage. PDF is formatted for reading; JSON is suitable for further processing.</p>
      <NormalizedReportDownloads report={report} filename={filename} />
    </section>
    <section className="np-panel"><h2>Report summary</h2><div className="np-summary-grid">
      <div><span>Platform</span><strong>{report.platform.display_name}</strong></div>
      <div><span>Findings</span><strong>{report.summary.total_findings}</strong></div>
      <div><span>Security score</span><strong>{report.summary.security_score === null ? "Not scored" : `${report.summary.security_score}/100`}</strong></div>
      <div><span>Risk level</span><strong>{report.summary.risk_level ?? "Not assigned"}</strong></div>
    </div>
    <h3>Severity breakdown</h3><div className="np-severity-grid">{severities.map((s) => <div key={s}><span>{s.toUpperCase()}</span><strong>{report.summary.severity_counts[s]}</strong></div>)}</div>
    <p className="np-muted">This is static analysis of an uploaded configuration, not a runtime IDS/IPS assessment or a full policy verification.</p></section>
  </div>;
}
