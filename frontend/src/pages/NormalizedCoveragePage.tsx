import type { NormalizedReport } from "../api/universal";
import "./NormalizedPlatformPages.css";

const label = (text: string) => text.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
export default function NormalizedCoveragePage({ report }: { report: NormalizedReport }) {
  return <div className="np-page">
    <header className="np-header"><p className="np-kicker">{report.platform.display_name}</p><h1>Analysis Coverage</h1><p>What this static analyzer did and did not check.</p></header>
    <section className="np-panel"><h2>Assessment scope</h2><p className="np-muted">Assessed means implemented checks ran. It does not imply full platform coverage or runtime validation.</p>
      <div className="np-coverage">{report.coverage.domains.map((domain) => (
        <div className="np-coverage-row" key={domain.domain}><strong>{label(domain.domain)}</strong><span className={domain.status === "assessed" ? "np-assessed" : "np-unassessed"}>{domain.status === "assessed" ? "Assessed" : "Not assessed"}</span></div>
      ))}</div>
    </section>
    <section className="np-panel"><h2>Limitations</h2>{report.coverage.limitations.length ? <ul>{report.coverage.limitations.map((l, i) => <li key={`${i}-${l}`}>{l}</li>)}</ul> : <p className="np-muted">No additional limitations were supplied by the analyzer. Static configuration checks remain limited in scope.</p>}</section>
    {!!report.warnings.length && <section className="np-panel"><h2>Parser warnings</h2><ul>{report.warnings.map((w, i) => <li key={`${i}-${w}`}>{w}</li>)}</ul></section>}
  </div>;
}
