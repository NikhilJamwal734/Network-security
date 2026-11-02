/** API-010.0 report validation panel for all four supported platforms.
 * Diagnostics are NOT security findings and never change the risk score.
 * All text is rendered through React escaping; no raw HTML or configuration
 * commands are inserted into the DOM.
 */
import type { ReportQuality } from "../api/universal";
import "./ReportQualityPanel.css";

interface Props {
  quality?: ReportQuality;
}

export default function ReportQualityPanel({ quality }: Props) {
  if (!quality) return null;
  const hasErrors = quality.summary.errors > 0;
  const label = hasErrors
    ? "Report needs review"
    : quality.coverage.incomplete
      ? "Internally consistent · Limited coverage"
      : "Internally consistent · Reviewed scope only";
  return (
    <section className="ua-panel report-quality" aria-labelledby="report-quality-title">
      <div className="report-quality-head">
        <div>
          <h2 id="report-quality-title">Report accuracy checks</h2>
          <p>Cross-checks findings, severity counts, identifiers, inventory, and review scoring.</p>
        </div>
        <span className={`report-quality-badge ${hasErrors ? "report-quality-badge-error" : "report-quality-badge-ok"}`}>
          {label}
        </span>
      </div>
      <div className="report-quality-metrics">
        <div><span>Findings cross-checked</span><strong>{quality.finding_evidence.findings_crosschecked_with_adapter} / {quality.finding_evidence.findings_total}</strong></div>
        <div><span>Consistency errors</span><strong>{quality.summary.errors}</strong></div>
        <div><span>Areas not assessed</span><strong>{quality.coverage.unassessed_domains.length}</strong></div>
      </div>
      {quality.issues.length > 0 && (
        <div className="report-quality-issues">
          <h3>Validation notices</h3>
          <ul>
            {quality.issues.map((issue, index) => (
              <li key={`${issue.code}-${index}`}>
                <strong>{issue.code}</strong> — {issue.explanation}
              </li>
            ))}
          </ul>
          {quality.summary.issues_suppressed > 0 && (
            <p>{quality.summary.issues_suppressed} further validation notices were suppressed.</p>
          )}
        </div>
      )}
      <p className="report-quality-caveat">{quality.platform_note}</p>
      <p className="report-quality-caveat">{quality.finding_evidence.line_reference_note}</p>
      <small className="report-quality-footnote">
        These checks validate the consistency of the generated report, not the real-world
        security of a firewall or IDS/IPS deployment. Unassessed areas remain unknown.
      </small>
    </section>
  );
}
