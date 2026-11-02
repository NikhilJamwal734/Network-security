import type { ReportValidationReview } from "../api/universal";
import "./ReportValidationSnippet.css";

/** Summary only. Individual validation evidence and guidance are PDF-exclusive. */
export default function ReportValidationSnippet({ review }: { review?: ReportValidationReview }) {
  if (!review) return null;
  const s = review.summary;
  return (
    <section className="ua-panel rpt112-panel" aria-labelledby="rpt112-title">
      <div className="rpt112-heading">
        <h2 id="rpt112-title">Report validation review</h2>
        <span>{review.status === "inconsistent" ? "Needs attention" : review.status === "limited" ? "Limited coverage" : "Consistent subset"}</span>
      </div>
      <div className="rpt112-stats">
        <div><strong>{s.checks_performed}</strong><span>Checks</span></div>
        <div><strong>{s.passed_checks}</strong><span>Consistent</span></div>
        <div><strong>{s.discrepancies}</strong><span>Discrepancies</span></div>
        <div><strong>{s.warnings}</strong><span>Coverage warnings</span></div>
      </div>
      {review.checks.filter((c) => c.result !== "pass").slice(0, 2).length > 0 && (
        <ul className="rpt112-snippets">
          {review.checks.filter((c) => c.result !== "pass").slice(0, 2).map((c) => (
            <li key={c.reference}>{c.reference} · {c.check.replace(/_/g, " ")}</li>
          ))}
        </ul>
      )}
      <p className="rpt112-note">Structured report checks only. PDF rendering is not verified. Full evidence: PDF only.</p>
    </section>
  );
}
