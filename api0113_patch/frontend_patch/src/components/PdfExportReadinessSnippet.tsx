import type { PdfExportReview } from "../api/universal";
import "./PdfExportReadinessSnippet.css";

/** Only counts and two short labels: full observations belong in PDF. */
export default function PdfExportReadinessSnippet({ review }: { review?: PdfExportReview }) {
  if (!review) return null;
  const s = review.summary;
  return (
    <section className="ua-panel pdf113-panel" aria-labelledby="pdf113-title">
      <div className="pdf113-heading">
        <h2 id="pdf113-title">PDF export readiness</h2>
        <span>{review.status === "blocked" ? "Review blockers" : review.status === "limited" ? "Limited preflight" : "Preflight checked"}</span>
      </div>
      <div className="pdf113-stats">
        <div><strong>{s.checks}</strong><span>Checks</span></div>
        <div><strong>{s.passed}</strong><span>Passed</span></div>
        <div><strong>{s.warnings}</strong><span>Warnings</span></div>
        <div><strong>{s.blockers}</strong><span>Blockers</span></div>
      </div>
      {review.observations.length > 0 && (
        <ul className="pdf113-snippets">
          {review.observations.slice(0, 2).map((item) => (
            <li key={item.reference}>{item.reference} · {item.kind.replace(/_/g, " ")}</li>
          ))}
        </ul>
      )}
      <p className="pdf113-note">Pre-export structure checks only. Detailed observations: PDF report.</p>
    </section>
  );
}
