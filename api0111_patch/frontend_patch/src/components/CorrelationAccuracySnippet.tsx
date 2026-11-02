import type { CorrelationAccuracyReview } from "../api/universal";
import "./CorrelationAccuracySnippet.css";

/** Bounded dashboard snippets only. Full reasons and remedies are PDF-exclusive. */
export default function CorrelationAccuracySnippet({ review }: { review?: CorrelationAccuracyReview }) {
  if (!review) return null;
  const s = review.summary;
  return (
    <section className="ua-panel acc111-panel" aria-labelledby="acc111-heading">
      <div className="acc111-heading">
        <h2 id="acc111-heading">Correlation accuracy review</h2>
        <span>{review.status === "limited" ? "Limited review" : "Reviewed subset"}</span>
      </div>
      <div className="acc111-stats">
        <div><strong>{s.links_checked}</strong><span>Links inspected</span></div>
        <div><strong>{s.plausible_links}</strong><span>Potential matches</span></div>
        <div><strong>{s.unsupported_links}</strong><span>Unsupported links</span></div>
        <div><strong>{s.uncertain_links}</strong><span>Need context</span></div>
      </div>
      {review.decisions.length > 0 && (
        <ul className="acc111-snippets">
          {review.decisions.slice(0, 2).map((item) => (
            <li key={item.reference}>{item.reference} · {item.classification.replace(/_/g, " ")}</li>
          ))}
        </ul>
      )}
      {s.incomplete && <p className="acc111-note">Partial coverage — see the PDF report.</p>}
      <p className="acc111-note">No findings or scores were changed. Detailed evidence: PDF only.</p>
    </section>
  );
}
