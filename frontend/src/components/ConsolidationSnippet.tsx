import type { ConsolidationReview } from "../api/universal";
import "./ConsolidationSnippet.css";

/** Only short metadata snippets. No source configuration, interpretations or remediation. */
export default function ConsolidationSnippet({ review }: { review?: ConsolidationReview }) {
  if (!review) return null;
  const s = review.summary;
  return (
    <section className="ua-panel con110-panel" aria-labelledby="con110-title">
      <div className="con110-heading">
        <h2 id="con110-title">Cross-review consistency</h2>
        <span>{review.status === "limited" ? "Limited coverage" : "Reviewed subset"}</span>
      </div>
      <div className="con110-stats">
        <div><strong>{s.sections_present}</strong><span>Review sections</span></div>
        <div><strong>{s.advisory_items_examined}</strong><span>Items examined</span></div>
        <div><strong>{s.candidate_links}</strong><span>Potential links</span></div>
        <div><strong>{s.quality_observations}</strong><span>Metadata checks</span></div>
      </div>
      {review.issues.length > 0 && (
        <ul className="con110-snippets">
          {review.issues.slice(0, 2).map((item) => (
            <li key={item.reference}><strong>{item.reference}</strong> · {item.kind.replace(/_/g, " ")}</li>
          ))}
        </ul>
      )}
      {s.incomplete && <p className="con110-note">Partial review — exclusions are documented in the PDF.</p>}
      <p className="con110-note">Source evidence, cross-review links and recommendations: PDF only.</p>
    </section>
  );
}
