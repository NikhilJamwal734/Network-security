import type { ServiceIPv6Review } from "../api/universal";
import "./ServiceIPv6Snippet.css";

type Props = { review?: ServiceIPv6Review };

export default function ServiceIPv6Snippet({ review }: Props) {
  if (!review) return null;
  const { summary } = review;
  return (
    <section className="ua-panel sg6-panel" aria-labelledby="sg6-title">
      <div className="sg6-head">
        <h2 id="sg6-title">Service groups &amp; IPv6</h2>
        <span>{review.status === "not_assessed" ? "Not assessed" : review.status === "limited" ? "Limited" : "Reviewed subset"}</span>
      </div>
      {review.status === "not_assessed" ? (
        <p className="sg6-note">These object checks are not assessed for this IDS/IPS configuration.</p>
      ) : (
        <>
          <div className="sg6-stats" aria-label="Service and IPv6 review summary">
            <div><strong>{summary.definitions_resolved}</strong><span>Objects resolved</span></div>
            <div><strong>{summary.definitions_unresolved}</strong><span>Unresolved</span></div>
            <div><strong>{summary.rules_eligible}</strong><span>Rules compared</span></div>
            <div><strong>{summary.correlation_candidates}</strong><span>Review candidates</span></div>
          </div>
          {review.pairs.length > 0 && (
            <ul className="sg6-previews">
              {review.pairs.slice(0, 2).map((pair) => (
                <li key={pair.reference}><strong>{pair.reference}</strong> · {pair.kind.replace(/_/g, " ")}
                  <small>Lines {pair.related_line_number} and {pair.line_number}</small>
                </li>
              ))}
            </ul>
          )}
          {summary.incomplete && <p className="sg6-note">Coverage is incomplete; no absence conclusion is supported.</p>}
        </>
      )}
      <p className="sg6-pdf-note">Full object definitions, source evidence, relationships, recommendations, and limitations are in the PDF report.</p>
    </section>
  );
}
