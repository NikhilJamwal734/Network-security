import type { VendorReview } from "../api/universal";
import "./VendorDeepReviewPanel.css";

interface Props { review?: VendorReview }

export default function VendorDeepReviewPanel({ review }: Props) {
  if (!review) return null;
  const checks = review.checks;
  return (
    <section className="ua-panel vendor-deep-review" aria-labelledby="vendor-deep-title">
      <div className="vendor-deep-header">
        <div>
          <h2 id="vendor-deep-title">Vendor-specific configuration review</h2>
          <p>Additional checks against explicit settings and supported rule syntax.</p>
        </div>
        <span className="vendor-deep-count">{checks.length} review {checks.length === 1 ? "item" : "items"}</span>
      </div>
      {checks.length ? (
        <ol className="vendor-deep-list">
          {checks.map((check, index) => (
            <li key={`${check.code}-${check.line_number ?? "n"}-${index}`} className="vendor-deep-item">
              <div className="vendor-deep-item-heading">
                <strong>{check.title}</strong>
                <span className={`vendor-deep-severity vendor-deep-${check.severity.toLowerCase()}`}>{check.severity}</span>
              </div>
              <p>{check.detail}</p>
              <p><strong>Recommendation:</strong> {check.recommendation}</p>
              <small>{check.code}{check.line_number === null ? "" : ` · Source line ${check.line_number}`}{check.rule_id === null ? "" : ` · Rule / object ${check.rule_id}`}</small>
            </li>
          ))}
        </ol>
      ) : (
        <p className="vendor-deep-empty">No additional observations matched these vendor-specific checks. This does not establish that the configuration is secure.</p>
      )}
      {review.suppressed_checks > 0 && <p>{review.suppressed_checks} additional review items omitted to keep the response bounded.</p>}
      <details className="vendor-deep-limits">
        <summary>Assessment limitations</summary>
        <ul>{review.limitations.map((limit, index) => <li key={index}>{limit}</li>)}</ul>
      </details>
      <p className="vendor-deep-disclaimer">{review.interpretation}</p>
    </section>
  );
}
