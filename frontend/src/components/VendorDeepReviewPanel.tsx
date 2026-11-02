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
      {review.precision && (
        <p className="vendor-deep-precision-summary">
          Context refinement: {review.precision.suppressed_preliminary_checks} preliminary observations removed;
          {" "}{review.precision.additional_evidence_checks} additional evidence checks added.
          {" "}{review.precision.note}
        </p>
      )}
      <div data-dashboard-snippet="vendor-review">
        {checks.length ? (
          <ol className="vendor-deep-list">
            {checks.slice(0, 2).map((check, index) => (
              <li key={`${check.code}-${check.line_number ?? "n"}-${index}`} className="vendor-deep-item">
                <div className="vendor-deep-item-heading">
                  <strong>{check.title}</strong>
                  <span className={`vendor-deep-severity vendor-deep-${check.severity.toLowerCase()}`}>{check.severity}</span>
                </div>
                <small>{check.code}{check.line_number === null ? "" : ` · Line ${check.line_number}`}</small>
              </li>
            ))}
          </ol>
        ) : <p className="vendor-deep-empty">No supplemental issues identified by the implemented checks.</p>}
        {checks.length > 2 && <p className="ua-hint">+{checks.length - 2} more review items in the PDF.</p>}
        {review.suppressed_checks > 0 && <p className="ua-hint">{review.suppressed_checks} observations omitted by the analysis service.</p>}
        <p className="ua-hint">Read the PDF for all available evidence, recommendations and assessment limitations.</p>
      </div>
    </section>
  );
}
