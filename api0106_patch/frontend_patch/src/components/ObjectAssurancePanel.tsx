import type { ObjectAssurance } from "../api/universal";
import "./ObjectAssurancePanel.css";

type Props = { review?: ObjectAssurance };

function pretty(value: string): string {
  return value.replace(/_/g, " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

export default function ObjectAssurancePanel({ review }: Props) {
  if (!review) return null;
  const { summary } = review;
  return (
    <section className="ua-panel oa-panel" aria-labelledby="oa-title">
      <div className="oa-heading">
        <div>
          <h2 id="oa-title">Object reference integrity</h2>
          <p>Checks references in the uploaded configuration. Missing from upload is not proof of an invalid live policy.</p>
        </div>
        <span className="oa-status">{pretty(review.status)}</span>
      </div>
      <div className="oa-metrics">
        <div><strong>{summary.references_checked}</strong><span>References checked</span></div>
        <div><strong>{summary.missing_in_upload}</strong><span>Not defined in upload</span></div>
        <div><strong>{summary.cycles}</strong><span>Group cycles</span></div>
        <div><strong>{summary.repeated_definitions}</strong><span>Repeated definitions</span></div>
      </div>
      {review.status === "not_assessed" ? (
        <p className="oa-note">Object dependency cross-references are not assessed for this configuration scope.</p>
      ) : review.observations.length ? (
        <ol className="oa-list">
          {review.observations.map((item) => (
            <li className="oa-entry" key={item.reference}>
              <div className="oa-entry-top"><strong>{item.reference} · {pretty(item.kind)}</strong>
                <span>Line {item.line_number}</span></div>
              <p><strong>{item.object_name}:</strong> {item.explanation}</p>
              <p><strong>Review:</strong> {item.recommendation}</p>
              {!!item.related_line_numbers.length && (
                <small>Related source lines: {item.related_line_numbers.join(", ")}</small>
              )}
            </li>
          ))}
        </ol>
      ) : (
        <p className="oa-note">No object-reference integrity observations were produced by the supported checks. This is not a comprehensive policy validation.</p>
      )}
      {summary.incomplete && (
        <p className="oa-note">The source or analysis was incomplete; absent definitions may be outside the inspected portion.</p>
      )}
      {summary.observations_omitted > 0 && (
        <p className="oa-note">{summary.observations_omitted} additional observations were omitted by the output limit.</p>
      )}
      <details className="oa-limitations">
        <summary>Coverage and interpretation limits</summary>
        <ul>{review.limitations.map((limit, i) => <li key={i}>{limit}</li>)}</ul>
      </details>
      <p className="oa-disclaimer">These checks do not alter existing security findings, scores, or rule correlations.</p>
    </section>
  );
}
