import type { ObjectResolution } from "../api/universal";
import "./ObjectResolutionPanel.css";

type Props = { analysis?: ObjectResolution };

function label(value: string): string {
  return value.replace(/_/g, " ").replace(/\b\w/g, (char) => char.toUpperCase());
}

export default function ObjectResolutionPanel({ analysis }: Props) {
  if (!analysis) return null;
  const { summary } = analysis;
  return (
    <section className="ua-panel or-panel" aria-labelledby="or-title">
      <div className="or-heading">
        <div>
          <h2 id="or-title">Network objects and policy selectors</h2>
          <p>Limited, evidence-based IPv4 object expansion. Resolved selectors are advisory, not proof of reachability.</p>
        </div>
        <span className="or-label">{analysis.status === "not_assessed" ? "Not assessed" : analysis.status === "limited" ? "Limited coverage" : "Reviewed subset"}</span>
      </div>
      <div className="or-metrics">
        <div><strong>{summary.definitions_resolved}</strong><span>Objects resolved</span></div>
        <div><strong>{summary.definitions_unresolved}</strong><span>Objects unresolved</span></div>
        <div><strong>{summary.rules_with_resolved_selectors}</strong><span>Rules parsed</span></div>
        <div><strong>{summary.candidate_pairs}</strong><span>Selector correlations</span></div>
      </div>
      {summary.rules_not_resolved > 0 && (
        <p className="or-note">{summary.rules_not_resolved} rule(s) could not be fully resolved in the supported subset. Unresolved rules are excluded from object-based comparisons.</p>
      )}
      {analysis.pairs.length ? (
        <ol className="or-list">
          {analysis.pairs.map((pair) => (
            <li className="or-result" key={pair.correlation_id}>
              <div className="or-result-head">
                <strong>{pair.correlation_id} · {label(pair.kind)}</strong>
                <span>{label(pair.order_status)}</span>
              </div>
              <p>{pair.explanation}</p>
              <p><strong>Review:</strong> {pair.recommendation}</p>
              <small>Source lines {pair.evidence.related_line_number} and {pair.evidence.line_number}
                {pair.resolved_object_references.length ? ` · Objects: ${pair.resolved_object_references.join(", ")}` : ""}</small>
            </li>
          ))}
        </ol>
      ) : (
        <p>No additional selector correlations were established by supported named-object expansion. This does not establish that the configuration is free of conflicts.</p>
      )}
      {analysis.objects.length > 0 && (
        <details>
          <summary>Object resolution inventory ({analysis.objects.length} shown)</summary>
          <div className="or-inventory">
            {analysis.objects.map((object, index) => (
              <div key={`${object.kind}-${object.name}-${index}`}>
                <strong>{object.name}</strong>
                <span>{object.status} · line {object.line_number} · {object.value ?? object.reason}</span>
              </div>
            ))}
          </div>
        </details>
      )}
      <details>
        <summary>Assessment coverage and limitations</summary>
        <ul>{analysis.limitations.map((item, index) => <li key={index}>{item}</li>)}</ul>
      </details>
      {summary.truncated && <p className="or-note">Processing limits were reached; the review is incomplete.</p>}
      <p className="or-disclaimer">Object-based correlations do not change existing findings, severity ratings, or provisional scores.</p>
    </section>
  );
}
