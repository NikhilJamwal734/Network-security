import type { CorrelationAssurance } from "../api/universal";
import "./CorrelationAssurancePanel.css";

type Props = { assurance?: CorrelationAssurance };

const labels: Record<string, string> = {
  ordering_contradicted: "Order contradicts source order",
  order_supported_candidate: "Explicit order is consistent",
  order_unverified: "Rule order not verified",
  object_resolution_required: "Object resolution required",
  ids_options_unverified: "IDS rule options not compared",
  evidence_unavailable: "Source evidence unavailable",
};

export default function CorrelationAssurancePanel({ assurance }: Props) {
  if (!assurance) return null;
  const { summary } = assurance;
  return (
    <section className="ua-panel ca-panel" aria-labelledby="ca-heading">
      <div className="ca-heading">
        <div>
          <h2 id="ca-heading">Correlation evidence and ordering review</h2>
          <p>Checks whether candidate references point to supported source lines and whether ASA explicit ACL sequence agrees with the proposed order.</p>
        </div>
        <span className="ca-badge">{assurance.status === "limited" ? "Limited review" : "Advisory review"}</span>
      </div>
      <div className="ca-metrics">
        <div><strong>{summary.pairs_reviewed}</strong><span>Pairs reviewed</span></div>
        <div><strong>{summary.evidence_present}</strong><span>Source references located</span></div>
        <div><strong>{summary.ordering_contradictions}</strong><span>ASA order contradictions</span></div>
      </div>
      {summary.ordering_contradictions > 0 && (
        <p className="ca-warning">Some ASA correlations assume source-file ordering that conflicts with explicit ACL sequence numbers. Do not treat those candidates as confirmed shadowing.</p>
      )}
      {assurance.items.length ? (
        <ol className="ca-list">
          {assurance.items.map((item, index) => (
            <li className="ca-item" key={`${item.correlation_id}-${index}`}>
              <div className="ca-item-title"><strong>{item.correlation_id} — {labels[item.status] ?? item.status}</strong>
                <span>{item.evidence_present ? "Source lines located" : "Evidence not confirmed"}</span>
              </div>
              <p>{item.explanation}</p>
              <p><strong>Next check:</strong> {item.next_action}</p>
              <small>Referenced source lines: {item.related_line_number ?? "?"}, {item.line_number ?? "?"}</small>
            </li>
          ))}
        </ol>
      ) : <p>No correlation candidates required additional evidence review in the supported subset.</p>}
      {summary.truncated && <p className="ca-warning">Processing limits were reached. Some source references or rules may be unassessed.</p>}
      <details>
        <summary>What this review does not establish</summary>
        <ul>{assurance.limitations.map((text, index) => <li key={index}>{text}</li>)}</ul>
      </details>
      <p className="ca-disclaimer">Source evidence and ordering checks are advisory and never modify the original security findings or scores.</p>
    </section>
  );
}
