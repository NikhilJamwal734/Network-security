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
      <div data-dashboard-snippet="correlation-assurance">
        <div className="ca-metrics">
          <div><strong>{summary.pairs_reviewed}</strong><span>Pairs reviewed</span></div>
          <div><strong>{summary.evidence_present}</strong><span>Source references located</span></div>
          <div><strong>{summary.ordering_contradictions}</strong><span>Ordering contradictions</span></div>
        </div>
        {summary.ordering_contradictions > 0 && (
          <p className="ca-warning">Some Cisco ASA rule-order assumptions contradict explicit ACL sequence evidence.</p>
        )}
        {assurance.items.length > 0 && (
          <ol className="ca-list">
            {assurance.items.slice(0, 2).map((item, index) => (
              <li className="ca-item" key={`${item.correlation_id}-${index}`}>
                <div className="ca-item-title">
                  <strong>{item.correlation_id} — {labels[item.status] ?? item.status}</strong>
                </div>
                <small>Referenced lines: {item.related_line_number ?? "?"}, {item.line_number ?? "?"}</small>
              </li>
            ))}
          </ol>
        )}
        {assurance.items.length > 2 && <p className="ua-hint">+{assurance.items.length - 2} more evidence checks in the PDF.</p>}
        {summary.truncated && <p className="ca-warning">Processing limit reached; review is incomplete.</p>}
        <p className="ua-hint">See the PDF for ordering explanations, next checks, and verification limitations.</p>
      </div>
    </section>
  );
}
