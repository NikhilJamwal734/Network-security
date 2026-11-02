import type { RuleCorrelation } from "../api/universal";
import "./RuleCorrelationPanel.css";

type Props = { review?: RuleCorrelation };

const kindLabel: Record<string, string> = {
  redundant_candidate: "Potential redundancy",
  shadowed_candidate: "Potential shadowing",
  overlap_candidate: "Overlapping selectors",
  action_conflict_candidate: "Opposite-action overlap",
  header_overlap: "Shared IDS header",
  action_interaction_candidate: "IDS action interaction",
};

export default function RuleCorrelationPanel({ review }: Props) {
  if (!review) return null;
  const { summary, pairs } = review;
  return (
    <section className="ua-panel rule-correlation-panel" aria-labelledby="rule-correlation-heading">
      <div className="rule-correlation-title-row">
        <div>
          <h2 id="rule-correlation-heading">Rule correlation and conflict review</h2>
          <p>Evidence-based, advisory comparison of supported configuration rules.</p>
        </div>
        <span className="rule-correlation-total">{summary.candidate_pairs} candidate {summary.candidate_pairs === 1 ? "pair" : "pairs"}</span>
      </div>
      <div className="rule-correlation-metrics">
        <div><strong>{summary.eligible_rules}</strong><span>Rules compared</span></div>
        <div><strong>{summary.rules_not_correlated}</strong><span>Not correlated</span></div>
        <div><strong>{summary.truncated ? "Limited" : "Subset"}</strong><span>Analysis coverage</span></div>
      </div>
      {pairs.length ? (
        <ol className="rule-correlation-list">
          {pairs.map((item) => (
            <li key={item.correlation_id} className="rule-correlation-item">
              <div className="rule-correlation-entry-title">
                <strong>{item.correlation_id} · {item.title}</strong>
                <span className="rule-correlation-kind">{kindLabel[item.kind] ?? item.kind}</span>
              </div>
              <p>{item.detail}</p>
              <p><strong>Review action:</strong> {item.recommendation}</p>
              <small>Source lines {item.evidence.related_line_number} and {item.evidence.line_number}
                {item.evidence.related_rule_id ? ` · Reference: ${item.evidence.related_rule_id}` : ""}
                {item.evidence.rule_id ? ` → ${item.evidence.rule_id}` : ""}
                {` · ${item.confidence} confidence`}</small>
            </li>
          ))}
        </ol>
      ) : (
        <p className="rule-correlation-empty">No candidate correlations were found within the supported rule subset. This does not prove rules are free of conflicts or that deployment is secure.</p>
      )}
      {summary.truncated && <p className="rule-correlation-caution">The correlation review reached a processing limit. Results are incomplete.</p>}
      <details>
        <summary>Correlation scope and limitations</summary>
        <ul>{review.limitations.map((entry, index) => <li key={index}>{entry}</li>)}</ul>
      </details>
      <p className="rule-correlation-disclaimer">These candidates are not included in the original findings, severity totals or review score.</p>
    </section>
  );
}
