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
      <div data-dashboard-snippet="rule-correlation">
        <p className="ua-hint">
          {summary.eligible_rules} rules compared · {summary.rules_not_correlated} outside comparison scope.
        </p>
        {pairs.length ? (
          <ol className="rule-correlation-list">
            {pairs.slice(0, 2).map((item) => (
              <li key={item.correlation_id} className="rule-correlation-item">
                <div className="rule-correlation-entry-title">
                  <strong>{item.correlation_id} · {item.title}</strong>
                  <span className="rule-correlation-kind">{kindLabel[item.kind] ?? item.kind}</span>
                </div>
                <small>Source lines {item.evidence.related_line_number} and {item.evidence.line_number}</small>
              </li>
            ))}
          </ol>
        ) : <p className="rule-correlation-empty">No candidate correlations within the supported rule subset.</p>}
        {pairs.length > 2 && <p className="ua-hint">+{pairs.length - 2} more candidate pairs in the PDF.</p>}
        {summary.truncated && <p className="rule-correlation-caution">Processing limit reached; the review is incomplete.</p>}
        <p className="ua-hint">See the PDF for candidate relationships, supporting evidence, recommendations and limitations.</p>
      </div>
    </section>
  );
}
