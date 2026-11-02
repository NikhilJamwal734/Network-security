import type { IdsDeepReview } from "../api/universal";
import "./IdsDeepSnippet.css";

/** Deliberately snippet-only: never render full evidence, source text or recommendations. */
export default function IdsDeepSnippet({ review }: { review?: IdsDeepReview }) {
  if (!review || review.status === "not_applicable") return null;
  const s = review.summary;
  return (
    <section className="ua-panel ids109-panel" aria-labelledby="ids109-title">
      <div className="ids109-heading">
        <h2 id="ids109-title">Snort / Suricata deep review</h2>
        <span>{review.status === "limited" ? "Limited" : "Reviewed subset"}</span>
      </div>
      <div className="ids109-stats">
        <div><strong>{s.rules_inspected}</strong><span>Inline rules checked</span></div>
        <div><strong>{s.duplicate_rule_ids}</strong><span>Repeated IDs</span></div>
        <div><strong>{s.external_references}</strong><span>External references</span></div>
        <div><strong>{s.evidence_items}</strong><span>Evidence items</span></div>
      </div>
      {review.evidence.length > 0 && (
        <ul className="ids109-snippets">
          {review.evidence.slice(0, 2).map((item) => (
            <li key={item.reference}><strong>{item.reference}</strong> · {item.kind.replace(/_/g, " ")}</li>
          ))}
        </ul>
      )}
      {s.incomplete && <p className="ids109-note">Partial coverage — no absence conclusion supported.</p>}
      <p className="ids109-note">Complete source evidence and recommendations: PDF report only.</p>
    </section>
  );
}
