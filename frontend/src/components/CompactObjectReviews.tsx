import type { ObjectAssurance, ObjectResolution } from "../api/universal";
import "./ServiceIPv6Snippet.css";

/** Summary-only cards. The PDF report retains evidence and recommendations. */
export function CompactObjectResolution({ analysis }: { analysis?: ObjectResolution }) {
  if (!analysis) return null;
  const s = analysis.summary;
  return (
    <section className="ua-panel sg6-panel" aria-labelledby="or-compact-title">
      <h2 id="or-compact-title">Network objects and policy selectors</h2>
      <div className="sg6-stats">
        <div><strong>{s.definitions_resolved}</strong><span>Resolved</span></div>
        <div><strong>{s.definitions_unresolved}</strong><span>Unresolved</span></div>
        <div><strong>{s.rules_with_resolved_selectors}</strong><span>Rules analyzed</span></div>
        <div><strong>{s.candidate_pairs}</strong><span>Candidate pairs</span></div>
      </div>
      {analysis.pairs.length > 0 && (
        <p className="sg6-note">Preview: {analysis.pairs[0].correlation_id} · {analysis.pairs[0].kind.replace(/_/g, " ")}</p>
      )}
      <p className="sg6-pdf-note">Object definitions, evidence, relationships, and limitations are detailed in the PDF.</p>
    </section>
  );
}

export function CompactObjectAssurance({ review }: { review?: ObjectAssurance }) {
  if (!review) return null;
  const s = review.summary;
  return (
    <section className="ua-panel sg6-panel" aria-labelledby="oa-compact-title">
      <h2 id="oa-compact-title">Object reference integrity</h2>
      {review.status === "not_assessed" ? (
        <p className="sg6-note">Not assessed for this platform.</p>
      ) : (
        <div className="sg6-stats">
          <div><strong>{s.references_checked}</strong><span>References checked</span></div>
          <div><strong>{s.missing_in_upload}</strong><span>Missing in upload</span></div>
          <div><strong>{s.cycles}</strong><span>Group cycles</span></div>
          <div><strong>{s.repeated_definitions}</strong><span>Repeated definitions</span></div>
        </div>
      )}
      {review.observations.length > 0 && (
        <p className="sg6-note">Preview: {review.observations[0].reference} · {review.observations[0].kind.replace(/_/g, " ")}</p>
      )}
      {s.incomplete && <p className="sg6-note">Incomplete analysis coverage.</p>}
      <p className="sg6-pdf-note">The PDF contains all available source evidence, explanations, and recommendations.</p>
    </section>
  );
}
