import type { PipelineValidationReview } from "../api/universal";
import "./PipelineValidationSnippet.css";

/** Only counters and two stage labels; technical evidence stays in the PDF. */
export default function PipelineValidationSnippet({ review }: { review?: PipelineValidationReview }) {
  if (!review) return null;
  const s = review.summary;
  const notes = review.stages.filter((stage) => stage.result !== "pass");
  return (
    <section className="ua-panel e2e114-panel" aria-labelledby="e2e114-title">
      <div className="e2e114-heading">
        <h2 id="e2e114-title">End-to-end pipeline checks</h2>
        <span>{review.status === "blocked" ? "Review blockers" : review.status === "limited" ? "Limited contract" : "Server checks complete"}</span>
      </div>
      <div className="e2e114-stats">
        <div><strong>{s.checks}</strong><span>Checks</span></div>
        <div><strong>{s.passed}</strong><span>Passed</span></div>
        <div><strong>{s.warnings}</strong><span>Warnings</span></div>
        <div><strong>{s.blockers}</strong><span>Blockers</span></div>
      </div>
      {notes.length > 0 && <ul className="e2e114-snippets">
        {notes.slice(0, 2).map((stage) => (
          <li key={stage.reference}>{stage.reference} · {stage.stage.replace(/_/g, " ")}</li>
        ))}
      </ul>}
      <p className="e2e114-note">Server-side contract checks only. Browser export requires separate verification; details are in the PDF.</p>
    </section>
  );
}
