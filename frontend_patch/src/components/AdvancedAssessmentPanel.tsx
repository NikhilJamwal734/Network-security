/** API-009.8 provisional, cross-platform assessment presentation.
 * Shows only allowlisted metadata returned by the trusted backend; React
 * automatically escapes strings (no HTML injection from uploaded files).
 */
import type { AdvancedAssessment } from "../api/universal";
import "./AdvancedAssessmentPanel.css";

interface Props {
  assessment?: AdvancedAssessment;
}

function label(value: string): string {
  return value.replace(/_/g, " ").replace(/\b\w/g, (char) => char.toUpperCase());
}

export default function AdvancedAssessmentPanel({ assessment }: Props) {
  if (!assessment) return null;
  const { review_score: score, observations, coverage_review: coverage } = assessment;
  return (
    <section className="ua-panel advanced-assessment" aria-labelledby="advanced-assessment-heading">
      <div className="advanced-assessment-heading">
        <div>
          <p className="ua-eyebrow">API-009.8 / FOUR-PLATFORM ASSESSMENT</p>
          <h2 id="advanced-assessment-heading">Configuration review</h2>
          <p>Evidence from the uploaded text only. No rule-file references or device commands are executed.</p>
        </div>
        <span className="advanced-assessment-tag">Provisional only</span>
      </div>

      <div className="advanced-assessment-metrics">
        <div className="advanced-assessment-score">
          <span>Provisional review score</span>
          <strong>{score.value}<small> / 100</small></strong>
          <small>Maximum {score.maximum}/100 while coverage is incomplete</small>
        </div>
        <div className="advanced-assessment-coverage">
          <span>Assessment coverage</span>
          <strong>{coverage.assessed_domain_count} reviewed</strong>
          <small>{coverage.unassessed_domain_count} domains not assessed</small>
        </div>
        <div className="advanced-assessment-priority">
          <span>Finding priority</span>
          <strong>{label(score.priority)}</strong>
          <small>Based on findings, not a runtime risk rating</small>
        </div>
      </div>

      <p className="advanced-assessment-caution" role="note">{score.interpretation}</p>

      <h3>Visible configuration evidence</h3>
      <div className="advanced-assessment-observations">
        {observations.map((check) => (
          <article className="advanced-assessment-observation" key={check.code}>
            <div className="advanced-assessment-observation-head">
              <strong>{check.title}</strong>
              <span className={`advanced-assessment-status advanced-assessment-status-${check.status}`}>
                {label(check.status)}
              </span>
            </div>
            <p>{check.detail}</p>
            <small>Source: {check.evidence.source_field}</small>
          </article>
        ))}
      </div>

      <h3>Not assessed</h3>
      <p className="advanced-assessment-unassessed">
        {coverage.unassessed_domains.length
          ? coverage.unassessed_domains.map(label).join(" · ")
          : "Only the explicitly implemented checks were reviewed; runtime behavior remains unverified."}
      </p>
    </section>
  );
}
