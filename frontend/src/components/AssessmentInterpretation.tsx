/** Short, user-facing explanations shared by all supported platforms.
 * This is presentation-only; all scores and severities come from the API.
 */
import "./AssessmentInterpretation.css";

interface ReviewScoreExplanationProps {
  maximum: number;
  capped: boolean;
}

export function ReviewScoreExplanation({ maximum, capped }: ReviewScoreExplanationProps) {
  return (
    <div className="assessment-scale-help" role="note">
      <p>Summarizes detected findings in the configuration checks performed, with limits for missing assessment coverage.</p>
      <p><strong>Scale: 0–100.</strong> Higher means fewer detected concerns.
        {capped ? ` Important areas were not assessed, so this review score is capped at ${maximum}/100.` : " This is not a guarantee of security."}
      </p>
    </div>
  );
}

export function SeverityExplanation() {
  return (
    <div className="assessment-scale-help" role="note">
      <p>Shows the number of findings at each seriousness level; it is not another numeric security score.</p>
      <p><strong>Scale:</strong> Info → Low → Medium → High → Critical (increasing priority). Unknown means not classified.</p>
    </div>
  );
}
