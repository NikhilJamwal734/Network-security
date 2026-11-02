import type { FirewallReport } from "../types/report";

interface SecurityScoreProps {
  score: FirewallReport["summary"]["security_score"];
  riskLevel: FirewallReport["summary"]["risk_level"];
}

export default function SecurityScore({
  score,
  riskLevel,
}: SecurityScoreProps) {
  const radius = 78;
  const circumference = 2 * Math.PI * radius;
  const safeScore = Math.max(0, Math.min(100, score));
  const offset = circumference - (safeScore / 100) * circumference;

  return (
    <section className="dashboard-card security-score-card">
      <div className="card-header">
        <div>
          <span className="eyebrow">SECURITY POSTURE</span>
          <h2>Security Score</h2>
        </div>

        <span className={`risk-badge risk-${riskLevel.toLowerCase()}`}>
          {riskLevel}
        </span>
      </div>

      <div className="score-content">
        <div className="score-ring">
          <svg viewBox="0 0 200 200" className="score-svg">
            <circle
              className="score-track"
              cx="100"
              cy="100"
              r={radius}
            />

            <circle
              className="score-progress"
              cx="100"
              cy="100"
              r={radius}
              strokeDasharray={circumference}
              strokeDashoffset={offset}
            />
          </svg>

          <div className="score-value">
            <strong>{score}</strong>
            <span>/ 100</span>
          </div>
        </div>

        <div className="score-description">
          <div className="score-status">
            <span className="status-dot" />
            <span>Current assessment</span>
          </div>

          <p>
            Firewall configuration security score based on the findings
            detected in the analyzed configuration.
          </p>
        </div>
      </div>
    </section>
  );
}