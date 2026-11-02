import type { Finding } from "../types/report";

interface FindingsOverviewProps {
  findings: Finding[];
}

const severityOrder: Record<Finding["severity"], number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
};

export default function FindingsOverview({
  findings,
}: FindingsOverviewProps) {
  const priorityFindings = [...findings]
    .sort((a, b) => {
      const severityDifference =
        severityOrder[a.severity] - severityOrder[b.severity];

      if (severityDifference !== 0) {
        return severityDifference;
      }

      return (a.line_number ?? 0) - (b.line_number ?? 0);
    })
    .slice(0, 8);

  return (
    <section className="dashboard-card findings-card">
      <div className="card-header">
        <div>
          <span className="eyebrow">SECURITY FINDINGS</span>
          <h2>Priority Findings</h2>
        </div>

        <span className="chart-total">
          Showing {priorityFindings.length}
        </span>
      </div>

      <div className="findings-list">
        {priorityFindings.map((finding, index) => (
          <div
            className="finding-row"
            key={`${finding.code}-${finding.rule_id}-${finding.line_number}-${index}`}
          >
            <div className="finding-severity">
              <span
                className={`severity-badge severity-${finding.severity.toLowerCase()}`}
              >
                {finding.severity}
              </span>
            </div>

            <div className="finding-main">
              <div className="finding-title-row">
                <span className="finding-code">{finding.code}</span>
                <h3>{finding.title}</h3>
              </div>

              <div className="finding-meta">
                <span>
                  Rule ID:{" "}
                  <strong>
                    {finding.rule_id !== null
                      ? finding.rule_id
                      : "N/A"}
                  </strong>
                </span>

                <span>
                  Line: <strong>{finding.line_number}</strong>
                </span>
              </div>
            </div>
          </div>
        ))}

        {priorityFindings.length === 0 && (
          <div className="empty-state">
            No findings were reported.
          </div>
        )}
      </div>
    </section>
  );
}