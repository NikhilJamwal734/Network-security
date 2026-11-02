import SecurityScore from "../components/SecurityScore";
import SummaryCard from "../components/SummaryCard";
import FindingSummary from "../components/FindingSummary";
import ConfigurationSummary from "../components/ConfigurationSummary";
import SeverityChart from "../components/SeverityChart";
import FindingsOverview from "../components/FindingsOverview";
import FirewallInfo from "../components/FirewallInfo";
import type { FirewallReport } from "../types/report";
import "./Dashboard.css";

function Dashboard({report, onViewFindings}: {report: FirewallReport; onViewFindings: () => void}) {
  const { summary } = report;

  return (
    <div className="dashboard">
      <section className="page-header dashboard-header">
        <div>
          <div className="breadcrumb">
            Security Analysis / Dashboard
          </div>

          <h1>Firewall Security Dashboard</h1>

          <p>
            Security posture and configuration analysis for{" "}
            <strong>{report.hostname}</strong>.
          </p>
        </div>

        <div className="report-badge">
          <span className="status-dot" />
          {report.assessment_status === "complete" ? "Supported policy reviewed" : "Partial assessment"}
        </div>
      </section>

      <section className="dashboard-top-grid">
        <div className="panel score-panel">
          <SecurityScore
            score={summary.security_score}
            riskLevel={summary.risk_level}
          />
        </div>

        <div className="panel">
          <FindingSummary
            critical={summary.critical_findings}
            high={summary.high_findings}
            medium={summary.medium_findings}
            low={summary.low_findings}
            total={summary.total_findings}
          />
        </div>
      </section>

      <section className="summary-cards">
        <SummaryCard
          label="Firewall Rules"
          value={summary.total_rules}
          icon="≡"
        />

        <SummaryCard
          label="Network Objects"
          value={summary.total_network_objects}
          icon="◈"
        />

        <SummaryCard
          label="Service Objects"
          value={summary.total_service_objects}
          icon="◇"
        />

        <SummaryCard
          label="NAT Rules"
          value={summary.total_nat_rules}
          icon="↔"
        />

        <SummaryCard
          label="Routes"
          value={summary.total_routes}
          icon="⌁"
        />
      </section>

      <section className="dashboard-grid">
        <div className="panel">
          <div className="panel-header">
            <div>
              <h2>Severity Distribution</h2>
              <p>Findings grouped by security severity.</p>
            </div>
          </div>

          <SeverityChart
            critical={summary.critical_findings}
            high={summary.high_findings}
            medium={summary.medium_findings}
            low={summary.low_findings}
          />
        </div>

        <div className="panel">
          <FirewallInfo report={report} />
        </div>
      </section>

      <section className="panel findings-panel">
        <FindingsOverview findings={report.findings} />
        <button className="action" onClick={onViewFindings}>View all {report.findings.length} findings</button>
      </section>

      <section className="panel">
        <ConfigurationSummary summary={summary} />
      </section>
    </div>
  );
}

export default Dashboard;