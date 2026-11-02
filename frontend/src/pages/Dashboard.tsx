import SecurityScore from "../components/SecurityScore";
import SummaryCard from "../components/SummaryCard";
import FindingSummary from "../components/FindingSummary";
import ConfigurationSummary from "../components/ConfigurationSummary";
import SeverityChart from "../components/SeverityChart";
import FirewallInfo from "../components/FirewallInfo";
import FirewallUpload from "../components/FirewallUpload";

import { useAnalysis } from "../context/AnalysisContext";

import "./Dashboard.css";
import "./DashboardHeadingHighlights.css";
import "./DashboardMetrics.css";

function Dashboard() {
  const { analysis, loading, error } = useAnalysis();
  const report = analysis;

  return (
    <div className="dashboard">
      {/* PAGE HEADER */}
      <section className="page-header dashboard-header">
        <div>
          <div className="breadcrumb">Security Analysis / Dashboard</div>
          <h1>Firewall Security Dashboard</h1>
          <p>
            {report ? (
              <>
                Security posture and configuration analysis for{" "}
                <strong>{report.hostname}</strong>.
              </>
            ) : (
              "Upload a Cisco ASA configuration to begin security analysis."
            )}
          </p>
        </div>

        {report && (
          <div className="report-badge">
            <span className="status-dot" />
            Analysis Complete
          </div>
        )}
      </section>

      {/* FIREWALL CONFIGURATION UPLOAD */}
      <section className="panel">
        <FirewallUpload />
      </section>

      {/* LOADING STATE */}
      {loading && (
        <section className="dashboard-state" aria-live="polite">
          <div className="loading-spinner" />
          <h2>Analyzing firewall configuration...</h2>
          <p>Parsing configuration and running security checks.</p>
        </section>
      )}

      {/* ERROR STATE */}
      {error && !report && !loading && (
        <section className="dashboard-state error-state" role="alert">
          <div className="state-icon">!</div>
          <h2>Unable to analyze configuration</h2>
          <p>{error}</p>
          <p className="state-help">
            Check that the FastAPI backend is running at
            http://127.0.0.1:8000.
          </p>
        </section>
      )}

      {/* EMPTY STATE */}
      {!report && !loading && !error && (
        <section className="dashboard-state">
          <h2>No firewall analysis available</h2>
          <p>
            Select a .conf, .cfg, or .txt configuration file above and click
            Analyze Configuration.
          </p>
          <p>
            The analyzer will evaluate firewall rules, NAT policies, network
            objects, service objects, and routing configuration.
          </p>
        </section>
      )}

      {/* ANALYSIS RESULTS */}
      {report && (
        <>
          {/* SECURITY SCORE AND FINDING SUMMARY */}
          <section className="dashboard-top-grid">
            <div className="panel score-panel">
              <SecurityScore
                score={report.summary.security_score}
                riskLevel={report.summary.risk_level}
              />
            </div>

            <div className="panel">
              <FindingSummary
                critical={report.summary.critical_findings}
                high={report.summary.high_findings}
                medium={report.summary.medium_findings}
                low={report.summary.low_findings}
                total={report.summary.total_findings}
              />
            </div>
          </section>

          {/* CONFIGURATION STATISTICS */}
          <section className="fa-metrics-grid" aria-label="Firewall configuration statistics">
            <SummaryCard
              label="Firewall Rules"
              value={report.summary.total_rules}
            />
            <SummaryCard
              label="Network Objects"
              value={report.summary.total_network_objects}
            />
            <SummaryCard
              label="Service Objects"
              value={report.summary.total_service_objects}
            />
            <SummaryCard
              label="NAT Rules"
              value={report.summary.total_nat_rules}
            />
            <SummaryCard
              label="Routes"
              value={report.summary.total_routes}
            />
          </section>

          {/* SEVERITY CHART AND FIREWALL INFORMATION */}
          <section className="dashboard-grid">
            <div className="panel">
              <div className="panel-header">
                <div>
                  <h2>Severity Distribution</h2>
                  <p>Findings grouped by security severity.</p>
                </div>
              </div>

              <SeverityChart
                critical={report.summary.critical_findings}
                high={report.summary.high_findings}
                medium={report.summary.medium_findings}
                low={report.summary.low_findings}
              />
            </div>

            <div className="panel">
              <FirewallInfo report={report} />
            </div>
          </section>

          {/* SECURITY FINDINGS */}
          {/* CONFIGURATION SUMMARY */}
          <section className="panel">
            <ConfigurationSummary summary={report.summary} />
          </section>

          {/* PARSER WARNINGS */}
          {report.warnings.length > 0 && (
            <section className="panel">
              <div className="panel-header">
                <div>
                  <h2>Configuration Warnings</h2>
                  <p>
                    Issues encountered while parsing the firewall configuration.
                  </p>
                </div>
              </div>
              <ul>
                {report.warnings.map((warning, index) => (
                  <li key={`${index}-${warning}`}>{warning}</li>
                ))}
              </ul>
            </section>
          )}
        </>
      )}
    </div>
  );
}

export default Dashboard;
