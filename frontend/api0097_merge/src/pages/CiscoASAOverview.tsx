/**
 * Cisco ASA inventory cards inside the unified dashboard.
 * These legacy components require the Cisco ASA AnalysisContext report;
 * the normalized report deliberately does not pretend to contain them.
 */
import SummaryCard from "../components/SummaryCard";
import SecurityScore from "../components/SecurityScore";
import SeverityChart from "../components/SeverityChart";
import ConfigurationSummary from "../components/ConfigurationSummary";
import FirewallInfo from "../components/FirewallInfo";
import { useAnalysis } from "../context/AnalysisContext";
import "./Dashboard.css";

export default function CiscoASAOverview() {
  const { analysis } = useAnalysis();
  if (!analysis) return null;

  const summary = analysis.summary;

  return (
    <div className="dashboard ua-asa-overview">
      <div className="ua-section-heading">
        <div>
          <h2>Cisco ASA configuration overview</h2>
          <p>Firewall-specific inventory from the legacy Cisco ASA parser.</p>
        </div>
      </div>
      <div className="ua-asa-visual-grid">
        <div className="ua-asa-subpanel ua-asa-score">
          <SecurityScore score={summary.security_score} riskLevel={summary.risk_level} />
        </div>
        <div className="ua-asa-subpanel">
          <h3>Severity chart</h3>
          <SeverityChart
            critical={summary.critical_findings}
            high={summary.high_findings}
            medium={summary.medium_findings}
            low={summary.low_findings}
          />
        </div>
      </div>
      <div className="summary-cards">
        <SummaryCard label="Firewall Rules" value={summary.total_rules} icon="≡" />
        <SummaryCard label="Network Objects" value={summary.total_network_objects} icon="◈" />
        <SummaryCard label="Service Objects" value={summary.total_service_objects} icon="◇" />
        <SummaryCard label="NAT Rules" value={summary.total_nat_rules} icon="↔" />
        <SummaryCard label="Routes" value={summary.total_routes} icon="⌁" />
      </div>
      <div className="ua-asa-detail-grid">
        <div className="ua-asa-subpanel"><FirewallInfo report={analysis} /></div>
        <div className="ua-asa-subpanel"><ConfigurationSummary summary={summary} /></div>
      </div>
      <p className="ua-hint">Detailed Cisco ASA rules, objects, NAT, routes, configuration and legacy PDF exports are available in the sidebar.</p>
    </div>
  );
}
