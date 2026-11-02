/**
 * Cisco ASA inventory cards inside the unified dashboard.
 * These legacy components require the Cisco ASA AnalysisContext report;
 * the normalized report deliberately does not pretend to contain them.
 */
import SecurityScore from "../components/SecurityScore";
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
      <div className="ua-asa-visual-grid ua-asa-score-only">
        <div className="ua-asa-subpanel ua-asa-score">
          <SecurityScore score={summary.security_score} riskLevel={summary.risk_level} />
        </div>
      </div>
      {/* One responsive inventory summary (no duplicate icon cards). */}
      <section className="ua-asa-inventory ua-asa-subpanel" aria-label="Configuration summary">
        <ConfigurationSummary summary={summary} />
      </section>
      <section className="ua-asa-info ua-asa-subpanel" aria-label="Firewall information">
        <FirewallInfo report={analysis} />
      </section>
      <p className="ua-hint">Detailed Cisco ASA rules, objects, NAT, routes, configuration and legacy PDF exports are available in the sidebar.</p>
    </div>
  );
}
