import type { AnalysisResponse } from "../services/firewallApi";

interface FirewallInfoProps {
  report: AnalysisResponse;
}

export default function FirewallInfo({
  report,
}: FirewallInfoProps) {
  return (
    <section className="dashboard-card firewall-info-card">
      <div className="card-header">
        <div>
          <span className="eyebrow">FIREWALL</span>
          <h2>Firewall Information</h2>
        </div>

        <span className="vendor-badge">{report.vendor}</span>
      </div>

      <div className="firewall-info-grid">
        <div className="firewall-info-item">
          <span>Vendor</span>
          <strong>{report.vendor}</strong>
        </div>

        <div className="firewall-info-item">
          <span>Hostname</span>
          <strong>{report.hostname}</strong>
        </div>

        <div className="firewall-info-item">
          <span>Configuration File</span>
          <strong>{report.source?.configuration_file ?? "Uploaded configuration"}</strong>
        </div>

        <div className="firewall-info-item">
          <span>Risk Level</span>
          <strong
            className={`risk-text risk-${report.summary.risk_level.toLowerCase()}`}
          >
            {report.summary.risk_level}
          </strong>
        </div>
      </div>
    </section>
  );
}