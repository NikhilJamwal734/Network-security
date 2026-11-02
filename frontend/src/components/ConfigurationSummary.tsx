/**
 * Cisco ASA configuration inventory for the unified dashboard.
 * Presentation only: uses the existing summary values without altering analysis.
 */
import "./ConfigurationSummary.css";

type ConfigurationCounts = {
  total_rules: number;
  total_network_objects: number;
  total_service_objects: number;
  total_nat_rules: number;
  total_routes: number;
};

type ConfigurationSummaryProps = {
  summary: ConfigurationCounts;
};

export default function ConfigurationSummary({ summary }: ConfigurationSummaryProps) {
  const metrics = [
    { label: "Firewall Rules", value: summary.total_rules, accent: "rules" },
    { label: "Network Objects", value: summary.total_network_objects, accent: "network" },
    { label: "Service Objects", value: summary.total_service_objects, accent: "services" },
    { label: "NAT Rules", value: summary.total_nat_rules, accent: "nat" },
    { label: "Routes", value: summary.total_routes, accent: "routes" },
  ] as const;

  return (
    <section className="ucs-summary" aria-labelledby="ucs-title">
      <header className="ucs-header">
        <div>
          <p className="ucs-eyebrow">DEVICE INVENTORY</p>
          <h3 id="ucs-title">Configuration Summary</h3>
        </div>
        <p className="ucs-subtitle">Parsed Cisco ASA configuration</p>
      </header>
      <div className="ucs-grid" aria-label="Configuration object counts">
        {metrics.map(({ label, value, accent }) => (
          <div className={`ucs-card ucs-${accent}`} key={label}>
            <span className="ucs-label">{label}</span>
            <strong className="ucs-value">{value}</strong>
          </div>
        ))}
      </div>
    </section>
  );
}
