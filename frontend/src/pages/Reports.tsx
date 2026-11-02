
import { useAnalysis } from "../context/AnalysisContext";

import PdfReportDownload from "../components/PdfReportDownload";

import "./Reports.css";

type StatItem = {
  label: string;
  value: string | number;
  className?: string;
};

type InventoryItem = {
  label: string;
  count: number;
};

function Reports() {
  const { analysis, filename } = useAnalysis();

  if (!analysis) {
    return (
      <div className="reports-page">
        <section className="page-header">
          <div>
            <div className="breadcrumb">
              Security Analysis / Reports
            </div>

            <h1>Security Reports</h1>

            <p>
              Generate downloadable reports from your
              firewall security analysis.
            </p>
          </div>
        </section>

        <section className="panel reports-empty">
          <div className="reports-empty-icon">
            ▤
          </div>

          <h2>No analysis available</h2>

          <p>
            Open the Dashboard and analyze a Cisco ASA
            configuration before generating reports.
          </p>

          <p className="reports-empty-hint">
            Once your analysis is complete, JSON and PDF
            report downloads will become available here.
          </p>
        </section>
      </div>
    );
  }

  const summary = analysis.summary;
  const configuration = analysis.configuration;

  const overview: StatItem[] = [
    {
      label: "Security Score",
      value: `${summary.security_score}/100`,
      className: "reports-stat-score",
    },
    {
      label: "Risk Level",
      value: summary.risk_level,
      className: `reports-stat-risk-${String(
        summary.risk_level
      ).toLowerCase()}`,
    },
    {
      label: "Total Findings",
      value: summary.total_findings,
    },
  ];

  const severities = [
    {
      label: "Critical",
      count: summary.critical_findings,
      className: "critical",
    },
    {
      label: "High",
      count: summary.high_findings,
      className: "high",
    },
    {
      label: "Medium",
      count: summary.medium_findings,
      className: "medium",
    },
    {
      label: "Low",
      count: summary.low_findings,
      className: "low",
    },
  ];

  const inventory: InventoryItem[] = [
    {
      label: "Firewall Rules",
      count: configuration.rules.length,
    },
    {
      label: "Network Objects",
      count: configuration.network_objects.length,
    },
    {
      label: "Service Objects",
      count: configuration.service_objects.length,
    },
    {
      label: "NAT Rules",
      count: configuration.nat_rules.length,
    },
    {
      label: "Routes",
      count: configuration.routes.length,
    },
    {
      label: "Interfaces",
      count: configuration.interfaces.length,
    },
  ];

  return (
    <div className="reports-page">
      {/* PAGE HEADING */}
      <section className="page-header">
        <div>
          <div className="breadcrumb">
            Security Analysis / Reports
          </div>

          <h1>Security Reports</h1>

          <p>
            Generate and download security assessment
            reports for{" "}
            <strong>{analysis.hostname}</strong>.
          </p>
        </div>
      </section>

      {/* CURRENT ANALYSIS */}
      <section className="panel">
        <div className="reports-section-heading">
          <h2>Current Analysis</h2>

          <p>
            Reports are generated from the firewall
            configuration currently loaded in the
            application.
          </p>
        </div>

        <div className="reports-info-grid">
          <div className="reports-info-item">
            <span>Firewall Hostname</span>

            <strong>{analysis.hostname}</strong>
          </div>

          <div className="reports-info-item">
            <span>Vendor</span>

            <strong>{analysis.vendor}</strong>
          </div>

          <div className="reports-info-item">
            <span>Configuration File</span>

            <strong>
              {filename || "Uploaded configuration"}
            </strong>
          </div>
        </div>
      </section>

      {/* SECURITY SUMMARY */}
      <section className="panel">
        <div className="reports-section-heading">
          <h2>Security Summary</h2>

          <p>
            Key assessment results that will be included
            in your report.
          </p>
        </div>

        <div className="reports-stats-grid">
          {overview.map((item) => (
            <div
              className="reports-stat-card"
              key={item.label}
            >
              <span>{item.label}</span>

              <strong className={item.className || ""}>
                {item.value}
              </strong>
            </div>
          ))}
        </div>

        <h3 className="reports-subheading">
          Findings by Severity
        </h3>

        <div className="reports-severity-grid">
          {severities.map((severity) => (
            <div
              className={`reports-severity-card reports-severity-${severity.className}`}
              key={severity.label}
            >
              <span>{severity.label}</span>

              <strong>{severity.count}</strong>
            </div>
          ))}
        </div>
      </section>

      {/* REPORT DOWNLOAD OPTIONS */}
      <section className="panel">
        <div className="reports-section-heading">
          <h2>Download Reports</h2>

          <p>
            Choose the format that best suits your
            security review or documentation workflow.
          </p>
        </div>

        <div className="reports-download-grid">
          {/* JSON REPORT */}
          <article className="reports-download-card">
            <div className="reports-format-icon reports-json-icon">
              {"{ }"}
            </div>

            <div className="reports-format-heading">
              <h3>JSON Report</h3>

              <span className="reports-format-tag">
                Structured Data
              </span>
            </div>

            <p>
              Download the complete firewall analysis
              as a machine-readable JSON file.
            </p>

            <ul className="reports-feature-list">
              <li>Firewall information</li>
              <li>Security score and risk level</li>
              <li>All security findings</li>
              <li>Complete parsed configuration</li>
            </ul>

            <div className="reports-download-action">
            </div>
          </article>

          {/* PDF REPORT */}
          <article className="reports-download-card">
            <div className="reports-format-icon reports-pdf-icon">
              PDF
            </div>

            <div className="reports-format-heading">
              <h3>PDF Security Report</h3>

              <span className="reports-format-tag">
                Human Readable
              </span>
            </div>

            <p>
              Generate a formatted security assessment
              suitable for review, documentation, and
              sharing with authorized stakeholders.
            </p>

            <ul className="reports-feature-list">
              <li>Firewall security overview</li>
              <li>Severity breakdown</li>
              <li>Findings and recommendations</li>
              <li>Configuration inventory and details</li>
            </ul>

            <div className="reports-download-action">
              <PdfReportDownload />
            </div>
          </article>
        </div>
      </section>

      {/* CONFIGURATION INVENTORY */}
      <section className="panel">
        <div className="reports-section-heading">
          <h2>Configuration Inventory</h2>

          <p>
            Parsed configuration components included
            in the analysis.
          </p>
        </div>

        <div className="reports-inventory-grid">
          {inventory.map((item) => (
            <div
              className="reports-inventory-item"
              key={item.label}
            >
              <span>{item.label}</span>

              <strong>{item.count}</strong>
            </div>
          ))}
        </div>
      </section>

      {/* INFORMATION NOTICE */}
      <section className="reports-notice">
        <span
          className="reports-notice-symbol"
          aria-hidden="true"
        >
          i
        </span>

        <p>
          Reports may contain internal IP addresses,
          firewall rules, and security weaknesses.
          Store downloaded files securely and share
          them only with authorized personnel.
        </p>
      </section>
    </div>
  );
}

export default Reports;
