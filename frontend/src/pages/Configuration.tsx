
import { useMemo, useState } from "react";

import { useAnalysis } from "../context/AnalysisContext";

import "./Configuration.css";

/* ============================================================
   TYPES
   ============================================================ */

type ConfigurationRecord = Record<string, unknown>;

type InterfaceItem = {
  key: string;
  name: string;
  ipAddress: string;
  securityLevel: string;
  status: string;
  properties: [string, unknown][];
  searchable: string;
};

/* ============================================================
   HELPERS
   ============================================================ */

function formatValue(value: unknown): string {
  if (value === null || value === undefined) {
    return "—";
  }

  if (typeof value === "boolean") {
    return value ? "Yes" : "No";
  }

  if (
    typeof value === "string" ||
    typeof value === "number"
  ) {
    return String(value);
  }

  if (Array.isArray(value)) {
    if (value.length === 0) {
      return "—";
    }

    return value.map(formatValue).join(", ");
  }

  return JSON.stringify(value);
}

function formatLabel(key: string): string {
  return key
    .replace(/_/g, " ")
    .replace(/\b\w/g, (letter) =>
      letter.toUpperCase()
    );
}

function firstAvailable(
  record: ConfigurationRecord,
  keys: string[]
): string {
  for (const key of keys) {
    const value = record[key];

    if (
      value !== null &&
      value !== undefined &&
      value !== ""
    ) {
      return formatValue(value);
    }
  }

  return "—";
}

function normalizeInterface(
  item: unknown,
  index: number
): InterfaceItem {
  const record: ConfigurationRecord =
    item !== null &&
    typeof item === "object" &&
    !Array.isArray(item)
      ? (item as ConfigurationRecord)
      : { value: item };

  const name = firstAvailable(record, [
    "name",
    "nameif",
    "interface_name",
    "interface",
    "physical_name",
  ]);

  const ipAddress = firstAvailable(record, [
    "ip_address",
    "ip",
    "address",
    "ipv4_address",
  ]);

  const securityLevel = firstAvailable(record, [
    "security_level",
    "security",
  ]);

  const status = firstAvailable(record, [
    "status",
    "state",
    "enabled",
    "shutdown",
  ]);

  return {
    key: `${name}-${index}`,
    name:
      name === "—"
        ? `Interface ${index + 1}`
        : name,
    ipAddress,
    securityLevel,
    status,
    properties: Object.entries(record),
    searchable: JSON.stringify(record).toLowerCase(),
  };
}

/* ============================================================
   CONFIGURATION PAGE
   ============================================================ */

function Configuration() {
  const { analysis, filename } = useAnalysis();

  const [search, setSearch] = useState("");

  const interfaces = useMemo(() => {
    const source =
      analysis?.configuration.interfaces ?? [];

    return source.map((item, index) =>
      normalizeInterface(item, index)
    );
  }, [analysis]);

  const filteredInterfaces = useMemo(() => {
    const query = search.trim().toLowerCase();

    if (!query) {
      return interfaces;
    }

    return interfaces.filter(
      (item) =>
        item.searchable.includes(query) ||
        item.name.toLowerCase().includes(query)
    );
  }, [interfaces, search]);

  /* ==========================================================
     NO ANALYSIS STATE
     ========================================================== */

  if (!analysis) {
    return (
      <div className="configuration-page">
        <section className="page-header">
          <div>
            <div className="breadcrumb">
              Security Analysis / Configuration
            </div>

            <h1>Configuration</h1>

            <p>
              Review the parsed Cisco ASA firewall
              configuration.
            </p>
          </div>
        </section>

        <section className="panel configuration-empty">
          <h2>No configuration loaded</h2>

          <p>
            Open Dashboard and analyze a firewall
            configuration file first.
          </p>
        </section>
      </div>
    );
  }

  const inventory = [
    {
      label: "Firewall Rules",
      count: analysis.configuration.rules.length,
      icon: "≡",
    },
    {
      label: "Network Objects",
      count:
        analysis.configuration.network_objects.length,
      icon: "◈",
    },
    {
      label: "Service Objects",
      count:
        analysis.configuration.service_objects.length,
      icon: "◇",
    },
    {
      label: "NAT Rules",
      count: analysis.configuration.nat_rules.length,
      icon: "↔",
    },
    {
      label: "Routes",
      count: analysis.configuration.routes.length,
      icon: "⇄",
    },
    {
      label: "Interfaces",
      count: interfaces.length,
      icon: "▣",
    },
  ];

  /* ==========================================================
     PAGE
     ========================================================== */

  return (
    <div className="configuration-page">
      {/* PAGE HEADER */}
      <section className="page-header">
        <div>
          <div className="breadcrumb">
            Security Analysis / Configuration
          </div>

          <h1>Configuration</h1>

          <p>
            Parsed configuration details for{" "}
            <strong>{analysis.hostname}</strong>.
          </p>
        </div>
      </section>

      {/* FIREWALL INFORMATION */}
      <section className="panel">
        <div className="configuration-section-heading">
          <h2>Firewall Information</h2>

          <p>
            General information about the analyzed
            firewall.
          </p>
        </div>

        <div className="configuration-info-grid">
          <div className="configuration-info-item">
            <span>Hostname</span>

            <strong>{analysis.hostname}</strong>
          </div>

          <div className="configuration-info-item">
            <span>Vendor</span>

            <strong>{analysis.vendor}</strong>
          </div>

          <div className="configuration-info-item">
            <span>Configuration File</span>

            <strong>
              {filename || "Uploaded configuration"}
            </strong>
          </div>

          <div className="configuration-info-item">
            <span>Security Score</span>

            <strong>
              {analysis.summary.security_score}/100
            </strong>
          </div>

          <div className="configuration-info-item">
            <span>Risk Level</span>

            <strong
              className={`configuration-risk configuration-risk-${String(
                analysis.summary.risk_level
              ).toLowerCase()}`}
            >
              {analysis.summary.risk_level}
            </strong>
          </div>

          <div className="configuration-info-item">
            <span>Security Findings</span>

            <strong>
              {analysis.summary.total_findings}
            </strong>
          </div>
        </div>
      </section>

      {/* CONFIGURATION INVENTORY */}
      <section className="panel">
        <div className="configuration-section-heading">
          <h2>Configuration Inventory</h2>

          <p>
            Components extracted from the uploaded
            firewall configuration.
          </p>
        </div>

        <div className="configuration-inventory">
          {inventory.map((item) => (
            <div
              className="configuration-inventory-card"
              key={item.label}
            >
              <div className="configuration-inventory-icon">
                {item.icon}
              </div>

              <div>
                <span>{item.label}</span>

                <strong>{item.count}</strong>
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* INTERFACE DETAILS */}
      <section className="panel">
        <div className="configuration-interfaces-toolbar">
          <div>
            <h2>Firewall Interfaces</h2>

            <p>
              Showing {filteredInterfaces.length} of{" "}
              {interfaces.length} interfaces
            </p>
          </div>

          <input
            type="search"
            placeholder="Search interfaces..."
            aria-label="Search firewall interfaces"
            value={search}
            onChange={(event) =>
              setSearch(event.target.value)
            }
          />
        </div>

        {interfaces.length === 0 ? (
          <div className="configuration-empty">
            <h3>No interfaces found</h3>

            <p>
              The uploaded configuration contains no
              parsed interface records.
            </p>
          </div>
        ) : filteredInterfaces.length === 0 ? (
          <div className="configuration-empty">
            <h3>No matching interfaces</h3>

            <p>
              Try another interface name, IP address,
              or security level.
            </p>

            <button
              type="button"
              className="configuration-clear-button"
              onClick={() => setSearch("")}
            >
              Clear search
            </button>
          </div>
        ) : (
          <div className="configuration-interface-grid">
            {filteredInterfaces.map((item) => (
              <article
                className="configuration-interface-card"
                key={item.key}
              >
                <div className="configuration-interface-header">
                  <div>
                    <span className="configuration-interface-label">
                      FIREWALL INTERFACE
                    </span>

                    <h3>{item.name}</h3>
                  </div>

                  <span className="configuration-interface-symbol">
                    ▣
                  </span>
                </div>

                <div className="configuration-interface-summary">
                  <div>
                    <span>IP Address</span>
                    <strong>{item.ipAddress}</strong>
                  </div>

                  <div>
                    <span>Security Level</span>
                    <strong>{item.securityLevel}</strong>
                  </div>

                  <div>
                    <span>Status</span>
                    <strong>{item.status}</strong>
                  </div>
                </div>

                <details className="configuration-interface-details">
                  <summary>
                    View complete interface configuration
                  </summary>

                  <dl>
                    {item.properties.map(
                      ([key, value]) => (
                        <div
                          className="configuration-detail-row"
                          key={key}
                        >
                          <dt>{formatLabel(key)}</dt>

                          <dd>{formatValue(value)}</dd>
                        </div>
                      )
                    )}
                  </dl>
                </details>
              </article>
            ))}
          </div>
        )}
      </section>
    </div>
  );
}

export default Configuration;
