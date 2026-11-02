
import { useMemo, useState } from "react";
import { useAnalysis } from "../context/AnalysisContext";
import "./Findings.css";

type FindingRecord = Record<string, unknown>;

type FindingItem = {
  key: string;
  id: string;
  title: string;
  severity: string;
  description: string;
  recommendation: string;
  location: string | null;
  fields: [string, unknown][];
  searchable: string;
};

const SEVERITIES = [
  "CRITICAL",
  "HIGH",
  "MEDIUM",
  "LOW",
  "INFO",
] as const;

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
    return value.length === 0
      ? "—"
      : value.map(formatValue).join(", ");
  }

  return JSON.stringify(value);
}

function firstAvailable(
  record: FindingRecord,
  keys: string[]
): string {
  for (const key of keys) {
    const value = record[key];

    if (
      value !== undefined &&
      value !== null &&
      value !== ""
    ) {
      return formatValue(value);
    }
  }

  return "";
}

function formatLabel(key: string): string {
  return key
    .replace(/_/g, " ")
    .replace(/\b\w/g, (letter) =>
      letter.toUpperCase()
    );
}

function normalizeFinding(
  finding: unknown,
  index: number
): FindingItem {
  const record: FindingRecord =
    finding !== null && typeof finding === "object"
      ? (finding as FindingRecord)
      : { value: finding };

  const id =
    firstAvailable(record, [
      "check_id",
      "finding_id",
      "rule_id",
      "id",
    ]) || `Finding ${index + 1}`;

  const title =
    firstAvailable(record, [
      "title",
      "name",
      "check_name",
      "summary",
    ]) || id;

  const severity =
    (
      firstAvailable(record, [
        "severity",
        "risk_level",
        "level",
      ]) || "UNKNOWN"
    ).toUpperCase();

  const description =
    firstAvailable(record, [
      "description",
      "message",
      "details",
      "reason",
    ]) || "No description provided.";

  const recommendation =
    firstAvailable(record, [
      "recommendation",
      "remediation",
      "suggestion",
      "recommended_action",
      "fix",
    ]) || "";

  const locationValue = firstAvailable(record, [
    "line_number",
    "line",
    "location",
    "affected_object",
  ]);

  return {
    key: `${id}-${index}`,
    id,
    title,
    severity,
    description,
    recommendation,
    location: locationValue || null,
    fields: Object.entries(record),
    searchable: JSON.stringify(record).toLowerCase(),
  };
}

function Findings() {
  const { analysis } = useAnalysis();

  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] =
    useState("ALL");

  const findings = useMemo(() => {
    const source = analysis?.findings ?? [];

    return source.map((finding, index) =>
      normalizeFinding(finding, index)
    );
  }, [analysis]);

  const severityCounts = useMemo(() => {
    const counts: Record<string, number> = {};

    for (const severity of SEVERITIES) {
      counts[severity] = 0;
    }

    for (const finding of findings) {
      counts[finding.severity] =
        (counts[finding.severity] ?? 0) + 1;
    }

    return counts;
  }, [findings]);

  const filteredFindings = useMemo(() => {
    const query = search.trim().toLowerCase();

    return findings.filter((finding) => {
      const matchesSeverity =
        severityFilter === "ALL" ||
        finding.severity === severityFilter;

      const matchesSearch =
        query === "" ||
        finding.searchable.includes(query) ||
        finding.id.toLowerCase().includes(query) ||
        finding.title.toLowerCase().includes(query);

      return matchesSeverity && matchesSearch;
    });
  }, [findings, search, severityFilter]);

  function clearFilters() {
    setSearch("");
    setSeverityFilter("ALL");
  }

  if (!analysis) {
    return (
      <div className="findings-page">
        <section className="page-header">
          <div>
            <div className="breadcrumb">
              Security Analysis / Findings
            </div>

            <h1>Security Findings</h1>

            <p>
              Review security issues identified in your
              firewall configuration.
            </p>
          </div>
        </section>

        <section className="panel findings-empty">
          <h2>No analysis loaded</h2>

          <p>
            Open Dashboard and analyze a Cisco ASA
            configuration file to view security findings.
          </p>
        </section>
      </div>
    );
  }

  return (
    <div className="findings-page">
      {/* PAGE HEADER */}
      <section className="page-header">
        <div>
          <div className="breadcrumb">
            Security Analysis / Findings
          </div>

          <h1>Security Findings</h1>

          <p>
            Security issues identified in{" "}
            <strong>{analysis.hostname}</strong>.
          </p>
        </div>
      </section>

      {/* SEVERITY SUMMARY */}
      <div className="findings-stats">
        <div className="finding-stat">
          <span className="finding-stat-label">
            Total Findings
          </span>

          <strong>{findings.length}</strong>
        </div>

        {SEVERITIES.slice(0, 4).map((severity) => (
          <div
            className={`finding-stat finding-stat-${severity.toLowerCase()}`}
            key={severity}
          >
            <span className="finding-stat-label">
              {severity.charAt(0) +
                severity.slice(1).toLowerCase()}
            </span>

            <strong>
              {severityCounts[severity] ?? 0}
            </strong>
          </div>
        ))}
      </div>

      {/* MAIN FINDINGS PANEL */}
      <section className="panel">
        <div className="findings-toolbar">
          <div>
            <h2>Findings Inventory</h2>

            <p>
              Showing {filteredFindings.length} of{" "}
              {findings.length} findings
            </p>
          </div>

          <div className="findings-filters">
            <input
              type="search"
              placeholder="Search findings..."
              aria-label="Search findings"
              value={search}
              onChange={(event) =>
                setSearch(event.target.value)
              }
            />

            <select
              aria-label="Filter findings by severity"
              value={severityFilter}
              onChange={(event) =>
                setSeverityFilter(event.target.value)
              }
            >
              <option value="ALL">
                All Severities
              </option>

              {SEVERITIES.map((severity) => (
                <option
                  key={severity}
                  value={severity}
                >
                  {severity.charAt(0) +
                    severity.slice(1).toLowerCase()}
                </option>
              ))}

              <option value="UNKNOWN">
                Unknown
              </option>
            </select>

            <button
              type="button"
              className="findings-clear-button"
              onClick={clearFilters}
              disabled={
                search === "" &&
                severityFilter === "ALL"
              }
            >
              Clear
            </button>
          </div>
        </div>

        {/* EMPTY STATES */}
        {findings.length === 0 ? (
          <div className="findings-empty">
            <h3>No security findings</h3>

            <p>
              The analysis returned no finding records.
            </p>
          </div>
        ) : filteredFindings.length === 0 ? (
          <div className="findings-empty">
            <h3>No matching findings</h3>

            <p>
              Try another search or severity filter.
            </p>

            <button
              type="button"
              className="findings-clear-button"
              onClick={clearFilters}
            >
              Clear filters
            </button>
          </div>
        ) : (
          <div className="findings-list">
            {filteredFindings.map((finding) => (
              <article
                className="finding-card"
                key={finding.key}
              >
                <div className="finding-card-header">
                  <div className="finding-heading">
                    <span className="finding-id">
                      {finding.id}
                    </span>

                    <h3>{finding.title}</h3>
                  </div>

                  <span
                    className={`finding-severity finding-severity-${finding.severity.toLowerCase()}`}
                  >
                    {finding.severity}
                  </span>
                </div>

                <div className="finding-card-body">
                  <div className="finding-description">
                    <h4>Description</h4>

                    <p>{finding.description}</p>
                  </div>

                  {finding.recommendation && (
                    <div className="finding-recommendation">
                      <h4>Recommendation</h4>

                      <p>
                        {finding.recommendation}
                      </p>
                    </div>
                  )}

                  {finding.location && (
                    <p className="finding-location">
                      <strong>Location:</strong>{" "}
                      {finding.location}
                    </p>
                  )}
                </div>

                <details className="finding-details">
                  <summary>
                    View complete finding details
                  </summary>

                  <dl>
                    {finding.fields.map(
                      ([key, value]) => (
                        <div
                          className="finding-detail-row"
                          key={key}
                        >
                          <dt>
                            {formatLabel(key)}
                          </dt>

                          <dd>
                            {formatValue(value)}
                          </dd>
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

export default Findings;
