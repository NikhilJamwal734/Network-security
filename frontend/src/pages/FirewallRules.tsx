
import { useMemo, useState } from "react";
import { useAnalysis } from "../context/AnalysisContext";
import "./FirewallRules.css";

function FirewallRules() {
  const { analysis } = useAnalysis();

  const [search, setSearch] = useState("");
  const [actionFilter, setActionFilter] = useState("all");

  const rules = analysis?.configuration.rules ?? [];

  const filteredRules = useMemo(() => {
    return rules.filter((rule) => {
      const matchesAction =
        actionFilter === "all" ||
        rule.action.toLowerCase() === actionFilter;

      const searchableText = [
        rule.name,
        rule.action,
        rule.protocol,
        ...rule.source,
        ...rule.destination,
        rule.raw_config,
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();

      const matchesSearch = searchableText.includes(
        search.toLowerCase()
      );

      return matchesAction && matchesSearch;
    });
  }, [rules, search, actionFilter]);

  if (!analysis) {
    return (
      <div className="firewall-rules-page">
        <section className="page-header">
          <div>
            <div className="breadcrumb">
              Security Analysis / Rules
            </div>
            <h1>Firewall Rules</h1>
            <p>
              Upload a firewall configuration from the
              Dashboard to view parsed rules.
            </p>
          </div>
        </section>

        <section className="panel rules-empty">
          <h2>No configuration loaded</h2>
          <p>
            Go to Dashboard and analyze a Cisco ASA
            configuration file first.
          </p>
        </section>
      </div>
    );
  }

  return (
    <div className="firewall-rules-page">
      <section className="page-header">
        <div>
          <div className="breadcrumb">
            Security Analysis / Rules
          </div>

          <h1>Firewall Rules</h1>

          <p>
            Access control rules parsed from{" "}
            <strong>{analysis.hostname}</strong>.
          </p>
        </div>
      </section>

      <section className="panel">
        <div className="rules-toolbar">
          <div>
            <h2>Access Control Rules</h2>
            <p>
              Showing {filteredRules.length} of {rules.length} rules
            </p>
          </div>

          <div className="rules-filters">
            <input
              type="search"
              placeholder="Search firewall rules..."
              value={search}
              onChange={(event) =>
                setSearch(event.target.value)
              }
              aria-label="Search firewall rules"
            />

            <select
              value={actionFilter}
              onChange={(event) =>
                setActionFilter(event.target.value)
              }
              aria-label="Filter by rule action"
            >
              <option value="all">All Actions</option>
              <option value="permit">Permit</option>
              <option value="deny">Deny</option>
            </select>
          </div>
        </div>

        <div className="rules-table-container">
          <table className="rules-table">
            <thead>
              <tr>
                <th>Line</th>
                <th>Action</th>
                <th>Protocol</th>
                <th>Source</th>
                <th>Destination</th>
                <th>Logging</th>
                <th>Status</th>
              </tr>
            </thead>

            <tbody>
              {filteredRules.map((rule, index) => (
                <tr key={`${rule.id}-${index}`}>
                  <td>{rule.line_number}</td>

                  <td>
                    <span
                      className={`rule-action ${
                        rule.action.toLowerCase() === "permit"
                          ? "permit"
                          : "deny"
                      }`}
                    >
                      {rule.action}
                    </span>
                  </td>

                  <td>{rule.protocol}</td>

                  <td>
                    {rule.source.length > 0
                      ? rule.source.join(", ")
                      : "Any"}
                  </td>

                  <td>
                    {rule.destination.length > 0
                      ? rule.destination.join(", ")
                      : "Any"}
                  </td>

                  <td>{rule.logging ? "Yes" : "No"}</td>

                  <td>
                    {rule.disabled ? "Disabled" : "Enabled"}
                  </td>
                </tr>
              ))}

              {filteredRules.length === 0 && (
                <tr>
                  <td colSpan={7} className="rules-no-results">
                    No firewall rules match your filters.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}

export default FirewallRules;
