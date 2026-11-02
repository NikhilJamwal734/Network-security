
import { useMemo, useState } from "react";
import { useAnalysis } from "../context/AnalysisContext";
import "./NATRules.css";

type NATRuleData = Record<string, unknown>;

function formatValue(value: unknown): string {
  if (value === null || value === undefined) {
    return "—";
  }

  if (typeof value === "boolean") {
    return value ? "Yes" : "No";
  }

  if (typeof value === "string" || typeof value === "number") {
    return String(value);
  }

  if (Array.isArray(value)) {
    return value.length === 0
      ? "—"
      : value.map(formatValue).join(", ");
  }

  return JSON.stringify(value);
}

function formatLabel(key: string): string {
  return key
    .replace(/_/g, " ")
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function NATRules() {
  const { analysis } = useAnalysis();

  const [search, setSearch] = useState("");

  const rules = analysis?.configuration.nat_rules ?? [];

  const filteredRules = useMemo(() => {
    const query = search.trim().toLowerCase();

    if (!query) {
      return rules;
    }

    return rules.filter((rule) =>
      JSON.stringify(rule).toLowerCase().includes(query)
    );
  }, [rules, search]);

  if (!analysis) {
    return (
      <div className="nat-rules-page">
        <section className="page-header">
          <div>
            <div className="breadcrumb">
              Security Analysis / NAT Rules
            </div>

            <h1>NAT Rules</h1>

            <p>
              Upload and analyze a Cisco ASA configuration
              from the Dashboard to view NAT rules.
            </p>
          </div>
        </section>

        <section className="panel nat-rules-empty">
          <h2>No configuration loaded</h2>

          <p>
            Go to Dashboard and analyze a firewall
            configuration file first.
          </p>
        </section>
      </div>
    );
  }

  return (
    <div className="nat-rules-page">
      <section className="page-header">
        <div>
          <div className="breadcrumb">
            Security Analysis / NAT Rules
          </div>

          <h1>NAT Rules</h1>

          <p>
            Network Address Translation rules parsed from{" "}
            <strong>{analysis.hostname}</strong>.
          </p>
        </div>
      </section>

      <section className="panel">
        <div className="nat-rules-toolbar">
          <div>
            <h2>NAT Rule Inventory</h2>

            <p>
              Showing {filteredRules.length} of{" "}
              {rules.length} NAT rules
            </p>
          </div>

          <input
            type="search"
            placeholder="Search NAT rules..."
            aria-label="Search NAT rules"
            value={search}
            onChange={(event) =>
              setSearch(event.target.value)
            }
          />
        </div>

        {rules.length === 0 ? (
          <div className="nat-rules-empty">
            <h3>No NAT rules found</h3>

            <p>
              The analyzed configuration does not contain
              any parsed NAT rules.
            </p>
          </div>
        ) : filteredRules.length === 0 ? (
          <div className="nat-rules-empty">
            <h3>No matching NAT rules</h3>

            <p>Try another search term.</p>
          </div>
        ) : (
          <div className="nat-rules-list">
            {filteredRules.map((rule, index) => {
              const data: NATRuleData = { ...rule };

              return (
                <article
                  className="nat-rule-card"
                  key={`${rule.id}-${index}`}
                >
                  <div className="nat-rule-header">
                    <div>
                      <span className="nat-rule-label">
                        NAT RULE
                      </span>

                      <h3>
                        Rule {rule.id}
                      </h3>
                    </div>

                    <span className="nat-rule-line">
                      Line {formatValue(rule.line_number)}
                    </span>
                  </div>

                  <div className="nat-translation">
                    <div className="nat-address">
                      <span className="nat-address-label">
                        Original Source
                      </span>

                      <strong>
                        {formatValue(rule.source)}
                      </strong>
                    </div>

                    <div
                      className="nat-arrow"
                      aria-hidden="true"
                    >
                      →
                    </div>

                    <div className="nat-address">
                      <span className="nat-address-label">
                        Translated Source
                      </span>

                      <strong>
                        {formatValue(rule.translated_source)}
                      </strong>
                    </div>
                  </div>

                  <details className="nat-rule-details">
                    <summary>
                      View full NAT configuration
                    </summary>

                    <dl>
                      {Object.entries(data).map(
                        ([key, value]) => (
                          <div
                            className="nat-rule-detail"
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
              );
            })}
          </div>
        )}
      </section>
    </div>
  );
}

export default NATRules;
