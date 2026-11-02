
import { useMemo, useState } from "react";
import { useAnalysis } from "../context/AnalysisContext";
import "./NetworkObjects.css";

type NetworkObject = Record<string, unknown> & {
  name: string;
};

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

function NetworkObjects() {
  const { analysis } = useAnalysis();

  const [search, setSearch] = useState("");

  const objects: NetworkObject[] =
    analysis?.configuration.network_objects ?? [];

  const filteredObjects = useMemo(() => {
    const query = search.trim().toLowerCase();

    if (!query) {
      return objects;
    }

    return objects.filter((object) =>
      JSON.stringify(object).toLowerCase().includes(query)
    );
  }, [objects, search]);

  if (!analysis) {
    return (
      <div className="network-objects-page">
        <section className="page-header">
          <div>
            <div className="breadcrumb">
              Security Analysis / Network Objects
            </div>

            <h1>Network Objects</h1>

            <p>
              Upload and analyze a firewall configuration
              from the Dashboard to view network objects.
            </p>
          </div>
        </section>

        <section className="panel network-objects-empty">
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
    <div className="network-objects-page">
      <section className="page-header">
        <div>
          <div className="breadcrumb">
            Security Analysis / Network Objects
          </div>

          <h1>Network Objects</h1>

          <p>
            Network objects parsed from{" "}
            <strong>{analysis.hostname}</strong>.
          </p>
        </div>
      </section>

      <section className="panel">
        <div className="network-objects-toolbar">
          <div>
            <h2>Network Object Inventory</h2>

            <p>
              Showing {filteredObjects.length} of{" "}
              {objects.length} objects
            </p>
          </div>

          <input
            type="search"
            placeholder="Search network objects..."
            aria-label="Search network objects"
            value={search}
            onChange={(event) => setSearch(event.target.value)}
          />
        </div>

        {objects.length === 0 ? (
          <div className="network-objects-empty">
            <h3>No network objects found</h3>

            <p>
              The analyzed configuration does not contain
              any parsed network objects.
            </p>
          </div>
        ) : filteredObjects.length === 0 ? (
          <div className="network-objects-empty">
            <h3>No matching objects</h3>

            <p>
              Try another search term.
            </p>
          </div>
        ) : (
          <div className="network-objects-grid">
            {filteredObjects.map((object, index) => (
              <article
                className="network-object-card"
                key={`${object.name}-${index}`}
              >
                <div className="network-object-header">
                  <span className="network-object-icon">
                    ◈
                  </span>

                  <h3>{object.name}</h3>
                </div>

                <dl className="network-object-details">
                  {Object.entries(object)
                    .filter(([key]) => key !== "name")
                    .map(([key, value]) => (
                      <div
                        className="network-object-detail"
                        key={key}
                      >
                        <dt>
                          {key
                            .replace(/_/g, " ")
                            .replace(/\b\w/g, (letter) =>
                              letter.toUpperCase()
                            )}
                        </dt>

                        <dd>{formatValue(value)}</dd>
                      </div>
                    ))}
                </dl>
              </article>
            ))}
          </div>
        )}
      </section>
    </div>
  );
}

export default NetworkObjects;
