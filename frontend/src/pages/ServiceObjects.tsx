
import { useMemo, useState } from "react";
import { useAnalysis } from "../context/AnalysisContext";
import "./ServiceObjects.css";

type ServiceObject = Record<string, unknown> & {
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

function formatLabel(key: string): string {
  return key
    .replace(/_/g, " ")
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function ServiceObjects() {
  const { analysis } = useAnalysis();

  const [search, setSearch] = useState("");

  const objects: ServiceObject[] =
    analysis?.configuration.service_objects ?? [];

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
      <div className="service-objects-page">
        <section className="page-header">
          <div>
            <div className="breadcrumb">
              Security Analysis / Service Objects
            </div>

            <h1>Service Objects</h1>

            <p>
              Upload and analyze a Cisco ASA configuration
              from the Dashboard to view service objects.
            </p>
          </div>
        </section>

        <section className="panel service-objects-empty">
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
    <div className="service-objects-page">
      <section className="page-header">
        <div>
          <div className="breadcrumb">
            Security Analysis / Service Objects
          </div>

          <h1>Service Objects</h1>

          <p>
            Service objects parsed from{" "}
            <strong>{analysis.hostname}</strong>.
          </p>
        </div>
      </section>

      <section className="panel">
        <div className="service-objects-toolbar">
          <div>
            <h2>Service Object Inventory</h2>

            <p>
              Showing {filteredObjects.length} of{" "}
              {objects.length} objects
            </p>
          </div>

          <input
            type="search"
            placeholder="Search service objects..."
            aria-label="Search service objects"
            value={search}
            onChange={(event) =>
              setSearch(event.target.value)
            }
          />
        </div>

        {objects.length === 0 ? (
          <div className="service-objects-empty">
            <h3>No service objects found</h3>

            <p>
              The analyzed configuration does not contain
              any parsed service objects.
            </p>
          </div>
        ) : filteredObjects.length === 0 ? (
          <div className="service-objects-empty">
            <h3>No matching service objects</h3>

            <p>Try another search term.</p>
          </div>
        ) : (
          <div className="service-objects-grid">
            {filteredObjects.map((object, index) => (
              <article
                className="service-object-card"
                key={`${object.name}-${index}`}
              >
                <div className="service-object-header">
                  <span className="service-object-icon">
                    ◇
                  </span>

                  <h3>{object.name}</h3>
                </div>

                <dl className="service-object-details">
                  {Object.entries(object)
                    .filter(([key]) => key !== "name")
                    .map(([key, value]) => (
                      <div
                        className="service-object-detail"
                        key={key}
                      >
                        <dt>{formatLabel(key)}</dt>

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

export default ServiceObjects;
