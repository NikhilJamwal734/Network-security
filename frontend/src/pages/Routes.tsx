
import { useMemo, useState } from "react";
import { useAnalysis } from "../context/AnalysisContext";
import "./Routes.css";

type RouteData = Record<string, unknown>;

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

function firstAvailable(
  route: RouteData,
  keys: string[]
): string {
  for (const key of keys) {
    const value = route[key];

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

function Routes() {
  const { analysis } = useAnalysis();
  const [search, setSearch] = useState("");

  const routes = analysis?.configuration.routes ?? [];

  const filteredRoutes = useMemo(() => {
    const query = search.trim().toLowerCase();

    if (!query) {
      return routes;
    }

    return routes.filter((route) =>
      JSON.stringify(route).toLowerCase().includes(query)
    );
  }, [routes, search]);

  if (!analysis) {
    return (
      <div className="routes-page">
        <section className="page-header">
          <div>
            <div className="breadcrumb">
              Security Analysis / Routes
            </div>

            <h1>Routes</h1>

            <p>
              View routing information from your analyzed
              Cisco ASA configuration.
            </p>
          </div>
        </section>

        <section className="panel routes-empty">
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
    <div className="routes-page">
      <section className="page-header">
        <div>
          <div className="breadcrumb">
            Security Analysis / Routes
          </div>

          <h1>Routes</h1>

          <p>
            Routing information parsed from{" "}
            <strong>{analysis.hostname}</strong>.
          </p>
        </div>
      </section>

      <section className="panel">
        <div className="routes-toolbar">
          <div>
            <h2>Routing Table</h2>

            <p>
              Showing {filteredRoutes.length} of{" "}
              {routes.length} routes
            </p>
          </div>

          <input
            type="search"
            placeholder="Search routes..."
            aria-label="Search routes"
            value={search}
            onChange={(event) =>
              setSearch(event.target.value)
            }
          />
        </div>

        {routes.length === 0 ? (
          <div className="routes-empty">
            <div
              className="routes-empty-icon"
              aria-hidden="true"
            >
              ⇄
            </div>

            <h3>No routes found</h3>

            <p>
              The analyzed configuration contains no
              parsed static routes.
            </p>

            <p>
              This is expected for configurations without
              supported route statements.
            </p>
          </div>
        ) : filteredRoutes.length === 0 ? (
          <div className="routes-empty">
            <h3>No matching routes</h3>

            <p>
              Try another search term or clear the search.
            </p>
          </div>
        ) : (
          <div className="routes-table-container">
            <table className="routes-table">
              <thead>
                <tr>
                  <th>Interface</th>
                  <th>Destination</th>
                  <th>Gateway</th>
                  <th>Metric</th>
                  <th>Details</th>
                </tr>
              </thead>

              <tbody>
                {filteredRoutes.map((route, index) => {
                  const data: RouteData = { ...route };

                  return (
                    <tr key={index}>
                      <td>
                        {firstAvailable(data, [
                          "interface",
                          "interface_name",
                          "outgoing_interface",
                        ])}
                      </td>

                      <td>
                        {firstAvailable(data, [
                          "destination",
                          "destination_network",
                          "network",
                          "prefix",
                        ])}
                      </td>

                      <td>
                        {firstAvailable(data, [
                          "gateway",
                          "next_hop",
                          "next_hop_ip",
                        ])}
                      </td>

                      <td>
                        {firstAvailable(data, [
                          "metric",
                          "distance",
                          "administrative_distance",
                        ])}
                      </td>

                      <td>
                        <details className="route-details">
                          <summary>
                            View configuration
                          </summary>

                          <dl>
                            {Object.entries(data).map(
                              ([key, value]) => (
                                <div
                                  className="route-detail"
                                  key={key}
                                >
                                  <dt>{formatLabel(key)}</dt>

                                  <dd>
                                    {formatValue(value)}
                                  </dd>
                                </div>
                              )
                            )}
                          </dl>
                        </details>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}

export default Routes;
