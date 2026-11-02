/**
 * Shared severity chart for every normalized security platform.
 * Reads only the report's normalized severity counts (no legacy ASA dependency).
 * No third-party chart package, HTML injection, or backend changes required.
 */
import type { Severity } from "../api/universal";
import "./UniversalSeverityChart.css";

type SeverityCounts = Record<Severity, number>;

type SeverityDefinition = {
  key: Severity;
  label: string;
  color: string;
};

const DEFINITIONS: readonly SeverityDefinition[] = [
  { key: "critical", label: "Critical", color: "#fb4769" },
  { key: "high", label: "High", color: "#fb923c" },
  { key: "medium", label: "Medium", color: "#facc15" },
  { key: "low", label: "Low", color: "#60a5fa" },
  { key: "info", label: "Info", color: "#2dd4bf" },
  { key: "unknown", label: "Unknown", color: "#94a3b8" },
];

const RADIUS = 75;
const CIRCUMFERENCE = 2 * Math.PI * RADIUS;

interface UniversalSeverityChartProps {
  counts: SeverityCounts;
}

/** Clamp malformed counts defensively; backend validation remains authoritative. */
function validCount(value: number): number {
  return Number.isFinite(value) && value > 0 ? Math.floor(value) : 0;
}

export default function UniversalSeverityChart({ counts }: UniversalSeverityChartProps) {
  const entries = DEFINITIONS.map((item) => ({
    ...item,
    count: validCount(counts[item.key]),
  }));
  const total = entries.reduce((sum, entry) => sum + entry.count, 0);
  let completedArc = 0;
  const chartLabel = total === 0
    ? "Severity chart: no findings"
    : `Severity chart: ${entries.map((entry) => `${entry.label} ${entry.count}`).join(", ")}`;

  return (
    <div className="usc-layout">
      <div className="usc-donut-wrap">
        <svg
          className="usc-donut"
          viewBox="0 0 200 200"
          role="img"
          aria-label={chartLabel}
        >
          <circle
            cx="100" cy="100" r={RADIUS}
            className="usc-track"
            fill="none" strokeWidth="21"
          />
          {total > 0 && entries.map((entry) => {
            if (entry.count === 0) return null;
            const arc = (entry.count / total) * CIRCUMFERENCE;
            const offset = -completedArc;
            completedArc += arc;
            return (
              <circle
                key={entry.key}
                cx="100" cy="100" r={RADIUS}
                fill="none"
                stroke={entry.color}
                strokeWidth="21"
                strokeDasharray={`${arc} ${CIRCUMFERENCE - arc}`}
                strokeDashoffset={offset}
                transform="rotate(-90 100 100)"
              />
            );
          })}
          <text x="100" y="94" textAnchor="middle" className="usc-total">{total}</text>
          <text x="100" y="119" textAnchor="middle" className="usc-total-caption">
            {total === 1 ? "finding" : "findings"}
          </text>
        </svg>
      </div>
      <div className="usc-legend-wrap">
        <p className="usc-explainer">Severity of findings in this configuration</p>
        <ul className="usc-legend" aria-label="Severity counts">
          {entries.map((entry) => (
            <li className="usc-legend-item" key={entry.key}>
              <span className="usc-legend-label">
                <span className="usc-dot" style={{ backgroundColor: entry.color }} aria-hidden="true" />
                {entry.label}
              </span>
              <strong className="usc-count">{entry.count}</strong>
            </li>
          ))}
        </ul>
        {total === 0 && (
          <p className="usc-empty-note">No findings were reported by the available checks.</p>
        )}
      </div>
    </div>
  );
}
