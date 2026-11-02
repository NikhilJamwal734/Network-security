import "./SeverityChart.css";

type SeverityChartProps = {
  critical: number;
  high: number;
  medium: number;
  low: number;
};

const COLORS = {
  Critical: "#ef4444",
  High: "#f97316",
  Medium: "#eab308",
  Low: "#3b82f6",
} as const;

const RADIUS = 79;
const CIRCUMFERENCE = 2 * Math.PI * RADIUS;

function SeverityChart({ critical, high, medium, low }: SeverityChartProps) {
  const entries = [
    { name: "Critical", value: Math.max(0, critical), color: COLORS.Critical },
    { name: "High", value: Math.max(0, high), color: COLORS.High },
    { name: "Medium", value: Math.max(0, medium), color: COLORS.Medium },
    { name: "Low", value: Math.max(0, low), color: COLORS.Low },
  ];
  const total = entries.reduce((sum, entry) => sum + entry.value, 0);
  let offset = 0;
  const segments = entries.filter((entry) => entry.value > 0).map((entry) => {
    const length = (entry.value / total) * CIRCUMFERENCE;
    const segment = { ...entry, offset, length };
    offset += length;
    return segment;
  });

  return (
    <div className="fa-severity-layout">
      <div className="fa-severity-visual">
        <svg
          className="fa-severity-svg"
          viewBox="0 0 240 240"
          role="img"
          aria-label={`Findings by severity: ${critical} critical, ${high} high, ${medium} medium, ${low} low. ${total} findings total.`}
        >
          <circle cx="120" cy="120" r={RADIUS} fill="none" stroke="#334155" strokeWidth="34" />
          <g transform="rotate(-90 120 120)">
            {segments.map((segment) => (
              <circle
                key={segment.name}
                cx="120"
                cy="120"
                r={RADIUS}
                fill="none"
                stroke={segment.color}
                strokeWidth="34"
                strokeDasharray={`${segment.length} ${CIRCUMFERENCE - segment.length}`}
                strokeDashoffset={-segment.offset}
              >
                <title>{`${segment.name}: ${segment.value} (${Math.round((segment.value / total) * 100)}%)`}</title>
              </circle>
            ))}
          </g>
          <text x="120" y="114" textAnchor="middle" className="fa-severity-number">{total}</text>
          <text x="120" y="139" textAnchor="middle" className="fa-severity-center-label">Total findings</text>
        </svg>
      </div>

      <div className="fa-severity-legend" aria-label="Severity breakdown">
        {entries.map((entry) => (
          <div className="fa-severity-legend-row" key={entry.name}>
            <span className="fa-severity-dot" style={{ backgroundColor: entry.color }} aria-hidden="true" />
            <span className="fa-severity-label">{entry.name}</span>
            <strong className="fa-severity-count">{entry.value}</strong>
            <span className="fa-severity-percent">
              {total > 0 ? `${Math.round((entry.value / total) * 100)}%` : "0%"}
            </span>
          </div>
        ))}
        <p className="fa-severity-note">Each color represents a security finding severity.</p>
      </div>
    </div>
  );
}

export default SeverityChart;
