/**
 * Dashboard Finding Summary
 * One clean row per severity; no leading icons.
 */
import "./FindingSummary.css";

type FindingSummaryProps = {
  critical: number;
  high: number;
  medium: number;
  low: number;
  total: number;
};

function FindingSummary({
  critical,
  high,
  medium,
  low,
  total,
}: FindingSummaryProps) {
  const categories = [
    { name: "Critical", count: critical, key: "critical" },
    { name: "High", count: high, key: "high" },
    { name: "Medium", count: medium, key: "medium" },
    { name: "Low", count: low, key: "low" },
  ] as const;

  return (
    <section className="fsu-summary" aria-labelledby="fsu-title">
      <div className="fsu-heading">
        <h2 id="fsu-title">Finding Summary</h2>
        <p>
          <strong>{total}</strong> security findings detected
        </p>
      </div>

      <ul className="fsu-list" aria-label="Findings by severity">
        {categories.map((category) => (
          <li
            key={category.key}
            className={`fsu-row fsu-${category.key}`}
          >
            <span className="fsu-name">{category.name}</span>
            <span className="fsu-count">{category.count}</span>
          </li>
        ))}
      </ul>
    </section>
  );
}

export default FindingSummary;
