/**
 * API-008 Dashboard configuration statistics.
 * One-line metric label and count, no decorative icons.
 */

type SummaryCardProps = {
  label: string;
  value: number | string;
  // Kept optional for compatibility with older call sites.
  // Icons are intentionally not rendered.
  icon?: string;
};

export default function SummaryCard({
  label,
  value,
}: SummaryCardProps) {
  return (
    <div className="fa-metric-tile">
      <span className="fa-metric-tile__label">{label}</span>
      <strong className="fa-metric-tile__value">{value}</strong>
    </div>
  );
}
