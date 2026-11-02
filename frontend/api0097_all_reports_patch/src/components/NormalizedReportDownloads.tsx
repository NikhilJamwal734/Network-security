import type { NormalizedReport } from "../api/universal";
import { downloadNormalizedJson, downloadNormalizedPdf } from "../utils/normalizedPdf";
import "./NormalizedReportDownloads.css";

interface Props {
  report: NormalizedReport;
  filename: string;
  compact?: boolean;
}

export default function NormalizedReportDownloads({ report, filename, compact = false }: Props) {
  return (
    <div className={`normalized-downloads ${compact ? "normalized-downloads-compact" : ""}`} aria-label="Security report downloads">
      <button type="button" onClick={() => downloadNormalizedPdf(report, filename)}>
        Download PDF
      </button>
      <button type="button" onClick={() => downloadNormalizedJson(report, filename)}>
        Download JSON
      </button>
    </div>
  );
}
