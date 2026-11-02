import { useState } from "react";
import type { NormalizedReport } from "../api/universal";
import { downloadNormalizedPdf } from "../utils/normalizedPdf";
import "./NormalizedReportDownloads.css";

/** The same PDF exporter is used by all four security platforms. */
interface Props {
  report: NormalizedReport;
  filename: string;
  compact?: boolean;
}

export default function NormalizedReportDownloads({
  report,
  filename,
  compact = false,
}: Props) {
  const [working, setWorking] = useState(false);
  const [error, setError] = useState("");

  async function handleDownload() {
    if (working) return;
    setWorking(true);
    setError("");
    try {
      await downloadNormalizedPdf(report, filename);
    } catch {
      setError("Unable to generate PDF. Please try again.");
    } finally {
      setWorking(false);
    }
  }

  return (
    <div
      className={`normalized-downloads ${compact ? "normalized-downloads-compact" : ""}`}
      aria-label="Security report downloads"
    >
      <button type="button" onClick={() => void handleDownload()} disabled={working}>
        {working ? "Generating PDF..." : "Download PDF"}
      </button>
      {error && <span role="alert" className="normalized-download-error">{error}</span>}
    </div>
  );
}
