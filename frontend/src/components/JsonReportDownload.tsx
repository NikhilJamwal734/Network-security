
import { useState } from "react";

import { useAnalysis } from "../context/AnalysisContext";

import { downloadAnalysisJson } from "../services/reportExport";

import "./JsonReportDownload.css";

function JsonReportDownload() {
  const { analysis, filename } = useAnalysis();

  const [error, setError] = useState<string | null>(null);

  function handleDownload() {
    if (!analysis) {
      return;
    }

    try {
      downloadAnalysisJson(analysis, filename);
      setError(null);
    } catch (err) {
      console.error("JSON export failed:", err);

      setError("Unable to generate the JSON report.");
    }
  }

  return (
    <div className="json-report-download">
      <button
        type="button"
        className="json-download-button"
        onClick={handleDownload}
        disabled={!analysis}
        title={
          analysis
            ? "Download the current firewall security report"
            : "Analyze a firewall configuration first"
        }
      >
        <span aria-hidden="true">↓</span>
        <span>Download JSON</span>
      </button>

      {error && (
        <span
          className="json-download-error"
          role="alert"
        >
          {error}
        </span>
      )}
    </div>
  );
}

export default JsonReportDownload;
