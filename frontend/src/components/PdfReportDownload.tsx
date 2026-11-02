
import { useState } from "react";

import { useAnalysis } from "../context/AnalysisContext";

import { downloadAnalysisPdf } from "../services/pdfReport";

import "./PdfReportDownload.css";

function PdfReportDownload() {
  const { analysis, filename } = useAnalysis();

  const [downloading, setDownloading] =
    useState(false);

  const [error, setError] =
    useState<string | null>(null);

  async function handleDownload() {
    if (!analysis || downloading) {
      return;
    }

    setDownloading(true);
    setError(null);

    try {
      await downloadAnalysisPdf(
        analysis,
        filename
      );
    } catch (err) {
      console.error(
        "PDF export failed:",
        err
      );

      setError(
        "Unable to generate the PDF report."
      );
    } finally {
      setDownloading(false);
    }
  }

  return (
    <div className="pdf-report-download">
      <button
        type="button"
        className="pdf-download-button"
        onClick={handleDownload}
        disabled={!analysis || downloading}
        title={
          analysis
            ? "Download the current security analysis as PDF"
            : "Analyze a configuration first"
        }
      >
        <span aria-hidden="true">
          ↓
        </span>

        <span>
          {downloading
            ? "Generating PDF..."
            : "Download PDF"}
        </span>
      </button>

      {error && (
        <span
          className="pdf-download-error"
          role="alert"
        >
          {error}
        </span>
      )}
    </div>
  );
}

export default PdfReportDownload;
