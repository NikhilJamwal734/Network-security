
import type { AnalysisResponse } from "./firewallApi";

/**
 * Convert a name into a safe download filename.
 */
function safeFileName(value: string): string {
  return (
    value
      .replace(/\.[^.]+$/, "")
      .replace(/[^a-zA-Z0-9_-]+/g, "_")
      .replace(/^_+|_+$/g, "")
      .slice(0, 60) || "firewall"
  );
}

/**
 * Download the current firewall analysis as JSON.
 *
 * The exported structure matches the analysis data
 * already returned by the FastAPI backend.
 */
export function downloadAnalysisJson(
  analysis: AnalysisResponse,
  originalFilename?: string | null
): void {
  const json = JSON.stringify(analysis, null, 2);

  const blob = new Blob([json], {
    type: "application/json;charset=utf-8",
  });

  const url = URL.createObjectURL(blob);

  const sourceName =
    originalFilename ||
    analysis.hostname ||
    "firewall";

  const baseName = safeFileName(sourceName);

  const date = new Date().toISOString().slice(0, 10);

  const downloadName =
    `${baseName}_security_report_${date}.json`;

  const link = document.createElement("a");

  link.href = url;
  link.download = downloadName;

  document.body.appendChild(link);

  try {
    link.click();
  } finally {
    link.remove();

    // Allow the browser to start the download before
    // releasing the temporary object URL.
    window.setTimeout(() => {
      URL.revokeObjectURL(url);
    }, 1000);
  }
}
