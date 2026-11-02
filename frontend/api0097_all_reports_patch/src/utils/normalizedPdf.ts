/** Create a multi-page PDF using the normalized report for ANY registered platform.
 * All uploaded-configuration content is treated as plain text, never as HTML.
 * The output describes only checks present in the normalized report.
 */
import { jsPDF } from "jspdf";
import type { NormalizedReport } from "../api/universal";

const SEVERITIES = ["critical", "high", "medium", "low", "info", "unknown"] as const;

export function normalizedFilename(name: string): string {
  const base = name.trim().replace(/[^a-zA-Z0-9._-]/g, "_").slice(0, 80);
  return base || "configuration";
}

export function downloadNormalizedJson(report: NormalizedReport, filename: string): void {
  const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `${normalizedFilename(filename)}.normalized.json`;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function downloadNormalizedPdf(report: NormalizedReport, filename: string): void {
  const doc = new jsPDF({ unit: "pt", format: "a4" });
  const w = doc.internal.pageSize.getWidth();
  const h = doc.internal.pageSize.getHeight();
  const left = 46;
  const maxWidth = w - left * 2;
  const bottom = h - 52;
  let y = 52;
  let page = 1;

  const footer = () => {
    doc.setFont("helvetica", "normal");
    doc.setFontSize(8);
    doc.setTextColor(105, 115, 130);
    doc.text("Static configuration analysis - limited to implemented checks", left, h - 27);
    doc.text(`Page ${page}`, w - left, h - 27, { align: "right" });
  };
  const nextPage = () => {
    footer();
    doc.addPage();
    page += 1;
    y = 48;
  };
  const ensure = (required: number) => {
    if (y + required > bottom) nextPage();
  };
  const line = (value: unknown, options: { bold?: boolean; size?: number; indent?: number; gap?: number } = {}) => {
    const size = options.size ?? 10;
    const indent = options.indent ?? 0;
    const text = String(value ?? "").replace(/\r\n?/g, "\n");
    doc.setFont("helvetica", options.bold ? "bold" : "normal");
    doc.setFontSize(size);
    doc.setTextColor(options.bold ? 26 : 52, options.bold ? 40 : 64, options.bold ? 64 : 85);
    // Split and constrain arbitrary untrusted config text to the page width.
    const wrapped = doc.splitTextToSize(text, maxWidth - indent) as string[];
    const height = size * 1.38;
    for (const row of wrapped.length ? wrapped : [""]) {
      ensure(height + 2);
      doc.text(row, left + indent, y);
      y += height;
    }
    y += options.gap ?? 3;
  };
  const heading = (value: string) => {
    ensure(40);
    y += 11;
    line(value, { bold: true, size: 14, gap: 10 });
  };

  doc.setProperties({ title: `${report.platform.display_name} - normalized security report` });
  line("NETWORK SECURITY CONFIGURATION ANALYSIS", { bold: true, size: 17, gap: 11 });
  line(`Platform: ${report.platform.display_name} (${report.platform.family.toUpperCase()})`);
  line(`File: ${filename}`);
  line(`Generated: ${new Date().toLocaleString()}`);
  line(`Detection: ${report.platform.detection_method ?? "Unknown"}`);
  if (report.platform.hostname) line(`Hostname: ${report.platform.hostname}`);
  line(`Schema: ${report.schema_version}`);

  heading("Assessment summary");
  line(`Findings: ${report.summary.total_findings}`);
  line(`Security score: ${report.summary.security_score === null ? "Not scored" : `${report.summary.security_score}/100`}`);
  line(`Risk level: ${report.summary.risk_level ?? "Not assigned"}`);
  for (const severity of SEVERITIES) {
    line(`${severity[0].toUpperCase()}${severity.slice(1)}: ${report.summary.severity_counts[severity]}`, { indent: 12 });
  }

  heading("Security findings");
  if (!report.findings.length) line("No findings were produced by the implemented checks.");
  report.findings.forEach((finding, i) => {
    ensure(65);
    line(`${i + 1}. [${finding.severity.toUpperCase()}] ${finding.title}`, { bold: true, size: 11, gap: 2 });
    line(`Code: ${finding.code}  |  ID: ${finding.finding_id}`, { size: 9, indent: 10 });
    line(finding.description, { indent: 10 });
    if (finding.recommendation) line(`Recommendation: ${finding.recommendation}`, { indent: 10 });
    if (finding.evidence.line_number !== null) line(`Line: ${finding.evidence.line_number}`, { indent: 10, size: 9 });
    if (finding.evidence.rule_id !== null) line(`Rule ID: ${finding.evidence.rule_id}`, { indent: 10, size: 9 });
    y += 5;
  });

  heading("Analysis coverage");
  line("'Assessed' means the implemented checks ran, not that the configuration is fully secure.", { size: 9 });
  report.coverage.domains.forEach((d) => line(`${d.domain.replace(/_/g, " ")}: ${d.status.replace(/_/g, " ")}`, { indent: 10 }));
  if (report.coverage.limitations.length) {
    heading("Limitations");
    report.coverage.limitations.forEach((l) => line(`- ${l}`, { indent: 10 }));
  }
  if (report.warnings.length) {
    heading("Parser warnings");
    report.warnings.forEach((w) => line(`- ${w}`, { indent: 10 }));
  }
  footer();
  doc.save(`${normalizedFilename(filename)}.${report.platform.platform_id}.security-report.pdf`);
}
