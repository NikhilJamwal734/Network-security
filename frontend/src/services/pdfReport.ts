
import type { AnalysisResponse } from "./firewallApi";

/* ============================================================
   TYPES
   ============================================================ */

type DataRecord = Record<string, unknown>;

type PdfDocument = import("jspdf").jsPDF;

/* ============================================================
   FORMATTING HELPERS
   ============================================================ */

function toRecord(value: unknown): DataRecord {
  if (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value)
  ) {
    return value as DataRecord;
  }

  return { value };
}

function formatValue(value: unknown): string {
  if (value === null || value === undefined) {
    return "N/A";
  }

  if (typeof value === "boolean") {
    return value ? "Yes" : "No";
  }

  if (
    typeof value === "string" ||
    typeof value === "number"
  ) {
    return String(value);
  }

  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

function firstAvailable(
  record: DataRecord,
  keys: string[]
): string {
  for (const key of keys) {
    const value = record[key];

    if (
      value !== null &&
      value !== undefined &&
      value !== ""
    ) {
      return formatValue(value);
    }
  }

  return "";
}

function formatLabel(key: string): string {
  return key
    .replace(/_/g, " ")
    .replace(/\b\w/g, (letter) =>
      letter.toUpperCase()
    );
}

function safeFileName(value: string): string {
  return (
    value
      .replace(/\.[^.]+$/, "")
      .replace(/[^a-zA-Z0-9_-]+/g, "_")
      .replace(/^_+|_+$/g, "")
      .slice(0, 60) || "firewall"
  );
}

/*
 * Standard jsPDF fonts have limited Unicode coverage.
 * Convert common punctuation to ASCII to avoid
 * missing glyphs in the generated document.
 */
function pdfSafeText(value: string): string {
  return value
    .replace(/[\u2018\u2019]/g, "'")
    .replace(/[\u201C\u201D]/g, '"')
    .replace(/[\u2013\u2014]/g, "-")
    .replace(/\u2022/g, "*")
    .replace(/\u2026/g, "...")
    .replace(/\u2192/g, "->")
    .replace(/\u2190/g, "<-")
    .replace(/\u00A0/g, " ")
    .normalize("NFKD")
    .replace(/[^\x20-\x7E\n\r\t]/g, "?");
}

/* ============================================================
   PDF GENERATOR
   ============================================================ */

export async function downloadAnalysisPdf(
  analysis: AnalysisResponse,
  originalFilename?: string | null
): Promise<void> {
  /*
   * Load jsPDF only when the user downloads a report.
   * This avoids adding the entire library to the
   * application's initial JavaScript bundle.
   */
  const { jsPDF } = await import("jspdf");

  const doc: PdfDocument = new jsPDF({
    orientation: "portrait",
    unit: "mm",
    format: "a4",
  });

  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();

  const margin = 18;
  const contentWidth = pageWidth - margin * 2;
  const bottomLimit = pageHeight - 20;

  let y = 24;

  const colors = {
    dark: [15, 23, 42] as const,
    blue: [37, 99, 235] as const,
    gray: [100, 116, 139] as const,
    red: [220, 38, 38] as const,
    green: [22, 163, 74] as const,
  };

  /* ==========================================================
     PAGE MANAGEMENT
     ========================================================== */

  function newPage(): void {
    doc.addPage();
    y = 24;
  }

  function ensureSpace(requiredHeight: number): void {
    if (y + requiredHeight > bottomLimit) {
      newPage();
    }
  }

  function writeWrapped(
    value: string,
    options?: {
      fontSize?: number;
      bold?: boolean;
      indent?: number;
      color?: readonly [number, number, number];
      lineHeight?: number;
    }
  ): void {
    const fontSize = options?.fontSize ?? 9;
    const bold = options?.bold ?? false;
    const indent = options?.indent ?? 0;
    const lineHeight = options?.lineHeight ?? 5;

    const color = options?.color ?? colors.dark;

    doc.setFont("helvetica", bold ? "bold" : "normal");
    doc.setFontSize(fontSize);
    doc.setTextColor(color[0], color[1], color[2]);

    const safeValue = pdfSafeText(value);

    const availableWidth = contentWidth - indent;

    const lines = doc.splitTextToSize(
      safeValue,
      availableWidth
    ) as string[];

    for (const line of lines) {
      ensureSpace(lineHeight);

      doc.text(
        line,
        margin + indent,
        y
      );

      y += lineHeight;
    }
  }

  function writeSection(title: string): void {
    ensureSpace(16);

    y += 6;

    doc.setDrawColor(
      colors.blue[0],
      colors.blue[1],
      colors.blue[2]
    );

    doc.setLineWidth(0.6);

    doc.line(margin, y, pageWidth - margin, y);

    y += 8;

    writeWrapped(title, {
      fontSize: 14,
      bold: true,
      color: colors.blue,
      lineHeight: 7,
    });

    y += 3;
  }

  function writeSubheading(title: string): void {
    ensureSpace(14);

    y += 4;

    writeWrapped(title, {
      fontSize: 11,
      bold: true,
      lineHeight: 6,
    });

    y += 2;
  }

  function writeField(
    label: string,
    value: unknown
  ): void {
    writeWrapped(
      `${label}: ${formatValue(value)}`,
      {
        fontSize: 9,
        lineHeight: 5,
      }
    );
  }

  function writeRecord(
    record: DataRecord
  ): void {
    for (const [key, value] of Object.entries(record)) {
      writeField(formatLabel(key), value);
    }
  }

  function writeRecordCollection(
    title: string,
    records: unknown[]
  ): void {
    writeSection(
      `${title} (${records.length})`
    );

    if (records.length === 0) {
      writeWrapped("No records found.");
      return;
    }

    records.forEach((item, index) => {
      const record = toRecord(item);

      const displayName =
        firstAvailable(record, [
          "name",
          "nameif",
          "id",
          "interface",
          "destination",
        ]) || `${title} ${index + 1}`;

      writeSubheading(
        `${index + 1}. ${displayName}`
      );

      writeRecord(record);

      y += 3;
    });
  }

  /* ==========================================================
     DOCUMENT METADATA
     ========================================================== */

  const reportDate = new Date();

  const dateText = reportDate.toLocaleString();

  const sourceName =
    originalFilename ||
    analysis.hostname ||
    "firewall";

  doc.setProperties({
    title: `${analysis.hostname} - Security Report`,
    subject: "Cisco ASA Firewall Security Analysis",
    author: "Firewall Configuration Analyzer",
    keywords: "Firewall, Security, Cisco ASA, Analysis",
    creator: "Firewall Configuration Analyzer",
  });

  /* ==========================================================
     REPORT COVER / HEADING
     ========================================================== */

  doc.setFillColor(
    colors.dark[0],
    colors.dark[1],
    colors.dark[2]
  );

  doc.rect(
    0,
    0,
    pageWidth,
    43,
    "F"
  );

  doc.setTextColor(255, 255, 255);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(19);

  doc.text(
    "FIREWALL SECURITY REPORT",
    margin,
    22
  );

  doc.setFont("helvetica", "normal");
  doc.setFontSize(10);

  doc.text(
    pdfSafeText(analysis.hostname),
    margin,
    32
  );

  y = 54;

  writeSection("Firewall Information");

  writeField("Hostname", analysis.hostname);
  writeField("Vendor", analysis.vendor);
  writeField("Source File", sourceName);
  writeField("Generated", dateText);

  /* ==========================================================
     SECURITY SUMMARY
     ========================================================== */

  writeSection("Security Summary");

  writeField(
    "Security Score",
    `${analysis.summary.security_score}/100`
  );

  writeField(
    "Risk Level",
    analysis.summary.risk_level
  );

  writeField(
    "Total Findings",
    analysis.summary.total_findings
  );

  writeSection("Severity Breakdown");

  writeField(
    "Critical",
    analysis.summary.critical_findings
  );

  writeField(
    "High",
    analysis.summary.high_findings
  );

  writeField(
    "Medium",
    analysis.summary.medium_findings
  );

  writeField(
    "Low",
    analysis.summary.low_findings
  );

  /* ==========================================================
     CONFIGURATION INVENTORY
     ========================================================== */

  writeSection("Configuration Inventory");

  const configuration = analysis.configuration;

  writeField(
    "Firewall Rules",
    configuration.rules.length
  );

  writeField(
    "Network Objects",
    configuration.network_objects.length
  );

  writeField(
    "Service Objects",
    configuration.service_objects.length
  );

  writeField(
    "NAT Rules",
    configuration.nat_rules.length
  );

  writeField(
    "Routes",
    configuration.routes.length
  );

  writeField(
    "Interfaces",
    configuration.interfaces.length
  );

  /* ==========================================================
     SECURITY FINDINGS
     ========================================================== */

  const findings = analysis.findings ?? [];

  writeSection(
    `Security Findings (${findings.length})`
  );

  if (findings.length === 0) {
    writeWrapped(
      "No security findings were returned by the analyzer."
    );
  }

  findings.forEach((finding, index) => {
    const record = toRecord(finding);

    const findingId =
      firstAvailable(record, [
        "check_id",
        "finding_id",
        "rule_id",
        "id",
      ]) || `Finding ${index + 1}`;

    const title =
      firstAvailable(record, [
        "title",
        "name",
        "check_name",
        "summary",
      ]) || findingId;

    const severity =
      firstAvailable(record, [
        "severity",
        "risk_level",
        "level",
      ]) || "UNKNOWN";

    ensureSpace(23);

    writeSubheading(
      `${index + 1}. ${findingId} - ${title}`
    );

    writeField("Severity", severity);

    const knownFields = new Set([
      "check_id",
      "finding_id",
      "rule_id",
      "id",
      "title",
      "name",
      "check_name",
      "summary",
      "severity",
      "risk_level",
      "level",
    ]);

    const description = firstAvailable(record, [
      "description",
      "message",
      "details",
      "reason",
    ]);

    if (description) {
      writeField(
        "Description",
        description
      );
    }

    const recommendation = firstAvailable(record, [
      "recommendation",
      "remediation",
      "suggestion",
      "recommended_action",
      "fix",
    ]);

    if (recommendation) {
      writeField(
        "Recommendation",
        recommendation
      );
    }

    /*
     * Include every remaining finding property.
     * This preserves additional information returned
     * by the analyzer.
     */
    const alreadyDisplayed = new Set([
      ...knownFields,
      "description",
      "message",
      "details",
      "reason",
      "recommendation",
      "remediation",
      "suggestion",
      "recommended_action",
      "fix",
    ]);

    for (const [key, value] of Object.entries(record)) {
      if (!alreadyDisplayed.has(key)) {
        writeField(formatLabel(key), value);
      }
    }

    y += 5;
  });

  /* ==========================================================
     PARSED CONFIGURATION DETAILS
     ========================================================== */

  writeRecordCollection(
    "Interfaces",
    configuration.interfaces
  );

  writeRecordCollection(
    "Firewall Rules",
    configuration.rules
  );

  writeRecordCollection(
    "Network Objects",
    configuration.network_objects
  );

  writeRecordCollection(
    "Service Objects",
    configuration.service_objects
  );

  writeRecordCollection(
    "NAT Rules",
    configuration.nat_rules
  );

  writeRecordCollection(
    "Routes",
    configuration.routes
  );

  /* ==========================================================
     HEADERS / FOOTERS
     ========================================================== */

  const pageCount = doc.getNumberOfPages();

  for (let page = 1; page <= pageCount; page++) {
    doc.setPage(page);

    doc.setDrawColor(203, 213, 225);
    doc.setLineWidth(0.2);

    doc.line(
      margin,
      pageHeight - 15,
      pageWidth - margin,
      pageHeight - 15
    );

    doc.setFont("helvetica", "normal");
    doc.setFontSize(8);

    doc.setTextColor(
      colors.gray[0],
      colors.gray[1],
      colors.gray[2]
    );

    doc.text(
      "Firewall Configuration Analyzer - Confidential",
      margin,
      pageHeight - 10
    );

    doc.text(
      `Page ${page} of ${pageCount}`,
      pageWidth - margin,
      pageHeight - 10,
      { align: "right" }
    );
  }

  /* ==========================================================
     DOWNLOAD
     ========================================================== */

  const date = reportDate
    .toISOString()
    .slice(0, 10);

  const downloadName =
    `${safeFileName(sourceName)}_security_report_${date}.pdf`;

  doc.save(downloadName);
}
