/**
 * Professional, multi-page security configuration review for all platforms.
 *
 * This file is presentation-only. It never executes uploaded configuration
 * text, traverses configuration paths, or invents security conclusions.
 * Only the normalized report returned by the API is rendered as PDF text.
 *
 * Keep jsPDF behind a dynamic import so it loads only when a PDF is requested.
 */
import type { jsPDF } from "jspdf";
import type { NormalizedReport, Severity } from "../api/universal";
import type { F5Phase1Review } from "../api/f5Phase1";

type Pdf = jsPDF;
type RGB = readonly [number, number, number];

const COLORS = {
  navy: [17, 34, 59] as RGB,
  blue: [32, 77, 128] as RGB,
  ink: [35, 49, 65] as RGB,
  muted: [104, 119, 138] as RGB,
  light: [245, 248, 251] as RGB,
  line: [217, 226, 235] as RGB,
  teal: [22, 160, 154] as RGB,
  white: [255, 255, 255] as RGB,
};

const SEVERITIES: readonly Severity[] = [
  "critical", "high", "medium", "low", "info", "unknown",
];
const SEVERITY_COLORS: Record<Severity, RGB> = {
  critical: [185, 28, 28],
  high: [221, 93, 39],
  medium: [184, 119, 20],
  low: [41, 111, 183],
  info: [16, 139, 134],
  unknown: [110, 119, 135],
};

const PAGE_MARGIN = 44;
const MAX_FINDINGS_IN_PDF = 300;
const MAX_OBSERVATIONS_IN_PDF = 80;

function safeText(value: unknown, limit = 2400): string {
  const text = String(value ?? "")
    .replace(/\r\n?/g, "\n")
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, " ")
    .trim();
  if (text.length <= limit) return text;
  return `${text.slice(0, limit)}... [shortened in PDF; full value in JSON]`;
}

function label(value: string): string {
  return value.replace(/_/g, " ").replace(/\b\w/g, (char) => char.toUpperCase());
}

function short(value: unknown, limit: number): string {
  const result = safeText(value, 2000).replace(/\s+/g, " ");
  return result.length <= limit ? result : `${result.slice(0, limit - 3)}...`;
}

function setFill(pdf: Pdf, c: RGB): void {
  pdf.setFillColor(c[0], c[1], c[2]);
}
function setStroke(pdf: Pdf, c: RGB): void {
  pdf.setDrawColor(c[0], c[1], c[2]);
}
function setInk(pdf: Pdf, c: RGB): void {
  pdf.setTextColor(c[0], c[1], c[2]);
}

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

/**
 * The PDF builder is separately exported to support tests and integrations;
 * it does not save files or touch browser APIs.
 */
export function renderNormalizedPdf(
  pdf: Pdf,
  report: NormalizedReport,
  filename: string,
  now: Date = new Date(),
): void {
  const pageWidth = pdf.internal.pageSize.getWidth();
  const pageHeight = pdf.internal.pageSize.getHeight();
  const contentWidth = pageWidth - PAGE_MARGIN * 2;
  const safePlatform = short(report.platform.platform_id, 25).toUpperCase();
  const stamp = now.toISOString().replace(/[-:TZ.]/g, "").slice(0, 14);
  const reference = `NSCA-${safePlatform}-${stamp}`;
  const dateString = `${now.toISOString().replace("T", " ").slice(0, 19)} UTC`;
  let cursor = 0;
  let sectionIndex = 0;
  const bodyBottom = pageHeight - 53;

  pdf.setProperties({
    title: `${short(report.platform.display_name, 95)} - Security Configuration Assessment`,
    subject: "Static network security configuration analysis",
    author: "Network Security Configuration Analyzer",
    keywords: "security, configuration, assessment, static analysis",
  });

  function pageHeader(first = false): void {
    if (first) {
      setFill(pdf, COLORS.navy);
      pdf.rect(0, 0, pageWidth, 120, "F");
      setFill(pdf, COLORS.teal);
      pdf.rect(0, 120, pageWidth, 5, "F");
      pdf.setFont("helvetica", "bold");
      pdf.setFontSize(11);
      setInk(pdf, [103, 218, 212]);
      pdf.text("NETWORK SECURITY", PAGE_MARGIN, 38);
      pdf.setFontSize(20);
      setInk(pdf, COLORS.white);
      pdf.text("CONFIGURATION ASSESSMENT", PAGE_MARGIN, 68);
      pdf.setFont("helvetica", "normal");
      pdf.setFontSize(9);
      setInk(pdf, [211, 226, 236]);
      pdf.text("Evidence-based static review  |  Firewall  /  IDS  /  IPS", PAGE_MARGIN, 90);
      cursor = 151;
    } else {
      pdf.setFont("helvetica", "bold");
      pdf.setFontSize(8);
      setInk(pdf, COLORS.blue);
      pdf.text("NETWORK SECURITY  /  CONFIGURATION REVIEW", PAGE_MARGIN, 32);
      pdf.setFont("helvetica", "normal");
      pdf.setFontSize(7.5);
      setInk(pdf, COLORS.muted);
      pdf.text(short(reference, 48), pageWidth - PAGE_MARGIN, 32, { align: "right" });
      setStroke(pdf, COLORS.line);
      pdf.setLineWidth(0.7);
      pdf.line(PAGE_MARGIN, 42, pageWidth - PAGE_MARGIN, 42);
      cursor = 64;
    }
  }

  function nextPage(): void {
    pdf.addPage();
    pageHeader();
  }

  function ensure(height: number): void {
    if (cursor + height > bodyBottom) nextPage();
  }

  /** Draw wrapped plain text one line at a time, paging safely. */
  function text(
    content: unknown,
    options: {
      size?: number;
      indent?: number;
      color?: RGB;
      bold?: boolean;
      spaceAfter?: number;
      maxChars?: number;
    } = {},
  ): void {
    const size = options.size ?? 9.4;
    const x = PAGE_MARGIN + (options.indent ?? 0);
    const maxWidth = pageWidth - PAGE_MARGIN - x;
    const value = safeText(content, options.maxChars ?? 2400);
    pdf.setFont("helvetica", options.bold ? "bold" : "normal");
    pdf.setFontSize(size);
    setInk(pdf, options.color ?? COLORS.ink);
    const lines = pdf.splitTextToSize(value || " ", maxWidth) as string[];
    const lineHeight = size * 1.48;
    for (const part of lines.length ? lines : [" "]) {
      ensure(lineHeight + 3);
      pdf.text(part, x, cursor);
      cursor += lineHeight;
    }
    cursor += options.spaceAfter ?? 5;
  }

  function section(title: string): void {
    ensure(51);
    cursor += 15;
    sectionIndex += 1;
    pdf.setFont("helvetica", "bold");
    pdf.setFontSize(8.4);
    setInk(pdf, COLORS.teal);
    pdf.text(String(sectionIndex).padStart(2, "0"), PAGE_MARGIN, cursor);
    pdf.setFontSize(12.5);
    setInk(pdf, COLORS.navy);
    pdf.text(title.toUpperCase(), PAGE_MARGIN + 29, cursor);
    cursor += 10;
    setStroke(pdf, COLORS.line);
    pdf.setLineWidth(0.6);
    pdf.line(PAGE_MARGIN, cursor, pageWidth - PAGE_MARGIN, cursor);
    cursor += 21;
  }

  function metricBox(x: number, y: number, width: number, name: string, value: string, accent: RGB): void {
    setFill(pdf, COLORS.light);
    pdf.roundedRect(x, y, width, 59, 6, 6, "F");
    setFill(pdf, accent);
    pdf.rect(x, y, 3, 59, "F");
    pdf.setFont("helvetica", "bold");
    pdf.setFontSize(8);
    setInk(pdf, COLORS.muted);
    pdf.text(name, x + 13, y + 20);
    pdf.setFontSize(13);
    setInk(pdf, COLORS.ink);
    const fitted = pdf.splitTextToSize(short(value, 65), width - 20) as string[];
    pdf.text(fitted[0] || "-", x + 13, y + 42);
  }

  function severityTag(severity: Severity, x: number, y: number): void {
    const color = SEVERITY_COLORS[severity];
    setFill(pdf, color);
    pdf.roundedRect(x, y - 11, 69, 16, 4, 4, "F");
    pdf.setFont("helvetica", "bold");
    pdf.setFontSize(7.4);
    setInk(pdf, COLORS.white);
    pdf.text(severity.toUpperCase(), x + 34.5, y, { align: "center" });
  }

  function evidenceLine(finding: NormalizedReport["findings"][number]): string {
    const bits = [`Code: ${safeText(finding.code, 120)}`, `ID: ${safeText(finding.finding_id, 140)}`];
    if (finding.evidence.line_number !== null) bits.push(`Line: ${finding.evidence.line_number}`);
    if (finding.evidence.rule_id !== null) bits.push(`Rule: ${safeText(finding.evidence.rule_id, 80)}`);
    if (finding.evidence.related_rule_id !== null) bits.push(`Related: ${safeText(finding.evidence.related_rule_id, 80)}`);
    return bits.join("  |  ");
  }

  // Report header and metadata.
  pageHeader(true);
  text(`REPORT REFERENCE  ${reference}`, { bold: true, size: 8.4, color: COLORS.blue, spaceAfter: 9 });
  const metadata = [
    `Platform: ${report.platform.display_name} (${report.platform.family.toUpperCase()})`,
    `Configuration: ${filename}`,
    `Generated: ${dateString}    |    Detection: ${report.platform.detection_method ?? "Unspecified"}`,
  ];
  if (report.platform.hostname) metadata.push(`Hostname: ${report.platform.hostname}`);
  for (const item of metadata) text(item, { size: 9, spaceAfter: 2 });
  cursor += 8;
  setFill(pdf, COLORS.light);
  ensure(33);
  pdf.roundedRect(PAGE_MARGIN, cursor - 9, contentWidth, 33, 5, 5, "F");
  pdf.setFont("helvetica", "normal");
  pdf.setFontSize(8.2);
  setInk(pdf, COLORS.muted);
  pdf.text("Scope: Uploaded configuration text only. Findings reflect implemented checks, not a full security audit.", PAGE_MARGIN + 11, cursor + 11);
  cursor += 41;

  section("Executive summary");
  ensure(80);
  const gap = 9;
  const boxWidth = (contentWidth - gap * 3) / 4;
  const metrics = [
    ["FINDINGS", String(report.summary.total_findings), COLORS.blue],
    ["RISK LEVEL", report.summary.risk_level ?? "Not assigned", COLORS.blue],
    ["SECURITY SCORE", report.summary.security_score === null ? "Not scored" : `${report.summary.security_score}/100`, COLORS.teal],
    ["REVIEW SCORE", report.assessment ? `${report.assessment.review_score.value}/100*` : "Not available", COLORS.teal],
  ] as const;
  metrics.forEach(([name, value, color], index) => metricBox(
    PAGE_MARGIN + index * (boxWidth + gap), cursor - 8, boxWidth, name, value, color,
  ));
  cursor += 75;
  if (report.assessment) {
    text("* Review score is provisional, based on implemented checks, and may be capped for missing coverage.", {
      size: 8.1, color: COLORS.muted, spaceAfter: 4,
    });
  }
  text("SEVERITY BREAKDOWN", { size: 8.7, bold: true, color: COLORS.navy, spaceAfter: 9 });
  ensure(51);
  const sevWidth = (contentWidth - 5 * 7) / 6;
  SEVERITIES.forEach((severity, i) => {
    const x = PAGE_MARGIN + i * (sevWidth + 7);
    const count = report.summary.severity_counts[severity] ?? 0;
    setFill(pdf, COLORS.light);
    pdf.roundedRect(x, cursor - 7, sevWidth, 43, 5, 5, "F");
    setFill(pdf, SEVERITY_COLORS[severity]);
    pdf.rect(x, cursor - 7, sevWidth, 3, "F");
    pdf.setFont("helvetica", "bold");
    pdf.setFontSize(7.7);
    setInk(pdf, COLORS.muted);
    pdf.text(label(severity), x + 7, cursor + 12);
    pdf.setFontSize(12.5);
    setInk(pdf, COLORS.ink);
    pdf.text(String(count), x + 7, cursor + 28);
  });
  cursor += 53;

  const findings = report.findings.slice(0, MAX_FINDINGS_IN_PDF);
  section("Findings register");
  if (!findings.length) {
    text("No findings were produced by the implemented checks.", { bold: true });
    text("Important: zero detected findings does not establish that the configuration or deployment is secure.", {
      color: COLORS.muted, size: 8.5,
    });
  } else {
    text("Reference each item by its serial number (F-001, F-002, ...). Full descriptions follow.", {
      color: COLORS.muted, size: 8.5,
    });
    for (let i = 0; i < findings.length; i += 1) {
      const finding = findings[i];
      ensure(27);
      const top = cursor - 10;
      if (i % 2 === 0) {
        setFill(pdf, COLORS.light);
        pdf.roundedRect(PAGE_MARGIN, top, contentWidth, 27, 3, 3, "F");
      }
      pdf.setFont("helvetica", "bold");
      pdf.setFontSize(8.3);
      setInk(pdf, COLORS.blue);
      pdf.text(`F-${String(i + 1).padStart(3, "0")}`, PAGE_MARGIN + 8, top + 18);
      severityTag(finding.severity, PAGE_MARGIN + 58, top + 17);
      pdf.setFont("helvetica", "normal");
      pdf.setFontSize(8.3);
      setInk(pdf, COLORS.ink);
      const titleWidth = contentWidth - 148;
      const title = pdf.splitTextToSize(short(finding.title, 165), titleWidth) as string[];
      pdf.text(title[0] || "Untitled finding", PAGE_MARGIN + 142, top + 17);
      cursor += 28;
    }
    cursor += 5;
  }
  if (report.findings.length > findings.length) {
    text(`PDF shows the first ${findings.length} of ${report.findings.length} findings. Export JSON for the complete set.`, {
      bold: true, color: COLORS.blue, size: 9,
    });
  }

  if (findings.length) {
    section("Finding details and recommendations");
    findings.forEach((finding, i) => {
      ensure(96);
      const top = cursor - 9;
      setFill(pdf, COLORS.light);
      pdf.roundedRect(PAGE_MARGIN, top, contentWidth, 43, 5, 5, "F");
      setFill(pdf, SEVERITY_COLORS[finding.severity]);
      pdf.rect(PAGE_MARGIN, top, 4, 43, "F");
      pdf.setFont("helvetica", "bold");
      pdf.setFontSize(10.4);
      setInk(pdf, COLORS.navy);
      pdf.text(`F-${String(i + 1).padStart(3, "0")}`, PAGE_MARGIN + 11, top + 19);
      severityTag(finding.severity, PAGE_MARGIN + 66, top + 19);
      pdf.setFont("helvetica", "normal");
      pdf.setFontSize(8.2);
      setInk(pdf, COLORS.muted);
      pdf.text(short(finding.code, 50), PAGE_MARGIN + 11, top + 34);
      cursor += 53;
      text(finding.title, { bold: true, size: 10.2, spaceAfter: 8 });
      text("DESCRIPTION", { bold: true, color: COLORS.blue, size: 8, spaceAfter: 2 });
      text(finding.description, { indent: 10, size: 9.1, spaceAfter: 8 });
      if (finding.recommendation) {
        text("RECOMMENDATION", { bold: true, color: COLORS.blue, size: 8, spaceAfter: 2 });
        text(finding.recommendation, { indent: 10, size: 9.1, spaceAfter: 8 });
      }
      text("SOURCE REFERENCE", { bold: true, color: COLORS.blue, size: 8, spaceAfter: 2 });
      text(evidenceLine(finding), { indent: 10, color: COLORS.muted, size: 8.1, spaceAfter: 6 });
      ensure(15);
      setStroke(pdf, COLORS.line);
      pdf.line(PAGE_MARGIN, cursor, pageWidth - PAGE_MARGIN, cursor);
      cursor += 14;
    });
  }

  if (report.assessment) {
    section("Configuration review evidence");
    const assessment = report.assessment;
    text(`Provisional review score: ${assessment.review_score.value}/${assessment.review_score.maximum}   |   Priority: ${label(assessment.review_score.priority)}`, {
      bold: true, size: 9.6,
    });
    text(assessment.review_score.interpretation, { color: COLORS.muted, size: 8.7 });
    const observations = assessment.observations.slice(0, MAX_OBSERVATIONS_IN_PDF);
    observations.forEach((obs, i) => {
      ensure(55);
      text(`O-${String(i + 1).padStart(2, "0")}  ${obs.title}  [${label(obs.status)}]`, {
        bold: true, size: 9.4, color: COLORS.navy, spaceAfter: 2,
      });
      text(obs.detail, { indent: 12, size: 8.8, spaceAfter: 1 });
      text(`Evidence field: ${obs.evidence.source_field}${obs.evidence.line_number === null ? "" : `  |  Line ${obs.evidence.line_number}`}`, {
        indent: 12, color: COLORS.muted, size: 8, spaceAfter: 10,
      });
    });
    if (assessment.observations.length > observations.length) {
      text(`${assessment.observations.length - observations.length} more observations omitted from PDF; see JSON.`, {
        color: COLORS.muted, size: 8.2,
      });
    }
    text(assessment.notice, { size: 8.4, color: COLORS.muted });
  }

  if (report.object_resolution) {
    section("Network object resolution and policy selectors");
    text("Limited IPv4 object expansion, not verified effective policy. Results are supplemental and do not affect existing findings or scores.", {
      size: 8.5, color: COLORS.muted, spaceAfter: 7,
    });
    const resolved = report.object_resolution;
    text(`Objects resolved: ${resolved.summary.definitions_resolved} | Unresolved: ${resolved.summary.definitions_unresolved} | Rules parsed: ${resolved.summary.rules_with_resolved_selectors} | Correlation candidates: ${resolved.summary.candidate_pairs}`, {
      size: 8.7, spaceAfter: 8,
    });
    resolved.pairs.slice(0, 30).forEach((pair) => {
      ensure(65);
      text(`${pair.correlation_id}  ${pair.kind.replace(/_/g, " ")}`, {
        bold: true, size: 9.4, color: COLORS.navy, spaceAfter: 4,
      });
      text(pair.explanation, { indent: 10, size: 8.3, spaceAfter: 4 });
      text(`Source lines: ${pair.evidence.related_line_number}, ${pair.evidence.line_number} | ${pair.order_status.replace(/_/g, " ")}`, {
        indent: 10, size: 8.1, color: COLORS.muted, spaceAfter: 4,
      });
      text(`Objects: ${pair.resolved_object_references.join(", ") || "none"}`, {
        indent: 10, size: 8.1, spaceAfter: 4,
      });
      text(`Review: ${pair.recommendation}`, { indent: 10, size: 8.3, spaceAfter: 9 });
    });
    resolved.limitations.slice(0, 4).forEach((limit) => {
      text(`Scope: ${limit}`, { size: 8, color: COLORS.muted, spaceAfter: 4 });
    });
    if (resolved.summary.truncated) {
      text("Object resolution was truncated; the assessment is incomplete.", {
        size: 8.5, color: COLORS.muted, spaceAfter: 5,
      });
    }
  }

  if (report.object_assurance) {
    section("Object reference integrity");
    const review = report.object_assurance;
    text("Upload-scoped cross-reference review, not proof of effective device policy. Observations do not affect the security score.", {
      size: 8.5, color: COLORS.muted, spaceAfter: 7,
    });
    text(`References checked: ${review.summary.references_checked} | Not defined in upload: ${review.summary.missing_in_upload} | Cycles: ${review.summary.cycles} | Repeated definitions: ${review.summary.repeated_definitions}`, {
      size: 8.6, spaceAfter: 8,
    });
    review.observations.slice(0, 30).forEach((item) => {
      ensure(62);
      text(`${item.reference}  ${item.kind.replace(/_/g, " ")}  | line ${item.line_number}`, {
        bold: true, size: 9.3, color: COLORS.navy, spaceAfter: 3,
      });
      text(`Object: ${item.object_name} | ${item.explanation}`, {
        indent: 10, size: 8.3, spaceAfter: 4,
      });
      if (item.related_line_numbers.length) {
        text(`Related lines: ${item.related_line_numbers.join(", ")}`, {
          indent: 10, size: 8, color: COLORS.muted, spaceAfter: 3,
        });
      }
      text(`Review: ${item.recommendation}`, { indent: 10, size: 8.2, spaceAfter: 8 });
    });
    if (review.observations.length > 30 || review.summary.observations_omitted > 0) {
      text("Additional observations were omitted from the PDF; consult the dashboard for the available bounded list.", {
        size: 8, color: COLORS.muted, spaceAfter: 5,
      });
    }
    if (review.summary.incomplete) {
      text("The uploaded source or processing was incomplete; absence claims cannot be established.", {
        size: 8.4, color: COLORS.muted, spaceAfter: 5,
      });
    }
    review.limitations.slice(0, 3).forEach((item) => {
      text(`Scope: ${item}`, { size: 8.1, color: COLORS.muted, spaceAfter: 4 });
    });
  }

  const f5Phase1Review = (report as NormalizedReport & { f5_phase1_review?: F5Phase1Review }).f5_phase1_review;
  if (f5Phase1Review) {
    section("F5 BIG-IP Phases 1 + 2 - Detailed technical evidence");
    text("Static F5-001/002/003/007 checks plus F5-004 logging associations, F5-005 UCS evidence, F5-006 update evidence and F5-008 iRule inventory. No live F5 or UCS inspection.", {
      size: 8.5, color: COLORS.muted, spaceAfter: 7,
    });
    text(`Profiles: ${f5Phase1Review.total_profiles} | Virtual servers: ${f5Phase1Review.total_virtual_servers} | Findings: ${f5Phase1Review.findings.length} | Review observations: ${f5Phase1Review.review_observations.length}`, {
      size: 9, bold: true, spaceAfter: 7,
    });
    const printF5Items = (items: F5Phase1Review["findings"], heading: string) => {
      text(heading, { bold: true, color: COLORS.blue, size: 9.1, spaceAfter: 6 });
      if (!items.length) text("No items returned in this category.", { size: 8.5, color: COLORS.muted });
      items.slice(0, 500).forEach((item) => {
        ensure(68);
        text(`${item.code} | ${item.title} | ${item.severity.toUpperCase()}`, { bold: true, size: 9.1, spaceAfter: 4 });
        text(`Object: ${item.affected_object} (${item.object_type}) | Source line: ${item.line_number ?? "not available"} | Confidence: ${item.confidence}`, {
          size: 8.2, color: COLORS.muted, spaceAfter: 3,
        });
        text(`Setting: ${item.evidence.setting} | Observed: ${item.evidence.observed}`, { size: 8.4, indent: 8, spaceAfter: 4 });
        if (item.associated_virtual_servers.length) {
          text(`Associated virtual servers: ${item.associated_virtual_servers.join(", ")}`, {
            size: 8.1, indent: 8, spaceAfter: 4,
          });
        }
        text(item.description, { indent: 8, size: 8.5, spaceAfter: 4 });
        text(`Recommendation: ${item.recommendation}`, { indent: 8, size: 8.5, spaceAfter: 5 });
        text(`Limitation: ${item.limitations}`, { indent: 8, color: COLORS.muted, size: 8, spaceAfter: 8 });
      });
      if (items.length > 500) text("Further F5 records omitted because the PDF safety limit was reached; refer to the complete JSON export.", {
        color: COLORS.muted, size: 8.2,
      });
    };
    printF5Items(f5Phase1Review.findings, "CONFIGURATION FINDINGS");
    printF5Items(f5Phase1Review.review_observations, "POLICY REVIEW / INSUFFICIENT EVIDENCE (NOT CONFIRMED VULNERABILITIES)");
    text("F5 PHASES 1 + 2 COVERAGE LIMITATIONS", { bold: true, color: COLORS.blue, size: 9, spaceAfter: 5 });
    f5Phase1Review.limitations.forEach((item) => text(`Limitation: ${item}`, {
      size: 8.2, color: COLORS.muted, spaceAfter: 5,
    }));
  }

  if (report.input_security_review) {
    const inputSecurity = report.input_security_review;
    section("Upload input validation — Detailed evidence");
    text("Validation occurred before analysis at the API-011.6 endpoint. These are bounded text/file checks, NOT a claim that the configuration is safe or every API route is protected.", {
      color: COLORS.muted, size: 8.3, spaceAfter: 7,
    });
    text(`Status: ${label(inputSecurity.status)} | Bytes: ${inputSecurity.summary.byte_count} | Lines: ${inputSecurity.summary.line_count} | Checks passed: ${inputSecurity.summary.checks_passed}`, {
      size: 8.2, spaceAfter: 6,
    });
    text(`Input SHA-256: ${inputSecurity.sha256}`, { size: 7.7, spaceAfter: 7 });
    inputSecurity.checks.forEach((check) => {
      text(`${label(check.name)}: ${label(check.result)}`, { size: 8.1, indent: 10, spaceAfter: 3 });
    });
    text("VALIDATION SCOPE AND LIMITATIONS", { bold: true, color: COLORS.blue, size: 8.8, spaceAfter: 4 });
    inputSecurity.limitations.forEach((item) => text(`Limitation: ${item}`, {
      color: COLORS.muted, size: 8, spaceAfter: 5,
    }));
  }

  section("Assessment coverage");
  text("'Assessed' means the implemented checks ran. It does not mean the configuration passed a complete security audit.", {
    size: 8.4, color: COLORS.muted, spaceAfter: 9,
  });
  report.coverage.domains.forEach((domain) => {
    ensure(23);
    const assessed = domain.status === "assessed";
    const statusColor: RGB = assessed ? COLORS.teal : SEVERITY_COLORS.unknown;
    setFill(pdf, statusColor);
    pdf.circle(PAGE_MARGIN + 6, cursor - 3, 3, "F");
    pdf.setFont("helvetica", "normal");
    pdf.setFontSize(8.7);
    setInk(pdf, COLORS.ink);
    pdf.text(short(label(domain.domain), 80), PAGE_MARGIN + 17, cursor);
    pdf.setFont("helvetica", "bold");
    pdf.setFontSize(8.2);
    setInk(pdf, statusColor);
    pdf.text(assessed ? "ASSESSED" : "NOT ASSESSED", pageWidth - PAGE_MARGIN, cursor, { align: "right" });
    cursor += 22;
  });
  if (report.coverage.limitations.length) {
    section("Scope limitations");
    report.coverage.limitations.forEach((limitation, i) => {
      text(`${i + 1}. ${limitation}`, { indent: 6, size: 8.9, spaceAfter: 7 });
    });
  }
  if (report.warnings.length) {
    section("Parser and analysis warnings");
    report.warnings.forEach((warning, i) => {
      text(`${i + 1}. ${warning}`, { indent: 6, size: 8.9, spaceAfter: 7 });
    });
  }
  section("Report interpretation");
  text("This document describes findings from static analysis of the uploaded configuration. An absence of findings must not be interpreted as proof of security.", {
    size: 8.8,
  });
  text("Referenced files, effective runtime policy, deployed rules, network traffic, and vendor features outside the implemented checks may not have been assessed.", {
    size: 8.8,
  });
  text(`Normalized report schema: ${report.schema_version}. Report reference identifies this PDF export, not a server-side audit record.`, {
    size: 8.2, color: COLORS.muted,
  });

  // Finish headers/footers after all pages exist so page totals are accurate.
  const totalPages = pdf.internal.getNumberOfPages();
  for (let p = 1; p <= totalPages; p += 1) {
    pdf.setPage(p);
    setStroke(pdf, COLORS.line);
    pdf.setLineWidth(0.6);
    pdf.line(PAGE_MARGIN, pageHeight - 42, pageWidth - PAGE_MARGIN, pageHeight - 42);
    pdf.setFont("helvetica", "normal");
    pdf.setFontSize(7.4);
    setInk(pdf, COLORS.muted);
    pdf.text(short(reference, 64), PAGE_MARGIN, pageHeight - 26);
    pdf.text(`Page ${p} of ${totalPages}`, pageWidth - PAGE_MARGIN, pageHeight - 26, { align: "right" });
  }
}

/** Invoke from a real user click; the PDF dependency is loaded on demand. */
export async function downloadNormalizedPdf(report: NormalizedReport, filename: string): Promise<void> {
  const { jsPDF } = await import("jspdf");
  const pdf = new jsPDF({ unit: "pt", format: "a4", compress: true });
  renderNormalizedPdf(pdf, report, filename);
  pdf.save(`${normalizedFilename(filename)}.${normalizedFilename(report.platform.platform_id)}.security-report.pdf`);
}
