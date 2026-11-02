import { useState } from "react";
import type { NormalizedReport, Severity } from "../api/universal";
import { downloadNormalizedPdf } from "../utils/normalizedPdf";
import "./ExecutiveDashboardSummary.css";

type Props = { report: NormalizedReport; filename: string };

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info", "unknown"];
const PRIORITY: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4, unknown: 5 };
const label = (name: string): string => name.replace(/_/g, " ").replace(/\b\w/g, s => s.toUpperCase());
const compact = (value: string, limit = 140): string => value.length > limit ? `${value.slice(0, limit - 1)}…` : value;

type NumberLike = number | undefined;
function nestedCount(value: unknown, ...path: string[]): NumberLike {
  let current: unknown = value;
  for (const segment of path) {
    if (!current || typeof current !== "object" || !(segment in current)) return undefined;
    current = (current as Record<string, unknown>)[segment];
  }
  return typeof current === "number" && Number.isFinite(current) ? current : undefined;
}

/** A short dashboard overview: the PDF is the single source for full explanations. */
export default function ExecutiveDashboardSummary({ report, filename }: Props) {
  const [exporting, setExporting] = useState(false);
  const [pdfError, setPdfError] = useState<string | null>(null);
  const counts = report.summary.severity_counts;
  const firstSeverity = SEVERITIES.find(severity => (counts[severity] ?? 0) > 0);
  const unassessed = report.coverage.domains.filter(item => item.status !== "assessed").length;
  const reviewed = report.coverage.domains.length - unassessed;
  const priorityFindings = [...report.findings]
    .sort((a, b) => PRIORITY[a.severity] - PRIORITY[b.severity])
    .slice(0, 3);

  const extra: Array<{ name: string; value: string; kind?: "attention" }> = [];
  const qualityErrors = nestedCount(report, "quality", "summary", "errors");
  const qualityReviews = nestedCount(report, "quality", "summary", "review_items");
  if (qualityErrors !== undefined) extra.push({ name: "Report consistency", value: `${qualityErrors} errors${qualityReviews ? `, ${qualityReviews} reviews` : ""}`, kind: qualityErrors ? "attention" : undefined });
  const vendorReview = (report as unknown as Record<string, unknown>).vendor_review;
  const vendorChecks = vendorReview && typeof vendorReview === "object"
    ? (vendorReview as Record<string, unknown>).checks : undefined;
  const vendorObservations = Array.isArray(vendorChecks) ? vendorChecks.length : undefined;
  if (vendorObservations !== undefined) extra.push({ name: "Vendor review", value: `${vendorObservations} observations` });
  const rulePairs = nestedCount(report, "rule_correlation", "summary", "candidate_pairs");
  if (rulePairs !== undefined) extra.push({ name: "Rule correlations", value: `${rulePairs} candidates` });
  const contradicted = nestedCount(report, "correlation_assurance", "summary", "ordering_contradictions");
  if (contradicted !== undefined) extra.push({ name: "Ordering checks", value: `${contradicted} contradictions`, kind: contradicted ? "attention" : undefined });
  const objectsUnresolved = nestedCount(report, "object_resolution", "summary", "definitions_unresolved");
  if (objectsUnresolved !== undefined) extra.push({ name: "Object resolution", value: `${objectsUnresolved} unresolved` });
  const objectsMissing = nestedCount(report, "object_assurance", "summary", "missing_in_upload");
  if (objectsMissing !== undefined) extra.push({ name: "Object references", value: `${objectsMissing} not visible in upload` });
  const objectCycles = nestedCount(report, "object_assurance", "summary", "cycles");
  if (objectCycles !== undefined && objectCycles > 0) extra.push({ name: "Reference cycles", value: `${objectCycles} candidates`, kind: "attention" });
  const reviewScore = report.assessment?.review_score;

  async function download(): Promise<void> {
    setExporting(true);
    setPdfError(null);
    try {
      await downloadNormalizedPdf(report, filename);
    } catch (error) {
      setPdfError(error instanceof Error ? error.message : "Unable to generate the PDF report.");
    } finally {
      setExporting(false);
    }
  }

  return (
    <section className="ua-panel ed-root" aria-labelledby="ed-title">
      <div className="ed-header">
        <div>
          <p className="ed-eyebrow">ANALYSIS SUMMARY</p>
          <h2 id="ed-title">{report.platform.display_name}</h2>
          <p className="ed-muted">{report.platform.hostname ? `${report.platform.hostname} · ` : ""}{report.platform.family.toUpperCase()} · Uploaded configuration only</p>
        </div>
        <button className="ed-pdf" type="button" disabled={exporting} onClick={() => { void download(); }}>
          {exporting ? "Preparing PDF…" : "Download full PDF report"}
        </button>
      </div>
      {pdfError && <p role="alert" className="ed-error">PDF generation failed: {pdfError}</p>}

      <div className="ed-kpis" aria-label="Assessment metrics">
        <div className="ed-kpi"><span>Findings</span><strong>{report.summary.total_findings}</strong></div>
        <div className="ed-kpi"><span>{reviewScore ? "Provisional review" : "Security score"}</span><strong>{reviewScore ? `${reviewScore.value}/${reviewScore.maximum}` : report.summary.security_score === null ? "Not scored" : `${report.summary.security_score}/100`}</strong></div>
        <div className="ed-kpi"><span>Highest severity</span><strong>{firstSeverity ? label(firstSeverity) : "None detected"}</strong></div>
        <div className="ed-kpi"><span>Coverage</span><strong>{reviewed}/{report.coverage.domains.length}</strong><small>Domains assessed</small></div>
      </div>
      <p className="ed-context">{reviewScore ? "Provisional score: higher means fewer detected concerns; incomplete coverage can cap the score at 80/100. " : "Vendor-specific scoring is not directly comparable across platforms. "}No findings does not mean the device is secure.</p>

      <div className="ed-section-heading"><h3>Severity at a glance</h3><span>Info → Critical indicates increasing priority</span></div>
      <div className="ed-severities" aria-label="Security finding severity counts">
        {SEVERITIES.map(s => <div className={`ed-severity ed-${s}`} key={s}><span>{label(s)}</span><strong>{counts[s] ?? 0}</strong></div>)}
      </div>

      <div className="ed-section-heading"><h3>Priority findings</h3><span>Up to 3 previews</span></div>
      {priorityFindings.length ? (
        <ol className="ed-findings">
          {priorityFindings.map(f => (
            <li className="ed-finding" key={f.finding_id}>
              <span className={`ed-chip ed-${f.severity}`}>{label(f.severity)}</span>
              <div><strong>{compact(f.title)}</strong><small>{f.code}{f.evidence.line_number !== null ? ` · Line ${f.evidence.line_number}` : ""}</small></div>
            </li>
          ))}
        </ol>
      ) : <p className="ed-empty">No findings were produced by the implemented checks.</p>}
      {report.summary.total_findings > priorityFindings.length && <p className="ed-muted">+{report.summary.total_findings - priorityFindings.length} more findings, with evidence and recommendations, in the PDF.</p>}

      {extra.length > 0 && <>
        <div className="ed-section-heading"><h3>Additional checks</h3><span>Summary only</span></div>
        <div className="ed-checks">
          {extra.map(item => <div className="ed-check" key={item.name}><span>{item.name}</span><strong className={item.kind === "attention" ? "ed-attention" : ""}>{item.value}</strong></div>)}
        </div>
      </>}
      {(unassessed > 0 || report.warnings.length > 0) && (
        <p className="ed-caveat">{unassessed} domain(s) not assessed · {report.warnings.length} parser warning(s). Read the PDF for coverage, uncertainty and evidence.</p>
      )}
      <div className="ed-footer">Full finding descriptions, remediation steps, correlations, object analysis, assessment definitions, and limitations are documented in the PDF report.</div>
    </section>
  );
}
