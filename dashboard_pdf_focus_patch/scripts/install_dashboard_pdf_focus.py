r"""Replace the long dashboard detail stack with a short overview; retain detailed PDF.

Usage (from the project root):
  .\.venv-win\Scripts\python.exe dashboard_pdf_focus_patch\scripts\install_dashboard_pdf_focus.py ".\frontend"
"""
from __future__ import annotations

from pathlib import Path
import re
import shutil
import sys

ROOT = Path(__file__).resolve().parents[1]
BACKUP = '.before_dashboard_pdf_focus.bak'


def patch_dashboard(src: str) -> str:
    if 'import ExecutiveDashboardSummary from' in src and '<ExecutiveDashboardSummary' in src:
        return src
    if 'const [choice, setChoice]' not in src or 'onReportChange(next)' not in src:
        raise ValueError('Unknown Unified Dashboard implementation. No files changed.')
    start_token = '      {report && ('
    end_token = '\n      )}\n    </div>\n  );'
    if src.count(start_token) != 1 or src.count(end_token) != 1:
        raise ValueError('Cannot isolate the report-only JSX safely; no changes were made.')
    start = src.index(start_token)
    end = src.index(end_token, start) + len('\n      )}')
    replacement = '''      {report && (
        <div className="ua-results" aria-live="polite">
          <ExecutiveDashboardSummary
            report={report}
            filename={file?.name ?? report.platform.hostname ?? report.platform.platform_id}
          />
          {report.platform.platform_id === "cisco_asa" && !legacyASAReady &&
            (asaSyncError || (legacyError && !legacyLoading)) && (
              <p role="status" className="ua-hint">
                Cisco ASA legacy detail pages are unavailable for this upload. The formal PDF report is still available.
              </p>
            )}
        </div>
      )}'''
    src = src[:start] + replacement + src[end:]

    # Components removed from the dashboard are not deleted from disk. Other pages
    # may still use their modules. Remove imports to satisfy noUnusedLocals.
    src = re.sub(r'(?m)^import CiscoASAOverview from [^\n]+\n', '', src)
    src = re.sub(r'(?m)^import (?:AdvancedAssessmentPanel|ReportQualityPanel|VendorDeepReviewPanel|RuleCorrelationPanel|CorrelationAssurancePanel|ObjectResolutionPanel|ObjectAssurancePanel|UniversalSeverityChart) from [^\n]+\n', '', src)
    src = src.replace('import "./UniversalAnalysis.css";',
                      'import ExecutiveDashboardSummary from "../components/ExecutiveDashboardSummary";\nimport "./UniversalAnalysis.css";', 1)

    # The old findings table and filter are gone; the compact component selects
    # its own top three findings, avoiding unused-identifier TS6133 errors.
    src = src.replace('const [analyzedFile, setAnalyzedFile] = useState("");',
                      'const [, setAnalyzedFile] = useState("");')
    src = re.sub(r'(?m)^const SEVERITIES: Severity\[\] = .*?;\n', '', src)
    src = re.sub(r'(?m)^\s*const \[severityFilter, setSeverityFilter\] = useState<[^\n]+\n', '', src)
    src = re.sub(r'(?m)^\s*setSeverityFilter\("all"\);\n', '', src)
    src = re.sub(r'\n  const visibleFindings = .*?\n  \) \?\? \[\];\n', '\n', src, flags=re.S) if 'const visibleFindings' in src else src
    # Older layout uses single-line `) ?? [];` after the filter.
    src = re.sub(r'\n  const visibleFindings = .*?\n  \) \?\? \[\];\n', '\n', src, flags=re.S)
    src = re.sub(r'\n  const visibleFindings = report\?\.findings\.filter\(.*?\n  \) \?\? \[\];\n', '\n', src, flags=re.S)
    # Remove unused helper functions from older dashboard revisions.
    for name in ('niceLabel', 'safeExportName', 'exportReport'):
        src = re.sub(r'(?ms)^function ' + name + r'\(.*?^}\n\n?', '', src)
    src = re.sub(r'(?m)^\s*type Severity,\n', '', src)
    # Remove unused named imports, but keep React hooks and API functions used in
    # the upload process. Additional third-party display modules are also pruned.
    for line in re.findall(r'(?m)^import ([A-Za-z_][A-Za-z_0-9]*) from [^\n]+\n', src):
        if line == 'ExecutiveDashboardSummary':
            continue
        if len(re.findall(r'\b' + re.escape(line) + r'\b', src)) == 1:
            src = re.sub(r'(?m)^import ' + re.escape(line) + r' from [^\n]+\n', '', src)
    if 'const visibleFindings' in src or 'severityFilter' in src or 'setSeverityFilter' in src:
        raise ValueError('Unused legacy findings-filter code could not be safely removed; no changes made.')
    if 'ExecutiveDashboardSummary' not in src or '{report && (' not in src:
        raise ValueError('Dashboard rewrite failed integrity verification.')
    return src


PDF_GLOSSARY = '''  section("How to read this assessment");
  text("The Dashboard is an overview only. This PDF is the detailed report for the uploaded configuration and its supported checks.", {
    size: 8.9, color: COLORS.ink, spaceAfter: 10,
  });
  const definitions: Array<[string, string]> = [
    ["Findings / severity", "Security findings are individual issues detected by implemented checks. Severity is an ordinal priority: Info, Low, Medium, High, Critical; Unknown means not classified. It is not a second numeric security score."],
    ["Provisional review score", "A 0-100 indicator based on the checks performed; higher generally means fewer detected concerns. Missing coverage may cap it at 80/100. It does not estimate the probability of compromise."],
    ["Security score / risk level", "An analyzer-specific summary that may use a legacy vendor-specific formula. Do not compare legacy scores directly with the provisional review score or between different vendors."],
    ["Report quality", "Checks internal consistency of generated report fields and source references. A consistent report is not proof the device is secure."],
    ["Vendor review", "Additional platform-specific, upload-scoped observations. These are separate from the normalized findings and do not change existing scores unless explicitly stated."],
    ["Rule correlation", "Candidate overlaps, redundancies, contradictory actions, or shadowing relationships. Their applicability depends on supported syntax, effective order, objects, interfaces and runtime behavior."],
    ["Evidence and ordering", "A cited line or sequence number is source evidence, not confirmation of effective deployed policy. Contradictory or absent ordering evidence requires manual review."],
    ["Object resolution", "Supported named network and service objects are expanded to compare selectors. Unsupported, unresolved, ambiguous and out-of-scope definitions are not assumed to match."],
    ["Object reference integrity", "Missing from upload means the referenced definition was not visible in the submitted file; this does not prove it is missing on the live device."],
    ["Coverage, warnings and limitations", "Assessed means the implemented checks ran, not that all vendor features were inspected. Not assessed, truncated input, omitted server observations and parser warnings limit any conclusion."],
  ];
  definitions.forEach(([term, explanation]) => {
    text(term.toUpperCase(), { bold: true, color: COLORS.blue, size: 8.6, spaceAfter: 3 });
    text(explanation, { indent: 9, size: 8.5, spaceAfter: 9 });
  });

'''



PDF_QUALITY_APPENDIX = '''  const qualityReview = (report as NormalizedReport & { quality?: {
    status: string; summary: { errors: number; review_items: number; issues_suppressed: number };
    finding_evidence: { findings_total: number; findings_crosschecked_with_adapter: number;
      findings_with_reported_line_references: number; line_reference_note: string; };
    coverage: { unassessed_domains: string[]; incomplete: boolean };
    issues: Array<{ level: string; code: string; explanation: string; finding_id?: string }>;
    platform_note: string; interpretation: string;
  } }).quality;
  if (qualityReview) {
    section("Report quality and consistency");
    text("This evaluates generated report consistency, not effective device security.", {
      size: 8.6, color: COLORS.muted, spaceAfter: 7,
    });
    text(`Status: ${qualityReview.status.replace(/_/g, " ")} | Errors: ${qualityReview.summary.errors} | Review notices: ${qualityReview.summary.review_items}`, {
      size: 8.9, bold: true, color: COLORS.navy, spaceAfter: 7,
    });
    text(`Findings cross-checked: ${qualityReview.finding_evidence.findings_crosschecked_with_adapter}/${qualityReview.finding_evidence.findings_total} | Source line references: ${qualityReview.finding_evidence.findings_with_reported_line_references}`, {
      size: 8.6, spaceAfter: 5,
    });
    qualityReview.issues.forEach((issue, index) => {
      text(`${index + 1}. ${issue.level.toUpperCase()}  ${issue.code}${issue.finding_id ? `  [${issue.finding_id}]` : ""}`, {
        size: 8.7, bold: true, color: COLORS.blue, spaceAfter: 2,
      });
      text(issue.explanation, { indent: 10, size: 8.5, spaceAfter: 7 });
    });
    if (qualityReview.summary.issues_suppressed > 0) {
      text(`${qualityReview.summary.issues_suppressed} additional notices were suppressed by the analysis service.`, {
        size: 8.4, color: COLORS.muted, spaceAfter: 5,
      });
    }
    text(qualityReview.platform_note, { size: 8.3, color: COLORS.muted, spaceAfter: 5 });
    text(qualityReview.finding_evidence.line_reference_note, { size: 8.3, color: COLORS.muted, spaceAfter: 5 });
    text(qualityReview.interpretation, { size: 8.3, color: COLORS.muted, spaceAfter: 6 });
    if (qualityReview.coverage.unassessed_domains.length) {
      text(`Not assessed: ${qualityReview.coverage.unassessed_domains.join(", ")}`, {
        size: 8.3, color: COLORS.muted, spaceAfter: 6,
      });
    }
  }

'''

PDF_OBJECT_INVENTORY = '''    if (resolved.objects.length) {
      text("OBJECT RESOLUTION INVENTORY", { bold: true, size: 8.7, color: COLORS.blue, spaceAfter: 7 });
      resolved.objects.forEach((object) => {
        text(`${object.name}  [${object.kind}]  |  ${object.status}  |  line ${object.line_number}`, {
          bold: true, size: 8.6, spaceAfter: 3,
        });
        text(object.value ?? object.reason, { indent: 10, size: 8.3, color: COLORS.muted, spaceAfter: 6 });
      });
    }

'''


def patch_pdf(src: str) -> str:
    required = ('renderNormalizedPdf(', 'section("Findings register")', 'section("Assessment coverage")',
                'section("Report interpretation")')
    if any(token not in src for token in required):
        raise ValueError('Professional PDF exporter not recognized; no files changed.')
    if 'section("How to read this assessment")' not in src:
        src = src.replace('  section("Report interpretation");', PDF_GLOSSARY + '  section("Report interpretation");', 1)
    # Increase bounded export coverage so the PDF contains all normally returned
    # source findings and observations. Backend-omitted source records cannot be
    # reconstructed by the UI; state that explicitly rather than referring to JSON.
    src = src.replace('const MAX_FINDINGS_IN_PDF = 300;', 'const MAX_FINDINGS_IN_PDF = 1500;')
    src = src.replace('const MAX_OBSERVATIONS_IN_PDF = 80;', 'const MAX_OBSERVATIONS_IN_PDF = 1000;')
    src = src.replace('... [shortened in PDF; full value in JSON]',
                      '... [long source value shortened for readability]')
    src = src.replace('Export JSON for the complete set.',
                      'The PDF safety limit was reached; analyze a narrower configuration to include the remaining findings.')
    src = src.replace('more observations omitted from PDF; see JSON.',
                      'more observations omitted from this PDF due to its safety limit. Analyze a narrower configuration to inspect the remainder.')
    src = src.replace('Additional observations were omitted from the PDF; consult the dashboard for the available bounded list.',
                      'Additional observations were not included in the analyzer response or exceeded its safety limit. The report is incomplete; review a narrower configuration.')
    src = src.replace('pdf.internal.getNumberOfPages()', 'pdf.getNumberOfPages()')

    if 'section("Report quality and consistency")' not in src:
        src = src.replace('  section("Assessment coverage");',
                          PDF_QUALITY_APPENDIX + '  section("Assessment coverage");', 1)
    if 'OBJECT RESOLUTION INVENTORY' not in src and 'if (report.object_resolution)' in src:
        src = src.replace('    resolved.limitations', PDF_OBJECT_INVENTORY + '    resolved.limitations', 1)
    if 'report.vendor_review.interpretation' in src and 'report.vendor_review.limitations.forEach' not in src:
        src = src.replace('    text(report.vendor_review.interpretation,',
                          '    report.vendor_review.limitations.forEach((limitation) => {\n'
                          '      text(`Scope: ${limitation}`, { size: 8.2, color: COLORS.muted, spaceAfter: 5 });\n'
                          '    });\n'
                          '    text(report.vendor_review.interpretation,', 1)
    # Existing vendor, rule, object and correlation sections already format
    # explanations, evidence, and recommendations. Stop truncating these lists
    # below what the backend returned; retain explicit source-side limits.
    for field in ('report.vendor_review.checks', 'report.rule_correlation.pairs',
                  'assurance.items', 'resolved.pairs', 'review.observations'):
        src = re.sub(r'\b' + re.escape(field) + r'\.slice\(0, \d+\)', field, src)
    for field in ('report.rule_correlation.limitations', 'assurance.limitations',
                  'resolved.limitations', 'review.limitations'):
        src = re.sub(r'\b' + re.escape(field) + r'\.slice\(0, \d+\)', field, src)
    # Preserve server-level omissions honestly; no dashboard-only details exist.
    src = src.replace('if (review.observations.length > 30 || review.summary.observations_omitted > 0)',
                      'if (review.summary.observations_omitted > 0)')
    return src


def plan(frontend: Path) -> dict[Path, bytes]:
    frontend = frontend.resolve()
    if not (frontend / 'package.json').is_file():
        raise ValueError(f'Expected frontend folder (contains package.json): {frontend}')
    updates: dict[Path, bytes] = {}
    for relative, transform in (
        ('src/pages/UniversalAnalysis.tsx', patch_dashboard),
        ('src/utils/normalizedPdf.ts', patch_pdf),
    ):
        path = frontend / relative
        if not path.is_file():
            raise ValueError(f'Missing required source file: {path}')
        original = path.read_text(encoding='utf-8-sig')
        updated = transform(original)
        if updated != original:
            updates[path] = updated.encode('utf-8')
    for relative in ('src/components/ExecutiveDashboardSummary.tsx',
                     'src/components/ExecutiveDashboardSummary.css'):
        path = frontend / relative
        payload = (ROOT / relative).read_bytes()
        if not path.is_file() or path.read_bytes() != payload:
            updates[path] = payload
    return updates


def install(frontend: Path) -> list[str]:
    updates = plan(frontend)  # Validate every source BEFORE modifying any files.
    for path, payload in updates.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            backup = path.with_name(path.name + BACKUP)
            if not backup.exists():
                shutil.copy2(path, backup)
        path.write_bytes(payload)
    return [str(path.relative_to(frontend.resolve())) for path in updates]


if __name__ == '__main__':
    target = Path(sys.argv[1]) if len(sys.argv) == 2 else Path.cwd() / 'frontend'
    try:
        changes = install(target)
    except (ValueError, OSError) as exc:
        sys.exit(f'ERROR: {exc}')
    print('Dashboard/PDF focus patch installed:' if changes else 'Dashboard/PDF focus patch already installed.')
    for relative in changes:
        print('  ' + relative)
    print('Next: cd frontend; npm run build')
