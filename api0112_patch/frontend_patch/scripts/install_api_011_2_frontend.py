"""API-011.2: dashboard snippets; full diagnostic contract evidence in PDF."""
from __future__ import annotations
from pathlib import Path
import shutil
import sys

PACKAGE = Path(__file__).resolve().parents[1]
BACKUP = '.before_api0112.bak'

TYPES = """
/** Static report-contract preflight; does not certify PDF render or security. */
export interface ReportValidationReview {
  version: "1.0";
  platform_id: "cisco_asa" | "fortios" | "snort" | "suricata";
  scope: "single_upload_report_contract_preflight";
  status: "consistent_subset" | "limited" | "inconsistent";
  summary: {
    checks_performed: number; passed_checks: number; discrepancies: number;
    warnings: number; reviews_examined: number; items_omitted: number;
    incomplete: boolean;
  };
  checks: Array<{
    reference: string; section: string; check: string; result: string;
    observed: string; expected: string; explanation: string;
    recommended_action: string; confidence: string;
  }>;
  limitations: string[];
}
"""


def replace_once(source: str, old: str, new: str, label: str) -> str:
    if new in source: return source
    if source.count(old) != 1:
        raise ValueError(f'{label}: expected one API-011.1 anchor')
    return source.replace(old, new, 1)


def patch_api(source: str) -> str:
    source = replace_once(source, '/api/v1/analyze/correlation-accuracy',
                          '/api/v1/analyze/report-validation', 'upload endpoint')
    source = replace_once(source, '  correlation_accuracy_review?: CorrelationAccuracyReview;',
                          '  correlation_accuracy_review?: CorrelationAccuracyReview;\n  report_validation_review?: ReportValidationReview;',
                          'normalized review property')
    if 'export interface ReportValidationReview {' not in source:
        source += '\n' + TYPES
    return source


def patch_dashboard(source: str) -> str:
    source = replace_once(source,
        'import CorrelationAccuracySnippet from "../components/CorrelationAccuracySnippet";',
        'import CorrelationAccuracySnippet from "../components/CorrelationAccuracySnippet";\n'
        'import ReportValidationSnippet from "../components/ReportValidationSnippet";',
        'dashboard import')
    return replace_once(source,
        '<CorrelationAccuracySnippet review={report.correlation_accuracy_review} />',
        '<CorrelationAccuracySnippet review={report.correlation_accuracy_review} />\n'
        '          <ReportValidationSnippet review={report.report_validation_review} />',
        'dashboard location')

PDF_BLOCK = """  if (report.report_validation_review) {
    section("Report validation and reporting reliability — Detailed preflight evidence");
    const rv = report.report_validation_review;
    text("This is a static normalized-report contract check. PDF generation, font rendering, page layout and download integrity have NOT been verified by this check.", {
      size: 8.4, color: COLORS.muted, spaceAfter: 8,
    });
    text(`Platform: ${rv.platform_id} | Status: ${label(rv.status)} | Checks: ${rv.summary.checks_performed} | Consistent: ${rv.summary.passed_checks} | Discrepancies: ${rv.summary.discrepancies} | Warnings: ${rv.summary.warnings}`, {
      size: 8.4, spaceAfter: 7,
    });
    text(`Review modules examined: ${rv.summary.reviews_examined} | Validation observations omitted: ${rv.summary.items_omitted} | Coverage incomplete: ${rv.summary.incomplete ? "yes" : "no"}`, {
      size: 8.2, spaceAfter: 7,
    });
    text("CONTRACT CHECK EVIDENCE AND ANALYST ACTIONS", {
      bold: true, color: COLORS.blue, size: 9, spaceAfter: 5,
    });
    rv.checks.forEach((item) => {
      ensure(90);
      text(`${item.reference} | ${label(item.section)} | ${label(item.check)} | ${label(item.result)}`, {
        bold: true, color: COLORS.navy, size: 8.6, spaceAfter: 4,
      });
      text(`Observed: ${item.observed} | Expected: ${item.expected} | Confidence: ${item.confidence}`, {
        size: 8, indent: 10, spaceAfter: 4,
      });
      text(`Assessment: ${item.explanation}`, { size: 8.2, indent: 10, spaceAfter: 4 });
      text(`Recommended verification: ${item.recommended_action}`, {
        size: 8.2, indent: 10, spaceAfter: 8,
      });
    });
    text("SCOPE AND VALIDATION LIMITATIONS", {
      bold: true, color: COLORS.blue, size: 9, spaceAfter: 5,
    });
    rv.limitations.forEach((item) => text(`Limitation: ${item}`, {
      color: COLORS.muted, size: 8, spaceAfter: 5,
    }));
    if (rv.summary.incomplete || rv.status === "inconsistent") {
      text("This report is not cleared for reliance without manual review of discrepancies or incomplete evidence.", {
        color: COLORS.muted, size: 8.2, spaceAfter: 8,
      });
    }
  }

"""


def patch_pdf(source: str) -> str:
    if 'section("Report validation and reporting reliability — Detailed preflight evidence")' in source:
        return source
    return replace_once(source, '  section("Assessment coverage");',
                        PDF_BLOCK + '  section("Assessment coverage");', 'PDF evidence section')


def plan(root: Path) -> dict[Path, bytes]:
    root = root.resolve()
    if not (root/'package.json').is_file():
        raise ValueError(f'Frontend package.json missing: {root}')
    changes: dict[Path, bytes] = {}
    for rel, patch in (
        ('src/api/universal.ts', patch_api),
        ('src/pages/UniversalAnalysis.tsx', patch_dashboard),
        ('src/utils/normalizedPdf.ts', patch_pdf),
    ):
        dst = root/rel
        if not dst.is_file():
            raise ValueError(f'Install API-011.1 frontend first: {dst}')
        old = dst.read_text(encoding='utf-8-sig')
        new = patch(old)
        if old != new: changes[dst] = new.encode('utf-8')
    for rel in ('src/components/ReportValidationSnippet.tsx',
                'src/components/ReportValidationSnippet.css'):
        src = PACKAGE / rel
        if not src.is_file(): raise ValueError(f'Packaged component missing: {src}')
        dst = root/rel
        if not dst.is_file() or dst.read_bytes() != src.read_bytes():
            changes[dst] = src.read_bytes()
    return changes


def install(root: Path) -> list[str]:
    root = root.resolve()
    changes = plan(root)
    for dst, payload in changes.items():
        dst.parent.mkdir(parents=True, exist_ok=True)
        backup = dst.with_name(dst.name + BACKUP)
        if dst.is_file() and not backup.exists(): shutil.copy2(dst, backup)
        dst.write_bytes(payload)
    return [str(x.relative_to(root)) for x in changes]


if __name__ == '__main__':
    if len(sys.argv) > 2: sys.exit('Usage: install_api_011_2_frontend.py [frontend-root]')
    target = Path(sys.argv[1]) if len(sys.argv) == 2 else Path.cwd()/'frontend'
    try: changes = install(target)
    except (OSError, ValueError, UnicodeError) as exc: sys.exit(f'ERROR: {exc}')
    print('API-011.2 frontend installed:' if changes else 'API-011.2 frontend already installed:')
    for rel in changes: print('  ' + rel)
