"""Add API-011.4 UI/PDF sections without rewriting previous review components."""
from __future__ import annotations
from pathlib import Path
import sys

PACKAGE = Path(__file__).resolve().parents[1]
TYPES = '''
/** API-011.4 server-side integration checks; browser export must be verified separately. */
export interface PipelineValidationReview {
  version: "1.0";
  platform_id: "cisco_asa" | "fortios" | "snort" | "suricata";
  scope: "single_upload_server_response_contract_and_manual_export_checklist";
  status: "server_checks_passed" | "limited" | "blocked";
  summary: { checks: number; passed: number; warnings: number; blockers: number; manual_required: number };
  stages: Array<{
    reference: string; stage: string; result: "pass" | "warning" | "blocker" | "manual_required";
    observation: string; recommendation: string; evidence_basis: string;
  }>;
  limitations: string[];
}
'''

PDF_SECTION = '''  if (report.pipeline_validation_review) {
    const pipelineReview = report.pipeline_validation_review;
    section("End-to-end pipeline validation — Detailed verification evidence");
    text("Server-side report checks cannot prove that the browser generated and saved the PDF. Run the saved-PDF audit and visually inspect the downloaded report.", {
      color: COLORS.muted, size: 8.3, spaceAfter: 7,
    });
    text(`Status: ${label(pipelineReview.status)} | Checks: ${pipelineReview.summary.checks} | Passed: ${pipelineReview.summary.passed} | Warnings: ${pipelineReview.summary.warnings} | Blockers: ${pipelineReview.summary.blockers} | Manual verification: ${pipelineReview.summary.manual_required}`, {
      size: 8.1, spaceAfter: 8,
    });
    pipelineReview.stages.forEach((item) => {
      ensure(91);
      text(`${item.reference} | ${label(item.stage)} | ${label(item.result)}`, {
        bold: true, color: COLORS.navy, size: 8.5, spaceAfter: 3,
      });
      text(`Observation: ${item.observation}`, { size: 8.1, indent: 10, spaceAfter: 3 });
      text(`Evidence basis: ${item.evidence_basis}`, { size: 7.9, indent: 10, spaceAfter: 3 });
      text(`Recommended action: ${item.recommendation}`, { size: 8.1, indent: 10, spaceAfter: 7 });
    });
    text("PIPELINE VALIDATION LIMITATIONS", { bold: true, color: COLORS.blue, size: 8.9, spaceAfter: 4 });
    pipelineReview.limitations.forEach((item) => text(`Limitation: ${item}`, {
      color: COLORS.muted, size: 8, spaceAfter: 5,
    }));
  }

'''


def replace_once(src: str, old: str, new: str, label: str) -> str:
    if src.count(new) == 1:
        return src
    if src.count(old) != 1:
        raise ValueError(f'API-011.4 {label}: missing/ambiguous API-011.3 anchor')
    return src.replace(old, new, 1)


def patch_api(src: str) -> str:
    src = replace_once(src, '/api/v1/analyze/pdf-readiness', '/api/v1/analyze/pipeline-validation', 'endpoint')
    src = replace_once(src, '  pdf_export_review?: PdfExportReview;',
        '  pdf_export_review?: PdfExportReview;\n  pipeline_validation_review?: PipelineValidationReview;', 'response type')
    if 'export interface PipelineValidationReview {' not in src:
        src += '\n' + TYPES
    return src


def patch_dashboard(src: str) -> str:
    src = replace_once(src,
        'import PdfExportReadinessSnippet from "../components/PdfExportReadinessSnippet";',
        'import PdfExportReadinessSnippet from "../components/PdfExportReadinessSnippet";\n'
        'import PipelineValidationSnippet from "../components/PipelineValidationSnippet";', 'dashboard import')
    return replace_once(src, '<PdfExportReadinessSnippet review={report.pdf_export_review} />',
        '<PdfExportReadinessSnippet review={report.pdf_export_review} />\n'
        '          <PipelineValidationSnippet review={report.pipeline_validation_review} />', 'dashboard review')


def patch_pdf(src: str) -> str:
    return replace_once(src, '  section("Assessment coverage");',
        PDF_SECTION + '  section("Assessment coverage");', 'PDF report section')


def plan(frontend: Path) -> dict[Path, bytes]:
    frontend = frontend.resolve()
    if not (frontend / 'package.json').is_file():
        raise ValueError(f'Not a frontend project: {frontend}')
    changes: dict[Path, bytes] = {}
    patches = (
        ('src/api/universal.ts', patch_api),
        ('src/pages/UniversalAnalysis.tsx', patch_dashboard),
        ('src/utils/normalizedPdf.ts', patch_pdf),
    )
    for rel, patch in patches:
        dest = frontend / rel
        if not dest.is_file():
            raise ValueError(f'Missing prerequisite API-011.3 file: {dest}')
        raw = dest.read_bytes()
        bom = raw.startswith(b'\xef\xbb\xbf')
        decoded = raw.decode('utf-8-sig')
        line_ending = '\r\n' if '\r\n' in decoded else '\n'
        src = decoded.replace('\r\n', '\n')
        updated = patch(src)
        if updated != src:
            changes[dest] = (b'\xef\xbb\xbf' if bom else b'') + updated.replace('\n', line_ending).encode('utf-8')
    for rel in ('src/components/PipelineValidationSnippet.tsx',
                'src/components/PipelineValidationSnippet.css'):
        dest = frontend / rel
        bundled = (PACKAGE / rel).read_bytes()
        if dest.exists():
            if dest.read_bytes() != bundled:
                raise ValueError(f'Refusing to overwrite customized component: {dest}')
        else:
            changes[dest] = bundled
    return changes


if __name__ == '__main__':
    if len(sys.argv)>2: sys.exit('Usage: install_api_011_4_frontend.py [frontend-root]')
    root=Path(sys.argv[1]) if len(sys.argv)==2 else Path.cwd()/'frontend'
    try:
        planned=plan(root)
        print('Frontend files to change (use combined installer for safe backups):')
        for f in planned: print(' -', f)
    except (OSError, ValueError, UnicodeError) as exc:
        sys.exit(f'ERROR: {exc}')
