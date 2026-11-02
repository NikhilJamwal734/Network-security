"""API-011.3: PDF-first frontend installer, plans before writing.

Preserves existing dashboards, review cards, PDF sections, and TSX source.
"""
from __future__ import annotations
from pathlib import Path
import sys

PACKAGE = Path(__file__).resolve().parents[1]
TYPES = '''
/** Static PDF readiness preflight; actual PDF bytes are checked in the browser on export. */
export interface PdfExportReview {
  version: "1.0";
  platform_id: "cisco_asa" | "fortios" | "snort" | "suricata";
  scope: "static_single_upload_pdf_export_preflight";
  status: "preflight_pass" | "limited" | "blocked";
  summary: { checks: number; passed: number; warnings: number; blockers: number; omitted: number };
  observations: Array<{
    reference: string; kind: string; result: string;
    observation: string; recommendation: string;
  }>;
  limitations: string[];
}
'''

PDF_BLOCK = '''  if (report.pdf_export_review) {
    section("PDF export readiness — Detailed preflight observations");
    const exportReview = report.pdf_export_review;
    text("These are checks of the normalized report BEFORE rendering. The browser separately checks the generated PDF header, EOF marker, file size and page count before initiating a download. Neither check proves visual fidelity or that the browser saved the file.", {
      size: 8.4, color: COLORS.muted, spaceAfter: 8,
    });
    text(`Status: ${label(exportReview.status)} | Checks: ${exportReview.summary.checks} | Passed: ${exportReview.summary.passed} | Warnings: ${exportReview.summary.warnings} | Blockers: ${exportReview.summary.blockers}`, {
      size: 8.4, spaceAfter: 8,
    });
    if (exportReview.observations.length === 0) {
      text("No structured preflight concerns were identified in the supported subset; this is NOT a guarantee of correct rendering or security.", {
        color: COLORS.muted, size: 8.2, spaceAfter: 8,
      });
    }
    exportReview.observations.forEach((item) => {
      ensure(92);
      text(`${item.reference} | ${label(item.kind)} | ${label(item.result)}`, {
        bold: true, color: COLORS.navy, size: 8.7, spaceAfter: 4,
      });
      text(`Observation: ${item.observation}`, { size: 8.2, indent: 10, spaceAfter: 4 });
      text(`Recommended action: ${item.recommendation}`, { size: 8.2, indent: 10, spaceAfter: 8 });
    });
    if (exportReview.summary.omitted > 0) {
      text(`${exportReview.summary.omitted} diagnostic observation(s) omitted from this PDF preflight section.`, {
        color: COLORS.muted, size: 8.1, spaceAfter: 6,
      });
    }
    text("PDF EXPORT VALIDATION LIMITATIONS", { bold: true, color: COLORS.blue, size: 9, spaceAfter: 5 });
    exportReview.limitations.forEach((item) => text(`Limitation: ${item}`, {
      color: COLORS.muted, size: 8.1, spaceAfter: 5,
    }));
  }

'''

SAVE_OLD = '  pdf.save(`${normalizedFilename(filename)}.${normalizedFilename(report.platform.platform_id)}.security-report.pdf`);'
SAVE_NEW = '''  // Validate the exact serialized bytes that will be downloaded.
  const payload = pdf.output("arraybuffer");
  const inspection = inspectPdfExport(new Uint8Array(payload), pdf.internal.getNumberOfPages());
  if (!inspection.ok) {
    throw new Error(`PDF export validation failed: ${inspection.problems.join("; ")}`);
  }
  downloadVerifiedPdf(payload, `${normalizedFilename(filename)}.${normalizedFilename(report.platform.platform_id)}.security-report.pdf`);'''


def replace_one(src: str, old: str, new: str, label: str) -> str:
    if src.count(new) == 1: return src
    if src.count(old) != 1: raise ValueError(f'{label}: expected exactly one API-011.2 anchor')
    return src.replace(old, new, 1)


def patch_api(src: str) -> str:
    src = replace_one(src, '/api/v1/analyze/report-validation', '/api/v1/analyze/pdf-readiness', 'API endpoint')
    src = replace_one(src, '  report_validation_review?: ReportValidationReview;',
        '  report_validation_review?: ReportValidationReview;\n  pdf_export_review?: PdfExportReview;', 'Report type')
    if 'export interface PdfExportReview {' not in src: src += '\n' + TYPES
    return src


def patch_dashboard(src: str) -> str:
    src = replace_one(src,
        'import ReportValidationSnippet from "../components/ReportValidationSnippet";',
        'import ReportValidationSnippet from "../components/ReportValidationSnippet";\n'
        'import PdfExportReadinessSnippet from "../components/PdfExportReadinessSnippet";',
        'Dashboard imports')
    return replace_one(src,
        '<ReportValidationSnippet review={report.report_validation_review} />',
        '<ReportValidationSnippet review={report.report_validation_review} />\n'
        '          <PdfExportReadinessSnippet review={report.pdf_export_review} />',
        'Dashboard review order')


def patch_pdf(src: str) -> str:
    src = replace_one(src, '  section("Assessment coverage");',
        PDF_BLOCK + '  section("Assessment coverage");', 'PDF detailed sections')
    src = replace_one(src, SAVE_OLD, SAVE_NEW, 'browser export')
    if 'import { inspectPdfExport, downloadVerifiedPdf } from "./pdfExportIntegrity";' not in src:
        anchor = 'import type { jsPDF } from "jspdf";'
        src = replace_one(src, anchor,
            anchor + '\nimport { inspectPdfExport, downloadVerifiedPdf } from "./pdfExportIntegrity";',
            'PDF integrity import')
    return src


def plan(frontend: Path) -> dict[Path, bytes]:
    frontend = frontend.resolve()
    if not (frontend/'package.json').is_file(): raise ValueError(f'Not a frontend root: {frontend}')
    changes: dict[Path,bytes] = {}
    for rel, patch in (
        ('src/api/universal.ts', patch_api),
        ('src/pages/UniversalAnalysis.tsx', patch_dashboard),
        ('src/utils/normalizedPdf.ts', patch_pdf),
    ):
        dst = frontend/rel
        if not dst.is_file(): raise ValueError(f'Missing API-011.2 file: {dst}')
        old_bytes = dst.read_bytes()
        # Preserve CRLF + BOM for existing source files.
        bom = old_bytes.startswith(b'\xef\xbb\xbf')
        old = old_bytes.decode('utf-8-sig')
        line_ending = '\r\n' if '\r\n' in old else '\n'
        canonical = old.replace('\r\n', '\n')
        updated = patch(canonical)
        if updated != canonical:
            new_bytes = (b'\xef\xbb\xbf' if bom else b'') + updated.replace('\n',line_ending).encode('utf-8')
            changes[dst] = new_bytes
    for rel in ('src/components/PdfExportReadinessSnippet.tsx',
                'src/components/PdfExportReadinessSnippet.css',
                'src/utils/pdfExportIntegrity.ts'):
        src = PACKAGE/rel
        if not src.is_file(): raise ValueError(f'Package file missing: {src}')
        dst=frontend/rel
        if dst.is_file() and dst.read_bytes()!=src.read_bytes():
            raise ValueError(f'Refusing to overwrite a customized file: {dst}')
        if not dst.exists(): changes[dst]=src.read_bytes()
    return changes


def install(frontend: Path) -> list[str]:
    # The combined installer is preferred because it creates rollback metadata.
    from shutil import copy2
    frontend=frontend.resolve()
    changes=plan(frontend)
    for dst,data in changes.items():
        dst.parent.mkdir(parents=True,exist_ok=True)
        backup=dst.with_name(dst.name+'.before_api0113.bak')
        if dst.is_file() and not backup.exists(): copy2(dst,backup)
        dst.write_bytes(data)
    return [dst.relative_to(frontend).as_posix() for dst in changes]


if __name__=='__main__':
    root=Path(sys.argv[1]) if len(sys.argv)==2 else Path.cwd()/'frontend'
    if len(sys.argv)>2: sys.exit('Usage: install_api_011_3_frontend.py [frontend-root]')
    try: result=install(root)
    except (OSError,ValueError,UnicodeError) as exc: sys.exit(f'ERROR: {exc}')
    print('Changed:', result)
