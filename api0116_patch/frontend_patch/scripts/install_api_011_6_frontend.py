"""Plan frontend API-011.6 URL/type + PDF-only evidence; no dashboard changes."""
from __future__ import annotations
from pathlib import Path
import sys

TYPES = '''
/** API-011.6: accepted input checks, not a general security guarantee. */
export interface InputSecurityReview {
  version: "1.0";
  status: "accepted";
  scope: "single_file_text_input_precheck";
  summary: { byte_count: number; line_count: number; checks_passed: number };
  sha256: string;
  checks: Array<{ name: string; result: "pass" }>;
  limitations: string[];
}
'''
PDF_BLOCK = '''  if (report.input_security_review) {
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

'''


def replace_once(src: str, old: str, new: str, label: str) -> str:
    if src.count(new) == 1:
        return src
    if src.count(old) != 1 or src.count(new) != 0:
        raise ValueError(f'API-011.6 ambiguous/missing {label} anchor')
    return src.replace(old, new, 1)


def patch_api(src: str) -> str:
    src = replace_once(src, '/api/v1/analyze/pipeline-validation',
                       '/api/v1/analyze/hardened', 'frontend request URL')
    src = replace_once(src, '  pipeline_validation_review?: PipelineValidationReview;',
                       '  pipeline_validation_review?: PipelineValidationReview;\n  input_security_review?: InputSecurityReview;',
                       'frontend response field')
    if 'export interface InputSecurityReview {' not in src:
        src = src.rstrip('\n') + '\n' + TYPES
    elif src.count('export interface InputSecurityReview {') != 1:
        raise ValueError('Duplicate API-011.6 input review types')
    return src


def patch_pdf(src: str) -> str:
    marker = '    section("Upload input validation — Detailed evidence");'
    if marker in src:
        if src.count(marker) != 1:
            raise ValueError('Duplicate API-011.6 PDF section')
        return src
    if src.count('  section("Assessment coverage");') != 1:
        raise ValueError('Missing or ambiguous PDF section insertion anchor')
    return src.replace('  section("Assessment coverage");', PDF_BLOCK + '  section("Assessment coverage");', 1)


def plan(root: Path) -> dict[Path, bytes]:
    root = root.resolve()
    if not (root / 'package.json').is_file():
        raise ValueError('Not a React frontend root (missing package.json)')
    changes = {}
    for rel, patch in (('src/api/universal.ts', patch_api), ('src/utils/normalizedPdf.ts', patch_pdf)):
        dst = root / rel
        if not dst.is_file() or dst.is_symlink():
            raise ValueError(f'Missing or linked prerequisite file: {dst}')
        raw = dst.read_bytes()
        bom = raw.startswith(b'\xef\xbb\xbf')
        src = raw.decode('utf-8-sig')
        eol = '\r\n' if '\r\n' in src else '\n'
        canonical = src.replace('\r\n', '\n')
        result = patch(canonical)
        updated = (b'\xef\xbb\xbf' if bom else b'') + result.replace('\n', eol).encode('utf-8')
        if updated != raw:
            changes[dst] = updated
    return changes


if __name__ == '__main__':
    root = Path(sys.argv[1]) if len(sys.argv) == 2 else Path.cwd() / 'frontend'
    if len(sys.argv) > 2:
        sys.exit('Usage: install_api_011_6_frontend.py [frontend-root]')
    try:
        for dest in plan(root):
            print(dest)
    except (OSError, UnicodeError, ValueError) as exc:
        sys.exit(f'ERROR: {exc}')
