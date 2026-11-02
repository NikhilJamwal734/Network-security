"""Set visible frontend exports to PDF-only and enlarge PDF section/finding references.

Usage from the BACKEND project root:
  .\\.venv-win\\Scripts\\python.exe pdf_only_ui_patch\\scripts\\apply_pdf_only_ui.py

Optional argument: full frontend path. Makes .before_pdf_only_ui.bak backups.
No backend behavior is modified. All edits are prepared before anything is written.
"""
from __future__ import annotations

import re
import shutil
import sys
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1]
PROJECT = PACKAGE.parent
FRONTEND = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else PROJECT / "frontend"
BACKUP_SUFFIX = ".before_pdf_only_ui.bak"


def delete_function(source: str, name: str) -> str:
    """Remove a known, file-local helper with balanced function braces."""
    match = re.search(rf"(?m)^function\s+{re.escape(name)}\s*\(", source)
    if not match:
        return source
    start = match.start()
    brace = source.find("{", match.end())
    if brace < 0:
        raise ValueError(f"Function {name} has no body; refusing edit")
    depth = 0
    end = -1
    for pos in range(brace, len(source)):
        if source[pos] == "{":
            depth += 1
        elif source[pos] == "}":
            depth -= 1
            if depth == 0:
                end = pos + 1
                break
    if end < 0:
        raise ValueError(f"Function {name} body is incomplete; refusing edit")
    # Only delete when the code is specifically the known normalized JSON helper.
    body = source[start:end]
    if name == "exportReport" and ('normalized.json' not in body or 'JSON.stringify' not in body):
        raise ValueError("Unexpected exportReport implementation; refusing edit")
    if name == "safeExportName" and 'replace(' not in body:
        raise ValueError("Unexpected safeExportName implementation; refusing edit")
    return source[:start] + source[end:].lstrip("\n") if start == 0 else source[:start].rstrip("\n") + "\n\n" + source[end:].lstrip("\n")


def remove_json_buttons(source: str, filename: str) -> str:
    """Drop only visible JSON export buttons; do not touch PDF buttons."""
    pattern = re.compile(r"(?is)<button\b[^>]*>.*?</button>")
    output = []
    offset = 0
    for match in pattern.finditer(source):
        body = match.group()
        is_json = bool(re.search(r"(?i)(?:download|export)(?:\s+normalized)?\s+JSON\b", body)) or (
            'downloadNormalizedJson(' in body or 'exportReport(report, analyzedFile)' in body
        )
        is_pdf = bool(re.search(r"(?i)(?:download|export)\s+PDF\b", body))
        if is_json and not is_pdf:
            output.append(source[offset:match.start()])
            offset = match.end()
    output.append(source[offset:])
    return "".join(output)


def patch_app(source: str) -> str:
    source = re.sub(r'(?m)^[ \t]*import\s+JsonReportDownload\s+from\s+[\'\"][^\'\"]+[\'\"];?[ \t]*\r?\n', '', source)
    source = re.sub(r'(?m)^[ \t]*<JsonReportDownload\s*/>[ \t]*\r?\n', '', source)
    # Guard against orphaned usage if syntax differs.
    if 'JsonReportDownload' in source:
        raise ValueError("App.tsx contains an unrecognized JSON export control")
    return source


def patch_shared_downloads(source: str) -> str:
    source = remove_json_buttons(source, 'NormalizedReportDownloads.tsx')
    # Support normalizedPdf exports on either the same or separate import lines.
    source = re.sub(r',\s*downloadNormalizedJson\b', '', source)
    source = re.sub(r'\bdownloadNormalizedJson\s*,\s*', '', source)
    if re.search(r'\bdownloadNormalizedJson\b', source):
        raise ValueError('Unrecognized JSON download import/control in NormalizedReportDownloads.tsx')
    if 'downloadNormalizedPdf' not in source:
        raise ValueError('Normalized PDF download was not found; refusing edit')
    return source


def patch_dashboard(source: str) -> str:
    source = remove_json_buttons(source, 'UniversalAnalysis.tsx')
    if 'exportReport(report, analyzedFile)' in source:
        raise ValueError('JSON button in Dashboard did not match known markup')
    if 'function exportReport(' in source:
        source = delete_function(source, 'exportReport')
    # safeExportName is used only by exportReport in the original dashboard.
    if 'function safeExportName(' in source:
        references = source.count('safeExportName(')
        if references == 1:
            source = delete_function(source, 'safeExportName')
        else:
            raise ValueError('safeExportName is used elsewhere; refusing edit to avoid breaking frontend')
    return source


def patch_report_page(source: str) -> str:
    source = source.replace(
        'Both files contain the same normalized findings and coverage. PDF is formatted for reading; JSON is suitable for further processing.',
        'Download the assessment as a formatted PDF, including findings, evidence and coverage limits.',
    )
    return source


def patch_pdf(source: str) -> str:
    if 'function section(title: string)' not in source or 'Finding details and recommendations' not in source:
        raise ValueError('Professional normalized PDF layout not recognized; refusing edit')
    # jsPDF public method (earlier package called internal.getNumberOfPages by mistake).
    source = source.replace('pdf.internal.getNumberOfPages()', 'pdf.getNumberOfPages()')

    section_start = source.index('function section(title: string)')
    section_end = source.index('function metricBox(', section_start)
    section = source[section_start:section_end]
    # Match section serial with section title 12.5 pt, same baseline.
    section, n = re.subn(r'pdf\.setFontSize\(8\.4\);(\s*setInk\(pdf, COLORS\.teal\);\s*pdf\.text\(String\(sectionIndex\))', r'pdf.setFontSize(12.5);\1', section, count=1)
    if n != 1 and 'pdf.setFontSize(12.5);\n    setInk(pdf, COLORS.teal);' not in section:
        raise ValueError('Section serial number anchor not found; refusing edit')
    source = source[:section_start] + section + source[section_end:]

    # Findings register: align serial and adjacent title font size at 10 pt.
    register_start = source.index('section("Findings register")')
    details_start = source.index('section("Finding details and recommendations")')
    register = source[register_start:details_start]
    register = register.replace('pdf.setFontSize(8.3);', 'pdf.setFontSize(10);')
    source = source[:register_start] + register + source[details_start:]

    # Detailed findings reference and title get the same 11.2pt font.
    detail_end = source.index('if (report.assessment)', details_start)
    detail = source[details_start:detail_end]
    detail = detail.replace('pdf.setFontSize(10.4);', 'pdf.setFontSize(11.2);')
    detail = detail.replace('text(finding.title, { bold: true, size: 10.2,', 'text(finding.title, { bold: true, size: 11.2,')
    source = source[:details_start] + detail + source[detail_end:]

    # PDF-only UX: do not direct readers to removed JSON download controls.
    source = source.replace('[shortened in PDF; full value in JSON]', '[shortened for readability]')
    source = source.replace('Export JSON for the complete set.', 'The remaining findings can be reviewed in the application.')
    source = source.replace('more observations omitted from PDF; see JSON.', 'additional observations not included in this PDF; review them in the application.')
    return source


def plan() -> dict[Path, bytes]:
    if not (FRONTEND / 'package.json').is_file():
        raise ValueError(f'Frontend package.json not found: {FRONTEND}')
    actions = {
        Path('src/utils/normalizedPdf.ts'): patch_pdf,
        Path('src/App.tsx'): patch_app,
        Path('src/pages/UniversalAnalysis.tsx'): patch_dashboard,
        Path('src/components/NormalizedReportDownloads.tsx'): patch_shared_downloads,
        Path('src/pages/NormalizedReportsPage.tsx'): patch_report_page,
    }
    essential = {Path('src/utils/normalizedPdf.ts'), Path('src/App.tsx'), Path('src/pages/UniversalAnalysis.tsx')}
    updates: dict[Path, bytes] = {}
    for relative, function in actions.items():
        target = FRONTEND / relative
        if not target.is_file():
            if relative in essential:
                raise ValueError(f'Required frontend file missing: {target}')
            continue
        original = target.read_text(encoding='utf-8-sig')
        updated = function(original)
        if updated != original:
            updates[target] = updated.encode('utf-8')

    # Existing ASA Reports.tsx may directly embed the JsonReportDownload component.
    asa_reports = FRONTEND / 'src/pages/Reports.tsx'
    if asa_reports.is_file():
        original = asa_reports.read_text(encoding='utf-8-sig')
        if 'JsonReportDownload' in original:
            updated = patch_app(original)
            if updated != original:
                updates[asa_reports] = updated.encode('utf-8')

    return updates


def install() -> list[str]:
    updates = plan()  # Validate before modifying any file.
    messages = []
    for target, content in updates.items():
        backup = target.with_name(target.name + BACKUP_SUFFIX)
        if not backup.exists():
            shutil.copy2(target, backup)
        target.write_bytes(content)
        messages.append(f'Updated: {target.relative_to(FRONTEND)} (backup: {backup.name})')
    if not messages:
        messages.append('Already applied: no further changes needed')
    return messages


if __name__ == '__main__':
    try:
        print('Frontend:', FRONTEND)
        for message in install():
            print(message)
        print('Run npm run build in the frontend folder to verify TypeScript and Vite.')
    except (OSError, ValueError) as exc:
        print(f'ERROR: {exc}', file=sys.stderr)
        sys.exit(1)
