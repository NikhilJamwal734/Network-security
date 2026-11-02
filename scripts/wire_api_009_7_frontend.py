"""API-009.7: safely add the universal page to an existing Vite src/App.tsx.

No other existing file is edited. Makes a timestamp-free one-time backup.
Refuses to edit when expected legacy anchors are missing or ambiguous.
Reruns are idempotent. Run from repository root.
"""
from pathlib import Path
import shutil
import sys

APP = Path('src/App.tsx')
BACKUP = Path('src/App.tsx.api0096.backup')


def patch_app(source: str) -> str:
    marker = 'const UniversalAnalysis = lazy(() => import("./pages/UniversalAnalysis"));'
    if marker in source:
        # Cannot assume arbitrary partial edits are correct; verify all required anchors.
        required = (
            '| "Universal Analysis"',
            '{ label: "Universal Analysis", icon: "◎" }',
            'activePage === "Universal Analysis"',
            '<UniversalAnalysis />',
        )
        if all(item in source for item in required):
            return source
        raise ValueError('Partial API-009.7 wiring detected. Resolve manually; no file changed.')

    operations = (
        (
            'const Dashboard = lazy(() => import("./pages/Dashboard"));',
            marker + '\nconst Dashboard = lazy(() => import("./pages/Dashboard"));',
        ),
        (
            '  | "Dashboard"\n',
            '  | "Universal Analysis"\n  | "Dashboard"\n',
        ),
        (
            '  { label: "Dashboard", icon: "▦" },',
            '  { label: "Universal Analysis", icon: "◎" },\n  { label: "Dashboard", icon: "▦" },',
        ),
        (
            'useState<PageName>("Dashboard")',
            'useState<PageName>("Universal Analysis")',
        ),
        (
            '            {activePage === "Dashboard" && (',
            '            {activePage === "Universal Analysis" && (\n              <UniversalAnalysis />\n            )}\n\n            {activePage === "Dashboard" && (',
        ),
    )
    patched = source
    for old, new in operations:
        if patched.count(old) != 1:
            raise ValueError(f'Expected exactly one App.tsx anchor: {old!r}; found {patched.count(old)}. No files changed.')
        patched = patched.replace(old, new, 1)

    # Topbar JSON/PDF exporters read ONLY the legacy Cisco ASA AnalysisContext.
    # Hide these stale exports on the new page, which offers its own normalized JSON export.
    old_exports = '''            <div className="fa-topbar-downloads">
              <JsonReportDownload />
              <PdfReportDownload />
            </div>'''
    new_exports = '''            {activePage !== "Universal Analysis" && (
              <div className="fa-topbar-downloads">
                <JsonReportDownload />
                <PdfReportDownload />
              </div>
            )}'''
    if patched.count(old_exports) != 1:
        raise ValueError('Legacy export toolbar differs from expected shape. No files changed.')
    patched = patched.replace(old_exports, new_exports, 1)

    # Rebrand the shell only when legacy markup is exactly as expected.
    patched = patched.replace(
        '<div className="brand-title">\n              Firewall\n            </div>',
        '<div className="brand-title">\n              Network Security\n            </div>',
        1,
    )
    patched = patched.replace('              Firewall Analyzer\n', '              Security Analyzer\n', 1)
    return patched


def main() -> int:
    if not APP.is_file():
        print(f'ERROR: {APP} not found. Run this script from the project root.', file=sys.stderr)
        return 2
    for needed in ('src/pages/UniversalAnalysis.tsx', 'src/pages/UniversalAnalysis.css', 'src/api/universal.ts'):
        if not Path(needed).is_file():
            print(f'ERROR: {needed} missing. Extract the API-009.7 ZIP to the project root first.', file=sys.stderr)
            return 2
    original = APP.read_text(encoding='utf-8-sig')
    try:
        updated = patch_app(original)
    except ValueError as error:
        print(f'ERROR: {error}', file=sys.stderr)
        return 2
    if updated == original:
        print('App.tsx already wired for API-009.7; no changes needed.')
        return 0
    if BACKUP.exists():
        print(f'ERROR: Backup {BACKUP} already exists. Check before overwriting.', file=sys.stderr)
        return 2
    shutil.copy2(APP, BACKUP)
    APP.write_text(updated, encoding='utf-8')
    print(f'Updated: {APP}')
    print(f'Original backed up: {BACKUP}')
    print('New universal page is the default; original Cisco ASA dashboard remains in navigation.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
