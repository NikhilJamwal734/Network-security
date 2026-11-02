"""Remove milestone/debug clutter and highlight available dashboard exports.

Usage from the backend project root:
  .\\.venv-win\\Scripts\\python.exe dashboard_cleanup_patch\\scripts\\install_dashboard_cleanup.py

Backs up every changed existing file once. Idempotent. Does not touch the backend.
"""
from __future__ import annotations

from pathlib import Path
import re
import shutil
import sys

PACKAGE = Path(__file__).resolve().parents[1]
PROJECT = PACKAGE.parent
FRONTEND = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else PROJECT / 'frontend'


def update_dashboard(source: str) -> str:
    """Remove the optional bundle panel from Dashboard, not the backend API."""
    importer = re.compile(
        r'^import\s+IDSRuleBundlePanel\s+from\s+[\'\"]\.\./components/IDSRuleBundlePanel[\'\"];\s*\n',
        re.MULTILINE,
    )
    widget = re.compile(r'^[ \t]*<IDSRuleBundlePanel\b[^>]*?/>[ \t]*\n', re.MULTILINE | re.DOTALL)
    has_import = bool(importer.search(source))
    has_widget = bool(widget.search(source))
    if has_import != has_widget:
        raise ValueError('IDS rule panel was partially modified; no files changed')
    if has_import:
        if len(importer.findall(source)) != 1 or len(widget.findall(source)) != 1:
            raise ValueError('Unexpected duplicate IDS panel imports or markup; no files changed')
        source = importer.sub('', source, count=1)
        source = widget.sub('', source, count=1)

    # Remove developer milestones/schema jargon, without hiding meaningful coverage details.
    source = source.replace('SECURITY ANALYSIS / DASHBOARD', 'CONFIGURATION ANALYSIS')
    source = re.sub(
        r'<p className="ua-eyebrow">NORMALIZED REPORT\s*·\s*SCHEMA\s*\{report\.schema_version\}</p>',
        '<p className="ua-eyebrow">ANALYSIS RESULTS</p>', source,
    )
    source = source.replace('<span className="ua-pill">Static analysis only</span>', '')
    source = source.replace(
        'Select a file and a platform to begin. Cisco ASA detail pages become available after a successful ASA analysis.',
        'Choose a configuration file to view findings, severity and reports.'
    )

    # The inline JSON export is also rendered only after report exists.
    pattern = re.compile(
        r'(<button\s+className=")ua-secondary("\s+type="button"\s+onClick=\{\(\)\s*=>\s*exportReport\(report,\s*analyzedFile\)\})',
    )
    if 'exportReport(report, analyzedFile)' in source and 'ua-download-ready' not in source:
        source, count = pattern.subn(r'\1ua-secondary ua-download-ready\2', source)
        if count != 1:
            raise ValueError('JSON export button markup changed; cannot style it safely')
    return source


def update_assessment(source: str) -> str:
    # Keep the explanation of provisional scoring and the coverage limitation.
    return source.replace('API-009.8 / FOUR-PLATFORM ASSESSMENT', 'SECURITY REVIEW')


def update_app(source: str) -> str:
    statement = 'import "./DashboardDownloadHighlight.css";'
    if statement in source:
        return source
    css_imports = list(re.finditer(
        r'(?m)^import\s+[\'\"][^\'\"]+\.css[\'\"];?[ \t]*\n', source,
    ))
    if not css_imports:
        raise ValueError('App.tsx has no known stylesheet imports; no files changed')
    anchor = css_imports[-1].end()
    return source[:anchor] + statement + '\n' + source[anchor:]


def plan() -> dict[Path, bytes]:
    page = FRONTEND / 'src/pages/UniversalAnalysis.tsx'
    app = FRONTEND / 'src/App.tsx'
    assessment = FRONTEND / 'src/components/AdvancedAssessmentPanel.tsx'
    css = FRONTEND / 'src/DashboardDownloadHighlight.css'
    if not (FRONTEND / 'package.json').is_file() or not page.is_file() or not app.is_file():
        raise ValueError('Expected frontend/package.json, src/App.tsx and src/pages/UniversalAnalysis.tsx')
    payload = {
        page: update_dashboard(page.read_text(encoding='utf-8-sig')).encode('utf-8'),
        app: update_app(app.read_text(encoding='utf-8-sig')).encode('utf-8'),
        css: (PACKAGE / 'src/DashboardDownloadHighlight.css').read_bytes(),
    }
    if assessment.is_file():
        payload[assessment] = update_assessment(assessment.read_text(encoding='utf-8-sig')).encode('utf-8')
    return payload


def install() -> list[str]:
    updates = plan()  # Validate ALL anchor changes before writing anything.
    log = []
    for target, data in updates.items():
        if target.is_file() and target.read_bytes() == data:
            log.append(f'Unchanged: {target.relative_to(FRONTEND)}')
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            backup = target.with_name(target.name + '.before_dashboard_cleanup.bak')
            if not backup.exists():
                shutil.copy2(target, backup)
        target.write_bytes(data)
        log.append(f'Updated: {target.relative_to(FRONTEND)}')
    return log


if __name__ == '__main__':
    try:
        print('Frontend:', FRONTEND)
        for msg in install():
            print(msg)
    except (OSError, ValueError) as error:
        print('ERROR:', error, file=sys.stderr)
        sys.exit(1)
