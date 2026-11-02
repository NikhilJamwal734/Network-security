"""Add scoped, visual-only Dashboard heading highlights.

No JSX elements or application logic are modified. One CSS import is added to
UniversalAnalysis and Dashboard, and a new stylesheet is installed beside them.
Preserves UTF-8 BOM / CRLF, refuses unsafe or unknown layouts, and is idempotent.
"""
from __future__ import annotations

from pathlib import Path
import sys

PACKAGE = Path(__file__).resolve().parents[1]
CSS = PACKAGE / 'src/pages/DashboardHeadingHighlights.css'
REL_CSS = Path('src/pages/DashboardHeadingHighlights.css')
VIEWS = (
    (Path('src/pages/UniversalAnalysis.tsx'), ('import "./UnifiedDashboardExtras.css";', 'import "./UniversalAnalysis.css";')),
    (Path('src/pages/Dashboard.tsx'), ('import "./Dashboard.css";',)),
)
IMPORT = 'import "./DashboardHeadingHighlights.css";'
BACKUP = '.before_heading_highlights.bak'


def _decode(raw: bytes) -> tuple[str, str, str]:
    bom = '\ufeff' if raw.startswith(b'\xef\xbb\xbf') else ''
    source = raw.decode('utf-8-sig')  # invalid UTF-8 must stop installation
    nl = '\r\n' if b'\r\n' in raw else '\n'
    return bom, source, nl


def _patch_import(text: str, anchors: tuple[str, ...], nl: str) -> str:
    if IMPORT in text:
        if text.count(IMPORT) != 1:
            raise ValueError('Duplicate heading stylesheet imports; no changes made')
        return text
    for anchor in anchors:
        if text.count(anchor) == 1:
            return text.replace(anchor, anchor + nl + IMPORT, 1)
    raise ValueError('Expected dashboard stylesheet import not found; no changes made')


def plan(root: Path) -> dict[Path, bytes]:
    root = root.resolve()
    if not (root / 'package.json').is_file():
        raise ValueError('Expected the frontend directory containing package.json')
    planned: dict[Path, bytes] = {}
    for rel, anchors in VIEWS:
        target = root / rel
        bom, source, nl = _decode(target.read_bytes())
        updated = _patch_import(source, anchors, nl)
        if updated != source:
            planned[target] = (bom + updated).encode('utf-8')
    target_css = root / REL_CSS
    css_bytes = CSS.read_bytes()
    if target_css.exists():
        if target_css.read_bytes() != css_bytes:
            raise ValueError(f'{target_css}: existing custom stylesheet differs; refusing overwrite')
    else:
        planned[target_css] = css_bytes
    return planned


def install(root: Path) -> list[str]:
    root = root.resolve()
    planned = plan(root)  # preflight all files before writing anything
    # No existing backup is ever overwritten by a repeat installation.
    for path in planned:
        if path.exists():
            backup = path.with_name(path.name + BACKUP)
            if not backup.exists():
                backup.write_bytes(path.read_bytes())
    written: list[Path] = []
    try:
        for path, data in planned.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            written.append(path)
    except Exception:
        for path in reversed(written):
            backup = path.with_name(path.name + BACKUP)
            if backup.exists():
                path.write_bytes(backup.read_bytes())
            else:
                path.unlink(missing_ok=True)
        raise
    return [p.relative_to(root).as_posix() for p in planned]


if __name__ == '__main__':
    if len(sys.argv) != 2:
        sys.exit('Usage: install_heading_highlights.py <frontend-directory>')
    try:
        modified = install(Path(sys.argv[1]))
    except (OSError, ValueError, UnicodeError) as exc:
        sys.exit(f'Heading highlight installation cancelled: {exc}')
    print('Updated: ' + ', '.join(modified) if modified else 'Already installed; no changes made.')
