"""Install dashboard-only review heading styles without changing review logic.

Only one import in frontend/src/pages/UniversalAnalysis.tsx and one standalone CSS
file are modified. Safe UTF-8/BOM and CRLF handling; idempotent with rollback.
"""
from __future__ import annotations
import sys
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1]
SOURCE_CSS = PACKAGE / 'src/pages/ReviewHeadingAccents.css'
REL_PAGE = Path('src/pages/UniversalAnalysis.tsx')
REL_CSS = Path('src/pages/ReviewHeadingAccents.css')
IMPORT = 'import "./ReviewHeadingAccents.css";'
ANCHORS = (
    'import "./DashboardHeadingHighlights.css";',
    'import "./UnifiedDashboardExtras.css";',
    'import "./UniversalAnalysis.css";',
)


def decode(raw: bytes) -> tuple[str, str, str]:
    bom = '\ufeff' if raw.startswith(b'\xef\xbb\xbf') else ''
    source = raw.decode('utf-8-sig')
    newline = '\r\n' if b'\r\n' in raw else '\n'
    return bom, source, newline


def plan(root: Path) -> dict[Path, bytes]:
    root = root.resolve()
    if not (root / 'package.json').is_file():
        raise ValueError('Expected frontend root containing package.json')
    path = root / REL_PAGE
    bom, source, newline = decode(path.read_bytes())
    if source.count(IMPORT) > 1:
        raise ValueError('Duplicate review accent imports; refusing changes')
    changes: dict[Path, bytes] = {}
    if IMPORT not in source:
        for anchor in ANCHORS:
            if source.count(anchor) == 1:
                updated = source.replace(anchor, anchor + newline + IMPORT, 1)
                changes[path] = (bom + updated).encode('utf-8')
                break
        else:
            raise ValueError('No expected dashboard CSS import found; refusing changes')
    css_path = root / REL_CSS
    expected_css = SOURCE_CSS.read_bytes()
    if css_path.exists():
        if css_path.read_bytes() != expected_css:
            raise ValueError('ReviewHeadingAccents.css already exists with different content; refusing overwrite')
    else:
        changes[css_path] = expected_css
    return changes


def install(root: Path) -> list[str]:
    root = root.resolve()
    changes = plan(root)   # Read and validate all targets before writing
    written: list[Path] = []
    try:
        for path, contents in changes.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.exists():
                backup = path.with_name(path.name + '.before_review_accents.bak')
                if not backup.exists():
                    backup.write_bytes(path.read_bytes())
            path.write_bytes(contents)
            written.append(path)
    except OSError:
        for path in reversed(written):
            backup = path.with_name(path.name + '.before_review_accents.bak')
            if backup.exists():
                path.write_bytes(backup.read_bytes())
            else:
                path.unlink(missing_ok=True)
        raise
    return [p.relative_to(root).as_posix() for p in changes]


if __name__ == '__main__':
    if len(sys.argv) != 2:
        sys.exit('Usage: install_review_heading_accents.py <frontend-root>')
    try:
        changed = install(Path(sys.argv[1]))
    except (OSError, ValueError, UnicodeError) as exc:
        sys.exit(f'Installation cancelled: {exc}')
    print('Updated: ' + ', '.join(changed) if changed else 'Already installed; nothing changed.')
