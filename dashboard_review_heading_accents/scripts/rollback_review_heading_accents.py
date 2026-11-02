"""Remove only this patch's CSS import/file, preserving later edits."""
from __future__ import annotations
import sys
from pathlib import Path
PACKAGE = Path(__file__).resolve().parents[1]
SOURCE_CSS = PACKAGE / 'src/pages/ReviewHeadingAccents.css'
REL_PAGE = Path('src/pages/UniversalAnalysis.tsx')
REL_CSS = Path('src/pages/ReviewHeadingAccents.css')
IMPORT = 'import "./ReviewHeadingAccents.css";'


def decode(raw: bytes) -> tuple[str, str, str]:
    bom = '\ufeff' if raw.startswith(b'\xef\xbb\xbf') else ''
    source = raw.decode('utf-8-sig')
    newline = '\r\n' if b'\r\n' in raw else '\n'
    return bom, source, newline


def rollback(root: Path) -> list[str]:
    root = root.resolve()
    path = root / REL_PAGE
    bom, source, nl = decode(path.read_bytes())
    css = root / REL_CSS
    if css.exists() and css.read_bytes() != SOURCE_CSS.read_bytes():
        raise ValueError('Custom review heading CSS has changed; rollback cancelled')
    updated = source.replace(IMPORT + nl, '', 1) if IMPORT in source else source
    if updated == source and not css.exists():
        return []
    changed = []
    if updated != source:
        path.write_bytes((bom + updated).encode('utf-8'))
        changed.append(REL_PAGE.as_posix())
    if css.exists():
        css.unlink()
        changed.append(REL_CSS.as_posix())
    return changed

if __name__ == '__main__':
    if len(sys.argv) != 2:
        sys.exit('Usage: rollback_review_heading_accents.py <frontend-root>')
    try:
        result = rollback(Path(sys.argv[1]))
    except (OSError, ValueError, UnicodeError) as exc:
        sys.exit(f'Rollback cancelled: {exc}')
    print('Restored: ' + ', '.join(result) if result else 'Nothing to rollback.')
