"""Remove only CSS imports added by the Dashboard heading-highlights patch.

Does not restore whole TSX files, so subsequent user edits are not discarded.
"""
from __future__ import annotations

from pathlib import Path
import sys
from install_heading_highlights import REL_CSS, VIEWS, IMPORT, CSS, _decode


def rollback(root: Path) -> list[str]:
    root = root.resolve()
    planned: dict[Path, bytes] = {}
    for rel, _ in VIEWS:
        path = root / rel
        bom, source, nl = _decode(path.read_bytes())
        if source.count(IMPORT) > 1:
            raise ValueError(f'{rel}: duplicate patch imports; no changes made')
        if IMPORT in source:
            for chunk in (IMPORT + nl, nl + IMPORT):
                if chunk in source:
                    source = source.replace(chunk, '', 1)
                    break
            else:
                raise ValueError(f'{rel}: patch import has unexpected formatting')
            planned[path] = (bom + source).encode('utf-8')
    stylesheet = root / REL_CSS
    if stylesheet.exists() and stylesheet.read_bytes() != CSS.read_bytes():
        raise ValueError('Stylesheet has changed; refusing to delete a modified file')
    for path, data in planned.items():
        path.write_bytes(data)
    if stylesheet.exists():
        stylesheet.unlink()
    return [p.relative_to(root).as_posix() for p in planned]


if __name__ == '__main__':
    if len(sys.argv) != 2:
        sys.exit('Usage: rollback_heading_highlights.py <frontend-directory>')
    try:
        modified = rollback(Path(sys.argv[1]))
    except (OSError, ValueError, UnicodeError) as exc:
        sys.exit(f'Rollback cancelled: {exc}')
    print('Removed heading highlights from: ' + ', '.join(modified) if modified else 'No heading imports to remove.')
