"""API-011.2 backend: validate all anchors before modifying any file."""
from __future__ import annotations
from pathlib import Path
import shutil
import sys

PACKAGE = Path(__file__).resolve().parents[1]
BACKUP = '.before_api0112.bak'
IMPORT = 'from app.api.report_validation import router as report_validation_router'
INCLUDE = 'app.include_router(report_validation_router)'
IMPORT_ANCHOR = 'from app.api.correlation_accuracy import router as correlation_accuracy_router\n'
INCLUDE_ANCHOR = 'app.include_router(correlation_accuracy_router)\n'


def insert(source: str, anchor: str, value: str, name: str) -> str:
    if source.count(value) == 1:
        return source
    if source.count(anchor) != 1:
        raise ValueError(f'{name}: missing or ambiguous API-011.1 anchor')
    return source.replace(anchor, anchor+value+'\n', 1)


def plan(root: Path) -> dict[Path, bytes]:
    root = root.resolve()
    for rel in ('app/api/main.py', 'app/api/correlation_accuracy.py', 'app/core/correlation_accuracy.py'):
        if not (root / rel).is_file():
            raise ValueError(f'Install API-011.1 first, missing: {root / rel}')
    dst = root/'app/api/main.py'
    old = dst.read_text(encoding='utf-8-sig')
    if (IMPORT in old) != (INCLUDE in old):
        raise ValueError('Partial API-011.2 router registration')
    new = insert(old, IMPORT_ANCHOR, IMPORT, 'router import')
    new = insert(new, INCLUDE_ANCHOR, INCLUDE, 'router include')
    changes: dict[Path, bytes] = {}
    if new != old: changes[dst] = new.encode('utf-8')
    for rel in ('app/api/report_validation.py', 'app/core/report_validation.py',
                'tests/test_api_011_2_report_validation.py'):
        src = PACKAGE / rel
        if not src.is_file(): raise ValueError(f'Packaged file missing: {src}')
        dest = root/rel
        contents = src.read_bytes()
        if not dest.is_file() or dest.read_bytes() != contents:
            changes[dest] = contents
    return changes


def install(root: Path) -> list[str]:
    root = root.resolve()
    changes = plan(root)
    for dst, content in changes.items():
        dst.parent.mkdir(parents=True, exist_ok=True)
        bak = dst.with_name(dst.name + BACKUP)
        if dst.is_file() and not bak.exists(): shutil.copy2(dst, bak)
        dst.write_bytes(content)
    return [str(dst.relative_to(root)) for dst in changes]


if __name__ == '__main__':
    target = Path(sys.argv[1]) if len(sys.argv) == 2 else Path.cwd()
    if len(sys.argv) > 2: sys.exit('Usage: install_api_011_2.py [project-root]')
    try: changed = install(target)
    except (OSError, ValueError, UnicodeError) as exc: sys.exit(f'ERROR: {exc}')
    print('API-011.2 backend installed:' if changed else 'API-011.2 backend already installed:')
    for rel in changed: print('  ' + rel)
