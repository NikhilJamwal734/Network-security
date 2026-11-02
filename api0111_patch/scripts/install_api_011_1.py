"""Fail-before-write, idempotent API-011.1 backend patch installer."""
from __future__ import annotations
from pathlib import Path
import shutil
import sys

PACKAGE = Path(__file__).resolve().parents[1]
BACKUP = '.before_api0111.bak'
IMPORT = 'from app.api.correlation_accuracy import router as correlation_accuracy_router'
INCLUDE = 'app.include_router(correlation_accuracy_router)'
IMPORT_ANCHOR = 'from app.api.consolidation import router as consolidation_router\n'
INCLUDE_ANCHOR = 'app.include_router(consolidation_router)\n'


def replace_once(source: str, old: str, new: str, description: str) -> str:
    if new in source:
        return source
    if source.count(old) != 1:
        raise ValueError(f'{description}: expected exactly one API-011.0 anchor')
    return source.replace(old, new, 1)


def patch_main(original: str) -> str:
    if (IMPORT in original) != (INCLUDE in original):
        raise ValueError('Partial API-011.1 router registration')
    if IMPORT in original:
        return original
    out = replace_once(original, IMPORT_ANCHOR, IMPORT_ANCHOR + IMPORT + '\n', 'router import')
    return replace_once(out, INCLUDE_ANCHOR, INCLUDE_ANCHOR + INCLUDE + '\n', 'router include')


def plan(root: Path) -> dict[Path, bytes]:
    root = root.resolve()
    for rel in ('app/api/main.py', 'app/api/consolidation.py', 'app/core/consolidation.py'):
        if not (root / rel).is_file():
            raise ValueError(f'Install API-011.0 first, missing: {root / rel}')
    dst = root / 'app/api/main.py'
    old = dst.read_text(encoding='utf-8-sig')
    new = patch_main(old)
    changes: dict[Path, bytes] = {}
    if new != old:
        changes[dst] = new.encode('utf-8')
    for rel in ('app/api/correlation_accuracy.py', 'app/core/correlation_accuracy.py',
                'tests/test_api_011_1_correlation_accuracy.py'):
        src = PACKAGE / rel
        if not src.is_file():
            raise ValueError(f'Packaged file missing: {src}')
        target = root / rel
        payload = src.read_bytes()
        if not target.is_file() or target.read_bytes() != payload:
            changes[target] = payload
    return changes


def install(root: Path) -> list[str]:
    root = root.resolve()
    changes = plan(root)
    for dst, payload in changes.items():
        dst.parent.mkdir(parents=True, exist_ok=True)
        backup = dst.with_name(dst.name + BACKUP)
        if dst.is_file() and not backup.exists():
            shutil.copy2(dst, backup)
        dst.write_bytes(payload)
    return [str(dst.relative_to(root)) for dst in changes]


if __name__ == '__main__':
    if len(sys.argv) > 2:
        sys.exit('Usage: install_api_011_1.py [project-root]')
    target = Path(sys.argv[1]) if len(sys.argv) == 2 else Path.cwd()
    try:
        files = install(target)
    except (OSError, UnicodeError, ValueError) as error:
        sys.exit(f'ERROR: {error}')
    print('API-011.1 backend installed:' if files else 'API-011.1 backend already installed:')
    for name in files:
        print('  ' + name)
