"""Fail-before-write API-011.0 backend installer."""
from __future__ import annotations
from pathlib import Path
import shutil
import sys

PACKAGE = Path(__file__).resolve().parents[1]
IMPORT = 'from app.api.consolidation import router as consolidation_router'
INCLUDE = 'app.include_router(consolidation_router)'
IMPORT_ANCHOR = 'from app.api.ids_configuration import router as ids_configuration_router\n'
INCLUDE_ANCHOR = 'app.include_router(ids_configuration_router)\n'
BACKUP = '.before_api0110.bak'


def replace_once(source: str, old: str, new: str, label: str) -> str:
    if new in source:
        return source
    if source.count(old) != 1:
        raise ValueError(f'{label}: expected a single API-010.9 anchor; no files changed')
    return source.replace(old, new, 1)


def patch_main(source: str) -> str:
    if (IMPORT in source) != (INCLUDE in source):
        raise ValueError('Partial API-011.0 registration; no files changed')
    if IMPORT in source:
        return source
    source = replace_once(source, IMPORT_ANCHOR, IMPORT_ANCHOR + IMPORT + '\n', 'router import')
    return replace_once(source, INCLUDE_ANCHOR, INCLUDE_ANCHOR + INCLUDE + '\n', 'router include')


def plan(root: Path) -> dict[Path, bytes]:
    root = root.resolve()
    for rel in ('app/api/main.py', 'app/api/ids_configuration.py', 'app/core/ids_configuration.py'):
        if not (root / rel).is_file():
            raise ValueError(f'Install API-010.9 first; required file not found: {root / rel}')
    main = root / 'app/api/main.py'
    original = main.read_text(encoding='utf-8-sig')
    patched = patch_main(original)
    changes: dict[Path, bytes] = {}
    if patched != original:
        changes[main] = patched.encode('utf-8')
    for rel in ('app/api/consolidation.py', 'app/core/consolidation.py',
                'tests/test_api_011_0_consolidation.py'):
        src = PACKAGE / rel
        if not src.is_file():
            raise ValueError(f'Missing packaged file: {src}')
        dst = root / rel
        data = src.read_bytes()
        if not dst.is_file() or dst.read_bytes() != data:
            changes[dst] = data
    return changes


def install(root: Path) -> list[str]:
    root = root.resolve()
    changes = plan(root)
    for dest, data in changes.items():
        dest.parent.mkdir(parents=True, exist_ok=True)
        if dest.exists() and not dest.with_name(dest.name + BACKUP).exists():
            shutil.copy2(dest, dest.with_name(dest.name + BACKUP))
        dest.write_bytes(data)
    return [str(dst.relative_to(root)) for dst in changes]


if __name__ == '__main__':
    if len(sys.argv) > 2:
        sys.exit('Usage: install_api_011_0.py [project-root]')
    root = Path(sys.argv[1]) if len(sys.argv) == 2 else Path.cwd()
    try:
        files = install(root)
    except (OSError, ValueError, UnicodeError) as exc:
        sys.exit(f'ERROR: {exc}')
    print('API-011.0 backend installed:' if files else 'API-011.0 backend already installed:')
    for f in files:
        print('  ' + f)
