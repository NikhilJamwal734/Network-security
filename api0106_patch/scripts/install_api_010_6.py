"""Install API-010.6 backend in-place (project root is an explicit argument).

python api0106_patch/scripts/install_api_010_6.py "."
"""
from __future__ import annotations
from pathlib import Path
import shutil
import sys

PACKAGE = Path(__file__).resolve().parents[1]
BACKUP_SUFFIX = '.before_api0106.bak'
IMPORT = 'from app.api.object_assurance import router as object_assurance_router'
INCLUDE = 'app.include_router(object_assurance_router)'
IMPORT_ANCHOR = 'from app.api.object_resolution import router as object_resolution_router\n'
INCLUDE_ANCHOR = 'app.include_router(object_resolution_router)\n'


def patch_main(source: str) -> str:
    existing = IMPORT in source, INCLUDE in source
    if all(existing):
        return source
    if any(existing):
        raise ValueError('Partial API-010.6 route registration; inspect app/api/main.py')
    if source.count(IMPORT_ANCHOR) != 1 or source.count(INCLUDE_ANCHOR) != 1:
        raise ValueError('Could not uniquely identify API-010.5 route registration anchors')
    return (source.replace(IMPORT_ANCHOR, IMPORT_ANCHOR + IMPORT + '\n', 1)
                  .replace(INCLUDE_ANCHOR, INCLUDE_ANCHOR + INCLUDE + '\n', 1))


def plan(root: Path) -> dict[Path, bytes]:
    root = root.resolve()
    for rel in ('app/api/main.py', 'app/api/object_resolution.py', 'app/core/object_resolution.py'):
        if not (root / rel).is_file():
            raise ValueError(f'API-010.5 prerequisite missing: {root / rel}')
    main = root / 'app/api/main.py'
    source = main.read_text(encoding='utf-8-sig')
    updated = patch_main(source)
    changes: dict[Path, bytes] = {}
    if updated != source:
        changes[main] = updated.encode('utf-8')
    for rel in ('app/api/object_assurance.py', 'app/core/object_assurance.py',
                'tests/test_api_010_6_object_assurance.py'):
        file_source = PACKAGE / rel
        if not file_source.is_file():
            raise ValueError(f'Installer package is incomplete: {file_source}')
        target = root / rel
        payload = file_source.read_bytes()
        if not target.is_file() or target.read_bytes() != payload:
            changes[target] = payload
    return changes


def install(root: Path) -> list[str]:
    root = root.resolve()
    changes = plan(root)  # validate all changes before writing
    for target, data in changes.items():
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            backup = target.with_name(target.name + BACKUP_SUFFIX)
            if not backup.exists():
                shutil.copy2(target, backup)
        target.write_bytes(data)
    return [str(target.relative_to(root)) for target in changes]


if __name__ == '__main__':
    target = Path(sys.argv[1]) if len(sys.argv) == 2 else Path.cwd()
    try:
        modified = install(target)
    except (OSError, ValueError) as error:
        sys.exit(f'ERROR: {error}')
    print('API-010.6 installed:' if modified else 'API-010.6 already installed.')
    for item in modified:
        print('  ' + item)
