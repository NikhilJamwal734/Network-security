"""Install additive API-010.5 backend from the project root.

Usage: python api0105_patch/scripts/install_api_010_5.py "."
Preflights all changes before writing. Writes backups only on first modification.
"""
from __future__ import annotations
from pathlib import Path
import shutil
import sys

PACKAGE = Path(__file__).resolve().parents[1]
BACKUP_SUFFIX = '.before_api0105.bak'
IMPORT = 'from app.api.object_resolution import router as object_resolution_router'
INCLUDE = 'app.include_router(object_resolution_router)'
IMPORT_ANCHOR = 'from app.api.correlation_assurance import router as correlation_assurance_router\n'
INCLUDE_ANCHOR = 'app.include_router(correlation_assurance_router)\n'


def patch_main(text: str) -> str:
    already = IMPORT in text, INCLUDE in text
    if all(already): return text
    if any(already): raise ValueError('Incomplete API-010.5 registration: inspect main.py before installing')
    if text.count(IMPORT_ANCHOR) != 1 or text.count(INCLUDE_ANCHOR) != 1:
        raise ValueError('API-010.4 route-registration anchors not found exactly once')
    return (text.replace(IMPORT_ANCHOR, IMPORT_ANCHOR + IMPORT + '\n', 1)
                .replace(INCLUDE_ANCHOR, INCLUDE_ANCHOR + INCLUDE + '\n', 1))


def plan(root: Path) -> dict[Path, bytes]:
    root = root.resolve()
    for rel in ('app/api/main.py', 'app/api/correlation_assurance.py', 'app/core/correlation_assurance.py',
                'app/api/rule_correlation.py', 'app/core/rule_correlation.py'):
        if not (root / rel).is_file():
            raise ValueError(f'API-010.4 prerequisite missing: {root / rel}')
    original = (root / 'app/api/main.py').read_text(encoding='utf-8-sig')
    updated = patch_main(original)
    changes: dict[Path, bytes] = {}
    if original != updated: changes[root / 'app/api/main.py'] = updated.encode('utf-8')
    for rel in ('app/api/object_resolution.py', 'app/core/object_resolution.py',
                'tests/test_api_010_5_object_resolution.py'):
        source = PACKAGE / rel
        if not source.is_file(): raise ValueError(f'Installer package incomplete: {source}')
        destination = root / rel
        data = source.read_bytes()
        if not destination.is_file() or destination.read_bytes() != data:
            changes[destination] = data
    return changes


def install(root: Path) -> list[str]:
    root = root.resolve()
    changes = plan(root)
    for path, content in changes.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.is_file():
            backup = path.with_name(path.name + BACKUP_SUFFIX)
            if not backup.exists(): shutil.copy2(path, backup)
        path.write_bytes(content)
    return [str(path.relative_to(root)) for path in changes]


if __name__ == '__main__':
    root = Path(sys.argv[1]) if len(sys.argv) == 2 else Path.cwd()
    try:
        changed = install(root)
    except (OSError, ValueError) as exc:
        sys.exit(f'ERROR: {exc}')
    print('API-010.5 backend installed:' if changed else 'API-010.5 backend already installed.')
    for path in changed: print('  ' + path)
