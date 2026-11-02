"""Safe, idempotent API-010.7 backend installer. Run with explicit project root."""
from __future__ import annotations
from pathlib import Path
import shutil
import sys

PACKAGE = Path(__file__).resolve().parents[1]
IMPORT = 'from app.api.service_ipv6 import router as service_ipv6_router'
INCLUDE = 'app.include_router(service_ipv6_router)'
ANCHOR_IMPORT = 'from app.api.object_assurance import router as object_assurance_router\n'
ANCHOR_INCLUDE = 'app.include_router(object_assurance_router)\n'
BACKUP = '.before_api0107.bak'


def patch_main(source: str) -> str:
    checks = (IMPORT in source, INCLUDE in source)
    if all(checks):
        return source
    if any(checks):
        raise ValueError('Partial API-010.7 registration; inspect app/api/main.py before retry')
    if source.count(ANCHOR_IMPORT) != 1 or source.count(ANCHOR_INCLUDE) != 1:
        raise ValueError('API-010.6 route registration anchors not found uniquely')
    return (source.replace(ANCHOR_IMPORT, ANCHOR_IMPORT + IMPORT + '\n', 1)
                  .replace(ANCHOR_INCLUDE, ANCHOR_INCLUDE + INCLUDE + '\n', 1))


def plan(root: Path) -> dict[Path, bytes]:
    root = root.resolve()
    for rel in ('app/api/main.py', 'app/api/object_assurance.py', 'app/core/object_assurance.py'):
        if not (root / rel).is_file():
            raise ValueError(f'API-010.6 prerequisite missing: {root / rel}')
    main = root / 'app/api/main.py'
    original = main.read_text(encoding='utf-8-sig')
    changed = patch_main(original)
    updates = {}
    if changed != original:
        updates[main] = changed.encode('utf-8')
    for rel in ('app/api/service_ipv6.py', 'app/core/service_ipv6.py', 'tests/test_api_010_7_service_ipv6.py'):
        source = PACKAGE / rel
        if not source.is_file():
            raise ValueError(f'Installer package incomplete: {source}')
        target = root / rel
        data = source.read_bytes()
        if not target.is_file() or target.read_bytes() != data:
            updates[target] = data
    return updates


def install(root: Path) -> list[str]:
    root = root.resolve()
    updates = plan(root)
    for target, data in updates.items():
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            backup = target.with_name(target.name + BACKUP)
            if not backup.exists():
                shutil.copy2(target, backup)
        target.write_bytes(data)
    return [str(p.relative_to(root)) for p in updates]


if __name__ == '__main__':
    if len(sys.argv) > 2:
        sys.exit('Usage: install_api_010_7.py [project-root]')
    root = Path(sys.argv[1]) if len(sys.argv) == 2 else Path.cwd()
    try:
        updates = install(root)
    except (OSError, ValueError, UnicodeError) as error:
        sys.exit(f'ERROR: {error}')
    print('API-010.7 installed:' if updates else 'API-010.7 already installed:')
    for change in updates:
        print('  ' + change)
