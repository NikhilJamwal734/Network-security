"""Validated API-010.8 backend installer, with non-destructive backups."""
from __future__ import annotations
from pathlib import Path
import shutil
import sys

PACKAGE = Path(__file__).resolve().parents[1]
IMPORT = 'from app.api.nat_route_reachability import router as nat_route_router'
INCLUDE = 'app.include_router(nat_route_router)'
ANCHOR_IMPORT = 'from app.api.service_ipv6 import router as service_ipv6_router\n'
ANCHOR_INCLUDE = 'app.include_router(service_ipv6_router)\n'
BACKUP = '.before_api0108.bak'


def patch_main(src: str) -> str:
    hits = IMPORT in src, INCLUDE in src
    if all(hits):
        return src
    if any(hits):
        raise ValueError('Partial API-010.8 registration; inspect app/api/main.py')
    if src.count(ANCHOR_IMPORT) != 1 or src.count(ANCHOR_INCLUDE) != 1:
        raise ValueError('Unique API-010.7 endpoint registration anchors not found')
    return (src.replace(ANCHOR_IMPORT, ANCHOR_IMPORT + IMPORT + '\n', 1)
               .replace(ANCHOR_INCLUDE, ANCHOR_INCLUDE + INCLUDE + '\n', 1))


def plan(root: Path) -> dict[Path, bytes]:
    root = root.resolve()
    for rel in ('app/api/main.py', 'app/api/service_ipv6.py', 'app/core/service_ipv6.py'):
        if not (root / rel).is_file():
            raise ValueError(f'API-010.7 prerequisite missing: {root / rel}')
    changes: dict[Path, bytes] = {}
    main = root / 'app/api/main.py'
    old = main.read_text(encoding='utf-8-sig')
    new = patch_main(old)
    if new != old:
        changes[main] = new.encode('utf-8')
    for rel in ('app/api/nat_route_reachability.py',
                'app/core/nat_route_reachability.py',
                'tests/test_api_010_8_nat_route_reachability.py'):
        src = PACKAGE / rel
        if not src.is_file():
            raise ValueError(f'Missing API-010.8 package file: {src}')
        dst = root / rel
        data = src.read_bytes()
        if not dst.exists() or dst.read_bytes() != data:
            changes[dst] = data
    return changes


def install(root: Path) -> list[str]:
    root = root.resolve()
    changes = plan(root)
    for dst, data in changes.items():
        dst.parent.mkdir(parents=True, exist_ok=True)
        if dst.exists():
            backup = dst.with_name(dst.name + BACKUP)
            if not backup.exists():
                shutil.copy2(dst, backup)
        dst.write_bytes(data)
    return [str(f.relative_to(root)) for f in changes]


if __name__ == '__main__':
    if len(sys.argv) > 2:
        sys.exit('Usage: install_api_010_8.py [project-root]')
    root = Path(sys.argv[1]) if len(sys.argv) == 2 else Path.cwd()
    try:
        paths = install(root)
    except (OSError, ValueError, UnicodeError) as err:
        sys.exit(f'ERROR: {err}')
    print('API-010.8 backend installed:' if paths else 'API-010.8 backend already installed:')
    for p in paths:
        print('  ' + p)
