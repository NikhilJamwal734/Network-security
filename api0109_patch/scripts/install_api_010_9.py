"""Preflight-validated, idempotent API-010.9 backend installer."""
from __future__ import annotations
from pathlib import Path
import shutil
import sys

PACKAGE = Path(__file__).resolve().parents[1]
IMPORT = 'from app.api.ids_configuration import router as ids_configuration_router'
INCLUDE = 'app.include_router(ids_configuration_router)'
ANCHOR_IMPORT = 'from app.api.nat_route_reachability import router as nat_route_router\n'
ANCHOR_INCLUDE = 'app.include_router(nat_route_router)\n'
BACKUP = '.before_api0109.bak'


def patch_main(src: str) -> str:
    has_i, has_r = IMPORT in src, INCLUDE in src
    if has_i and has_r:
        return src
    if has_i or has_r:
        raise ValueError('Partial API-010.9 registration: inspect app/api/main.py')
    if src.count(ANCHOR_IMPORT) != 1 or src.count(ANCHOR_INCLUDE) != 1:
        raise ValueError('Unique API-010.8 router anchors not found: install 10.8 first')
    return (src.replace(ANCHOR_IMPORT, ANCHOR_IMPORT + IMPORT + '\n', 1)
               .replace(ANCHOR_INCLUDE, ANCHOR_INCLUDE + INCLUDE + '\n', 1))


def plan(root: Path) -> dict[Path, bytes]:
    root = root.resolve()
    for rel in ('app/api/main.py', 'app/api/nat_route_reachability.py', 'app/core/nat_route_reachability.py'):
        if not (root / rel).is_file():
            raise ValueError(f'API-010.8 prerequisite missing: {root / rel}')
    result = {}
    main = root / 'app/api/main.py'
    orig = main.read_text(encoding='utf-8-sig')
    new = patch_main(orig)
    if new != orig:
        result[main] = new.encode('utf-8')
    for rel in ('app/api/ids_configuration.py', 'app/core/ids_configuration.py',
                'tests/test_api_010_9_ids_configuration.py'):
        src = PACKAGE / rel
        if not src.is_file():
            raise ValueError(f'Installer package asset missing: {src}')
        dst = root / rel
        data = src.read_bytes()
        if not dst.is_file() or dst.read_bytes() != data:
            result[dst] = data
    return result


def install(root: Path) -> list[str]:
    root = root.resolve()
    updates = plan(root)  # validate ALL files and anchors before writing
    for dest, data in updates.items():
        dest.parent.mkdir(parents=True, exist_ok=True)
        if dest.is_file():
            bak = dest.with_name(dest.name + BACKUP)
            if not bak.exists():
                shutil.copy2(dest, bak)
        dest.write_bytes(data)
    return [str(p.relative_to(root)) for p in updates]


if __name__ == '__main__':
    if len(sys.argv) > 2:
        sys.exit('Usage: install_api_010_9.py [project-root]')
    root = Path(sys.argv[1]) if len(sys.argv) == 2 else Path.cwd()
    try:
        paths = install(root)
    except (OSError, UnicodeError, ValueError) as exc:
        sys.exit(f'ERROR: {exc}')
    print('API-010.9 backend installed:' if paths else 'API-010.9 backend already installed:')
    for p in paths:
        print('  ' + p)
