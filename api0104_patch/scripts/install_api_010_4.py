"""Install opt-in API-010.4 without overwriting the fixed API-010.3 route."""
from __future__ import annotations

from pathlib import Path
import shutil
import sys

PACKAGE = Path(__file__).resolve().parents[1]
BACKUP = '.before_api0104.bak'
IMPORT = 'from app.api.correlation_assurance import router as correlation_assurance_router'
ROUTE = 'app.include_router(correlation_assurance_router)'


def patch_main(source: str) -> str:
    if IMPORT in source and ROUTE in source:
        return source
    if (IMPORT in source) != (ROUTE in source):
        raise ValueError('Partial API-010.4 registration; no changes made')
    import_anchor = 'from app.api.rule_correlation import router as rule_correlation_router\n'
    route_anchor = 'app.include_router(rule_correlation_router)\n'
    if source.count(import_anchor) != 1 or source.count(route_anchor) != 1:
        raise ValueError('Cannot identify API-010.3 route anchors in app/api/main.py')
    return (source.replace(import_anchor, import_anchor + IMPORT + '\n', 1)
                  .replace(route_anchor, route_anchor + ROUTE + '\n', 1))


def plan(root: Path) -> dict[Path, bytes]:
    root = root.resolve()
    for rel in ('app/api/main.py', 'app/api/rule_correlation.py',
                'app/core/rule_correlation.py', 'app/api/precision_review.py'):
        if not (root / rel).is_file():
            raise ValueError(f'API-010.3 prerequisite not found: {root / rel}')
    old_route = (root / 'app/api/rule_correlation.py').read_text(encoding='utf-8-sig')
    # Prevent reintroducing the closed-file crash via this new endpoint.
    marker = 'await file.seek(0)\n    data = await file.read(_MAX_CORRELATION_BYTES + 1)\n    await file.seek(0)'
    if marker not in old_route:
        raise ValueError('API-010.3 closed-upload fix missing or unexpected; apply its upload fix first')
    original = (root / 'app/api/main.py').read_text(encoding='utf-8-sig')
    update = patch_main(original)
    changes = {}
    if original != update:
        changes[root / 'app/api/main.py'] = update.encode('utf-8')
    for rel in ('app/api/correlation_assurance.py', 'app/core/correlation_assurance.py',
                'tests/test_api_010_4_assurance.py'):
        source_file = PACKAGE / rel
        if not source_file.is_file():
            raise ValueError(f'Package incomplete: {source_file}')
        target = root / rel
        data = source_file.read_bytes()
        if not target.is_file() or target.read_bytes() != data:
            changes[target] = data
    return changes


def install(root: Path) -> list[str]:
    root = root.resolve()
    changes = plan(root)
    for target, contents in changes.items():
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            backup = target.with_name(target.name + BACKUP)
            if not backup.exists():
                shutil.copy2(target, backup)
        target.write_bytes(contents)
    return [str(file.relative_to(root)) for file in changes]


if __name__ == '__main__':
    project = Path(sys.argv[1]) if len(sys.argv) == 2 else Path.cwd()
    try:
        modified = install(project)
    except (OSError, ValueError) as error:
        sys.exit(f'ERROR: {error}')
    print('API-010.4 installed:' if modified else 'API-010.4 already installed.')
    for item in modified:
        print('  ' + item)
