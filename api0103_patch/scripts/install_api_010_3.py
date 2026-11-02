"""Install opt-in API-010.3; idempotent, backup-aware, existing APIs unchanged.

Run from the *project root*:
  .\\.venv-win\\Scripts\\python.exe .\\api0103_patch\\scripts\\install_api_010_3.py "."
"""
from __future__ import annotations
from pathlib import Path
import shutil
import sys

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
BACKUP = '.before_api0103.bak'


def patch_main(text: str) -> str:
    imported = 'from app.api.rule_correlation import router as rule_correlation_router'
    included = 'app.include_router(rule_correlation_router)'
    if imported in text and included in text:
        return text
    if (imported in text) != (included in text):
        raise ValueError('Partial rule-correlation route integration; not safe to patch')
    original_import = 'from app.api.precision_review import router as precision_review_router\n'
    original_route = 'app.include_router(precision_review_router)\n'
    if text.count(original_import) != 1 or text.count(original_route) != 1:
        raise ValueError('Unknown API-010.2 app/api/main.py routing layout; no changes made')
    return (text.replace(original_import, original_import + imported + '\n', 1)
                .replace(original_route, original_route + included + '\n', 1))


def plan(root: Path) -> dict[Path, bytes]:
    root = root.resolve()
    required = [root / 'app/api/main.py', root / 'app/api/precision_review.py',
                root / 'app/core/precision_review.py', root / 'app/core/precision_enhancements.py']
    for file in required:
        if not file.is_file():
            raise ValueError(f'API-010.2.1 prerequisite missing: {file}')
    current = (root / 'app/api/main.py').read_text(encoding='utf-8-sig')
    changed = patch_main(current)
    updates: dict[Path, bytes] = {}
    if changed != current:
        updates[root / 'app/api/main.py'] = changed.encode('utf-8')
    for rel in ('app/api/rule_correlation.py', 'app/core/rule_correlation.py',
                'tests/test_api_010_3_correlation.py'):
        source = PACKAGE_ROOT / rel
        if not source.is_file():
            raise ValueError(f'Incomplete package: {source}')
        target = root / rel
        data = source.read_bytes()
        if not target.is_file() or target.read_bytes() != data:
            updates[target] = data
    return updates


def install(root: Path) -> list[str]:
    root = root.resolve()
    changes = plan(root)  # validate every prerequisite before changing anything
    for target, data in changes.items():
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            backup = target.with_name(target.name + BACKUP)
            if not backup.exists():
                shutil.copy2(target, backup)
        target.write_bytes(data)
    return [str(item.relative_to(root)) for item in changes]


if __name__ == '__main__':
    project = Path(sys.argv[1]) if len(sys.argv) == 2 else Path.cwd()
    try:
        changes = install(project)
    except (ValueError, OSError) as error:
        sys.exit('ERROR: ' + str(error))
    print('API-010.3 installed:' if changes else 'API-010.3 already installed.')
    for item in changes:
        print('  ' + item)
