r"""Install API-010.2.1 precision improvements in an existing API-010.2 project.

Usage (PowerShell from project root):
    .\.venv-win\Scripts\python.exe .\api0102_1_patch\scripts\install_api_010_2_1.py "."

No frontend, CSS, routes, legacy endpoints or scoring code is touched.
"""
from __future__ import annotations

from pathlib import Path
import shutil
import sys

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
BACKUP_SUFFIX = '.before_api0102_1.bak'
OLD_ANCHOR = '    return result\n'
NEW_ANCHOR = '''    from app.core.precision_enhancements import augment_precision_review
    return augment_precision_review(platform, lines, result)
'''


def patch_existing(text: str) -> str:
    if NEW_ANCHOR in text:
        return text
    if 'def refine_vendor_review(' not in text:
        raise ValueError('Existing API-010.2 precision function was not found')
    # The return statement is the final line in the original API-010.2 module.
    if not text.endswith(OLD_ANCHOR):
        raise ValueError('Unknown API-010.2 precision module layout; no files changed')
    return text[:-len(OLD_ANCHOR)] + NEW_ANCHOR


def plan(root: Path) -> dict[Path, bytes]:
    root = root.resolve()
    core = root / 'app/core/precision_review.py'
    endpoint = root / 'app/api/precision_review.py'
    if not core.is_file() or not endpoint.is_file():
        raise ValueError('API-010.2 must be installed before this enhancement')
    source = PACKAGE_ROOT / 'app/core/precision_enhancements.py'
    tests = PACKAGE_ROOT / 'tests/test_api_010_2_1_enhancements.py'
    updates: dict[Path, bytes] = {}
    old = core.read_text(encoding='utf-8-sig')
    updated = patch_existing(old)
    if old != updated:
        updates[core] = updated.encode('utf-8')
    for from_path, to_path in [
        (source, root / 'app/core/precision_enhancements.py'),
        (tests, root / 'tests/test_api_010_2_1_enhancements.py'),
    ]:
        if not from_path.is_file():
            raise ValueError(f'Incomplete patch package: {from_path}')
        data = from_path.read_bytes()
        if not to_path.is_file() or to_path.read_bytes() != data:
            updates[to_path] = data
    return updates


def install(root: Path) -> list[str]:
    root = root.resolve()
    changes = plan(root)  # All prereqs verified before any write.
    for target, content in changes.items():
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.is_file():
            backup = target.with_name(target.name + BACKUP_SUFFIX)
            if not backup.exists():
                shutil.copy2(target, backup)
        target.write_bytes(content)
    return [str(path.relative_to(root)) for path in changes]


if __name__ == '__main__':
    project = Path(sys.argv[1]) if len(sys.argv) == 2 else Path.cwd()
    try:
        changed = install(project)
    except (ValueError, OSError) as exc:
        sys.exit(f'ERROR: {exc}')
    print('API-010.2.1 installed:' if changed else 'API-010.2.1 already installed; no changes required.')
    for line in changed:
        print('  ' + line)
