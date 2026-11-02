"""Plan the additive API-011.6 backend registration (no writes)."""
from __future__ import annotations
from pathlib import Path
import sys

PACKAGE = Path(__file__).resolve().parents[1]


def plan(root: Path) -> dict[Path, bytes]:
    root = root.resolve()
    for required in ('app/core/pipeline_validation.py', 'app/api/pipeline_validation.py'):
        if not (root / required).is_file():
            raise ValueError(f'API-011.4 prerequisite is missing: {required}')
    target = root / 'app/api/main.py'
    if not target.is_file() or target.is_symlink():
        raise ValueError('Missing or linked app/api/main.py')
    raw = target.read_bytes()
    bom = raw.startswith(b'\xef\xbb\xbf')
    src = raw.decode('utf-8-sig')
    eol = '\r\n' if '\r\n' in src else '\n'
    src = src.replace('\r\n', '\n')
    old_import = 'from app.api.pipeline_validation import router as pipeline_validation_router\n'
    old_register = 'app.include_router(pipeline_validation_router)\n'
    new_import = 'from app.api.hardened_analysis import router as hardened_analysis_router\n'
    new_register = 'app.include_router(hardened_analysis_router)\n'
    if (new_import in src) != (new_register in src):
        raise ValueError('Incomplete API-011.6 router registration')
    if new_import not in src:
        if src.count(old_import) != 1 or src.count(old_register) != 1:
            raise ValueError('API-011.4 router anchors not found uniquely')
        src = src.replace(old_import, old_import + new_import, 1)
        src = src.replace(old_register, old_register + new_register, 1)
    updated = (b'\xef\xbb\xbf' if bom else b'') + src.replace('\n', eol).encode('utf-8')
    changes = {}
    if raw != updated:
        changes[target] = updated
    for rel in ('app/core/input_hardening.py', 'app/api/hardened_analysis.py'):
        source = (PACKAGE / rel).read_bytes()
        dest = root / rel
        if dest.is_symlink():
            raise ValueError(f'Refusing to modify symlink: {dest}')
        if dest.exists():
            if not dest.is_file() or dest.read_bytes() != source:
                raise ValueError(f'Refusing to overwrite customized module: {dest}')
        else:
            changes[dest] = source
    return changes


if __name__ == '__main__':
    root = Path(sys.argv[1]) if len(sys.argv) == 2 else Path.cwd()
    if len(sys.argv) > 2:
        sys.exit('Usage: install_api_011_6.py [project-root]')
    try:
        for dest in plan(root):
            print(dest)
    except (OSError, ValueError, UnicodeError) as exc:
        sys.exit(f'ERROR: {exc}')
