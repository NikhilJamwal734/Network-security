"""Single-command installer; validates both backend and frontend before writing."""
from __future__ import annotations
from pathlib import Path
import importlib.util
import shutil
import sys


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if not spec or not spec.loader:
        raise ValueError(f'Cannot load installer: {path}')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def install(root: Path) -> list[str]:
    root = root.resolve()
    package = Path(__file__).resolve().parents[1]
    backend = load(package / 'scripts/install_api_011_0.py', 'backend110')
    frontend = load(package / 'frontend_patch/scripts/install_api_011_0_frontend.py', 'frontend110')
    changes = {**backend.plan(root), **frontend.plan(root / 'frontend')}
    for dest, data in changes.items():
        dest.parent.mkdir(parents=True, exist_ok=True)
        backup = dest.with_name(dest.name + '.before_api0110.bak')
        if dest.exists() and not backup.exists():
            shutil.copy2(dest, backup)
        dest.write_bytes(data)
    return [str(file.relative_to(root)) for file in changes]


if __name__ == '__main__':
    if len(sys.argv) > 2:
        sys.exit('Usage: install_all_api_011_0.py [project-root]')
    root = Path(sys.argv[1]) if len(sys.argv) == 2 else Path.cwd()
    try:
        changes = install(root)
    except (OSError, ValueError, UnicodeError) as error:
        sys.exit(f'ERROR: {error}')
    print('API-011.0 installed:' if changes else 'API-011.0 already installed:')
    for change in changes:
        print('  ' + change)
