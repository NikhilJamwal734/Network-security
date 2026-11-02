"""Single-command 11.1 installer: validate all files before writing any."""
from __future__ import annotations
import importlib.util
from pathlib import Path
import shutil
import sys


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ValueError(f'Cannot load installer: {path}')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def install(root: Path) -> list[str]:
    root = root.resolve()
    pkg = Path(__file__).resolve().parents[1]
    backend = load(pkg / 'scripts/install_api_011_1.py', 'backend111')
    frontend = load(pkg / 'frontend_patch/scripts/install_api_011_1_frontend.py', 'frontend111')
    bchanges = backend.plan(root)
    fchanges = frontend.plan(root / 'frontend')
    changes = {**bchanges, **fchanges}
    for dst, payload in changes.items():
        dst.parent.mkdir(parents=True, exist_ok=True)
        bak = dst.with_name(dst.name + '.before_api0111.bak')
        if dst.is_file() and not bak.exists():
            shutil.copy2(dst, bak)
        dst.write_bytes(payload)
    return [str(x.relative_to(root)) for x in changes]


if __name__ == '__main__':
    if len(sys.argv) > 2:
        sys.exit('Usage: install_all_api_011_1.py [project-root]')
    target = Path(sys.argv[1]) if len(sys.argv) == 2 else Path.cwd()
    try:
        changes = install(target)
    except (OSError, UnicodeError, ValueError) as error:
        sys.exit(f'ERROR: {error}')
    print('API-011.1 installed:' if changes else 'API-011.1 already installed:')
    for name in changes:
        print('  ' + name)
