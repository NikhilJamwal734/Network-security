"""One-command API-010.9 install; preflight BOTH backend and frontend first."""
from __future__ import annotations
from pathlib import Path
import importlib.util
import shutil
import sys


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if not spec or not spec.loader:
        raise ValueError(f'Cannot load installer: {path}')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def install(root: Path) -> list[str]:
    root = root.resolve()
    script_dir = Path(__file__).resolve().parent
    backend = load(script_dir / 'install_api_010_9.py', 'api109_backend')
    frontend = load(script_dir.parent / 'frontend_patch/scripts/install_api_010_9_frontend.py', 'api109_frontend')
    # Fail before ANY writes if 10.8 is not present, or any frontend/PDF
    # anchor is missing. Prevents partial installation when layout differs.
    changes = {**backend.plan(root), **frontend.plan(root / 'frontend')}
    for dst, data in changes.items():
        dst.parent.mkdir(parents=True, exist_ok=True)
        if dst.exists():
            bak = dst.with_name(dst.name + '.before_api0109.bak')
            if not bak.exists():
                shutil.copy2(dst, bak)
        dst.write_bytes(data)
    return [str(p.relative_to(root)) for p in changes]


if __name__ == '__main__':
    if len(sys.argv) > 2:
        sys.exit('Usage: install_all_api_010_9.py [project-root]')
    root = Path(sys.argv[1]) if len(sys.argv) == 2 else Path.cwd()
    try:
        paths = install(root)
    except (OSError, UnicodeError, ValueError) as exc:
        sys.exit(f'ERROR: {exc}')
    print('API-010.9 installed:' if paths else 'API-010.9 already installed:')
    for p in paths:
        print('  ' + p)
