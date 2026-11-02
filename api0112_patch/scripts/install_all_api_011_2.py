"""One-command 11.2 patch: plan both halves before writing either."""
from __future__ import annotations
import importlib.util
from pathlib import Path
import shutil
import sys


def load(path: Path, key: str):
    spec = importlib.util.spec_from_file_location(key, path)
    if spec is None or spec.loader is None: raise ValueError(f'Cannot load installer: {path}')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def install(root: Path) -> list[str]:
    root = root.resolve()
    package = Path(__file__).resolve().parents[1]
    backend = load(package/'scripts/install_api_011_2.py', 'backend112')
    frontend = load(package/'frontend_patch/scripts/install_api_011_2_frontend.py', 'frontend112')
    changes = {**backend.plan(root), **frontend.plan(root/'frontend')}
    for dst, payload in changes.items():
        dst.parent.mkdir(parents=True, exist_ok=True)
        bak = dst.with_name(dst.name + '.before_api0112.bak')
        if dst.is_file() and not bak.exists(): shutil.copy2(dst, bak)
        dst.write_bytes(payload)
    return [str(x.relative_to(root)) for x in changes]


if __name__ == '__main__':
    if len(sys.argv) > 2: sys.exit('Usage: install_all_api_011_2.py [project-root]')
    target = Path(sys.argv[1]) if len(sys.argv) == 2 else Path.cwd()
    try: changed = install(target)
    except (OSError, ValueError, UnicodeError) as exc: sys.exit(f'ERROR: {exc}')
    print('API-011.2 installed:' if changed else 'API-011.2 already installed:')
    for rel in changed: print('  ' + rel)
