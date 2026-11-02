"""API-011.6 combined installer: validate both halves, then stage changes.

Manifest is scoped to the target project, preserving its own rollback data.
"""
from __future__ import annotations
from hashlib import sha256
import importlib.util
import json
from pathlib import Path
import sys

PACKAGE = Path(__file__).resolve().parents[1]
MANIFEST = '.api0116_install_manifest.json'
BACKUP = '.before_api0116.bak'
TEMP = '.api0116.tmp'


def checksum(blob: bytes) -> str:
    return sha256(blob).hexdigest()


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ValueError(f'Missing patch module: {path}')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def combined_plan(root: Path) -> dict[Path, bytes]:
    back = load(PACKAGE / 'scripts/install_api_011_6.py', 'api116_backend')
    front = load(PACKAGE / 'frontend_patch/scripts/install_api_011_6_frontend.py', 'api116_frontend')
    backend = back.plan(root)
    frontend = front.plan(root / 'frontend')
    if set(backend) & set(frontend):
        raise ValueError('Duplicate target in backend and frontend plans')
    return {**backend, **frontend}


def install(root: Path) -> list[str]:
    root = root.resolve()
    manifest = root / MANIFEST
    changes = combined_plan(root)
    if manifest.exists():
        if changes:
            raise ValueError('API-011.6 manifest exists but installed files have changed; inspect before retrying')
        try:
            installed = json.loads(manifest.read_text(encoding='utf-8'))
            records = installed['files']
            if installed.get('version') != '11.6' or not isinstance(records, dict) or not records:
                raise ValueError('Invalid API-011.6 manifest')
            for rel, record in records.items():
                dst = root / rel
                if (rel not in {'app/api/main.py', 'app/api/hardened_analysis.py',
                                'app/core/input_hardening.py', 'frontend/src/api/universal.ts',
                                'frontend/src/utils/normalizedPdf.ts'} or
                        dst.is_symlink() or not dst.is_file() or
                        checksum(dst.read_bytes()) != record.get('new_sha256')):
                    raise ValueError('API-011.6 manifest exists but installed files changed')
        except (KeyError, TypeError, json.JSONDecodeError) as exc:
            raise ValueError('Invalid API-011.6 installation manifest') from exc
        return []
    if not changes:
        return []
    originals = {dest: dest.read_bytes() if dest.exists() else None for dest in changes}
    entries: dict[str, dict] = {}
    for dest in changes:
        if dest.is_symlink() or not dest.resolve().is_relative_to(root):
            raise ValueError(f'Unsafe installation target: {dest}')
        backup = dest.with_name(dest.name + BACKUP)
        temp = dest.with_name(dest.name + TEMP)
        if backup.exists() or temp.exists():
            raise ValueError(f'Existing backup or temp file at {dest}')
        original = originals[dest]
        entries[dest.relative_to(root).as_posix()] = {
            'original_exists': original is not None,
            'original_sha256': checksum(original) if original is not None else None,
            'new_sha256': checksum(changes[dest]),
        }
    staged: list[Path] = []
    written: list[Path] = []
    try:
        for dest, data in changes.items():
            dest.parent.mkdir(parents=True, exist_ok=True)
            temp = dest.with_name(dest.name + TEMP)
            with temp.open('xb') as fp:
                fp.write(data)
            staged.append(temp)
        for dest in changes:
            original = originals[dest]
            if original is not None:
                with dest.with_name(dest.name + BACKUP).open('xb') as fp:
                    fp.write(original)
            dest.with_name(dest.name + TEMP).replace(dest)
            written.append(dest)
        tmp_manifest = root / (MANIFEST + '.tmp')
        with tmp_manifest.open('x', encoding='utf-8') as fp:
            json.dump({'version': '11.6', 'files': entries}, fp, indent=2)
        tmp_manifest.replace(manifest)
    except Exception:
        for dest in reversed(written):
            if dest.is_file() and checksum(dest.read_bytes()) == checksum(changes[dest]):
                old = originals[dest]
                if old is None:
                    dest.unlink()
                else:
                    dest.write_bytes(old)
        for dest in changes:
            dest.with_name(dest.name + BACKUP).unlink(missing_ok=True)
        (root / (MANIFEST + '.tmp')).unlink(missing_ok=True)
        raise
    finally:
        for item in staged:
            item.unlink(missing_ok=True)
    return list(entries)


if __name__ == '__main__':
    if len(sys.argv) > 2:
        sys.exit('Usage: install_all_api_011_6.py [project-root]')
    root = Path(sys.argv[1]) if len(sys.argv) == 2 else Path.cwd()
    try:
        changes = install(root)
    except (OSError, ValueError, UnicodeError) as exc:
        sys.exit(f'ERROR: {exc}')
    print('API-011.6 installed:' if changes else 'API-011.6 already installed; no changes:')
    for path in changes:
        print('  ' + path)
