"""Install API-012.0 without touching the frontend or earlier review modules.

A conservative, reversible installer: checks prerequisites before writes, rejects
unknown routers, preserves UTF-8 BOM and newline style, checks symlinks, writes a
project-specific manifest and backups, and refuses to undo later edits.
"""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys

PACKAGE = Path(__file__).resolve().parents[1]
MANIFEST = '.api0120_install_manifest.json'
BACKUP_SUFFIX = '.before_api0120.bak'
TEMP_SUFFIX = '.api0120.tmp'
TARGET_MAIN = Path('app/api/main.py')
TARGET_MODULE = Path('app/api/release_status.py')
REQUIRED = ('app/api/hardened_analysis.py', 'app/core/input_hardening.py',
            'app/api/pipeline_validation.py', 'frontend/src/api/universal.ts',
            'frontend/src/utils/normalizedPdf.ts')
IMPORT_ANCHOR = 'from app.api.hardened_analysis import router as hardened_analysis_router\n'
REGISTER_ANCHOR = 'app.include_router(hardened_analysis_router)\n'
NEW_IMPORT = 'from app.api.release_status import router as release_status_router\n'
NEW_REGISTER = 'app.include_router(release_status_router)\n'


def digest(raw: bytes) -> str:
    return sha256(raw).hexdigest()


def safe_target(root: Path, rel: Path) -> Path:
    path = root / rel
    if path.is_symlink() or not path.resolve().is_relative_to(root):
        raise ValueError(f'Unsafe target: {rel.as_posix()}')
    return path


def text_update(raw: bytes) -> bytes:
    bom = raw.startswith(b'\xef\xbb\xbf')
    src = raw.decode('utf-8-sig')
    if '\r' in src.replace('\r\n', ''):
        raise ValueError('Unsupported mixed line endings in API main')
    if '\r\n' in src and '\n' in src.replace('\r\n', ''):
        raise ValueError('Mixed line endings in API main')
    newline = '\r\n' if '\r\n' in src else '\n'
    canonical = src.replace('\r\n', '\n')
    if canonical.count(NEW_IMPORT) != canonical.count(NEW_REGISTER):
        raise ValueError('Partial API-012.0 router registration')
    if canonical.count(NEW_IMPORT) > 1:
        raise ValueError('Duplicate API-012.0 router registration')
    if NEW_IMPORT not in canonical:
        if canonical.count(IMPORT_ANCHOR) != 1 or canonical.count(REGISTER_ANCHOR) != 1:
            raise ValueError('API-011.6 router anchors missing or duplicated')
        canonical = canonical.replace(IMPORT_ANCHOR, IMPORT_ANCHOR + NEW_IMPORT, 1)
        canonical = canonical.replace(REGISTER_ANCHOR, REGISTER_ANCHOR + NEW_REGISTER, 1)
    return (b'\xef\xbb\xbf' if bom else b'') + canonical.replace('\n', newline).encode('utf-8')


def plan(root: Path) -> dict[Path, bytes]:
    root = root.resolve()
    if not root.is_dir():
        raise ValueError('Project root is not a directory')
    for rel in REQUIRED:
        path = safe_target(root, Path(rel))
        if not path.is_file():
            raise ValueError(f'API-011.6 prerequisite missing: {rel}')
    main = safe_target(root, TARGET_MAIN)
    if not main.is_file():
        raise ValueError('Missing app/api/main.py')
    new_main = text_update(main.read_bytes())
    module = safe_target(root, TARGET_MODULE)
    module_source = (PACKAGE / TARGET_MODULE).read_bytes()
    if module.exists() and (not module.is_file() or module.read_bytes() != module_source):
        raise ValueError('Refusing to overwrite customized release_status.py')
    result: dict[Path, bytes] = {}
    if new_main != main.read_bytes():
        result[main] = new_main
    if not module.exists():
        result[module] = module_source
    return result


def validate_manifest(root: Path) -> None:
    path = root / MANIFEST
    if path.is_symlink():
        raise ValueError('Unsafe release installation manifest')
    record = json.loads(path.read_text(encoding='utf-8'))
    files = record.get('files')
    allowed = {TARGET_MAIN.as_posix(), TARGET_MODULE.as_posix()}
    if record.get('version') != '12.0' or not isinstance(files, dict) or not files or not set(files) <= allowed:
        raise ValueError('Invalid API-012.0 manifest')
    for rel, item in files.items():
        dest = safe_target(root, Path(rel))
        if not dest.is_file() or digest(dest.read_bytes()) != item.get('installed_sha256'):
            raise ValueError(f'API-012.0 installed file has changed: {rel}')


def install(root: Path) -> list[str]:
    root = root.resolve()
    manifest = root / MANIFEST
    changes = plan(root)
    if manifest.exists():
        validate_manifest(root)
        if changes:
            raise ValueError('API-012.0 already installed but new changes are required')
        return []
    if not changes:
        # Do not fabricate ownership of a manually installed module/router.
        return []
    originals = {p: p.read_bytes() if p.exists() else None for p in changes}
    records = {}
    for path, data in changes.items():
        rel = path.relative_to(root).as_posix()
        original = originals[path]
        backup = path.with_name(path.name + BACKUP_SUFFIX)
        tmp = path.with_name(path.name + TEMP_SUFFIX)
        if backup.exists() or tmp.exists() or backup.is_symlink() or tmp.is_symlink():
            raise ValueError(f'Existing backup/temp for {rel}; refusing installation')
        records[rel] = {
            'had_original': original is not None,
            'original_sha256': digest(original) if original is not None else None,
            'installed_sha256': digest(data),
        }
    staged = []
    written = []
    backups = []
    try:
        for dest, blob in changes.items():
            dest.parent.mkdir(parents=True, exist_ok=True)
            tmp = dest.with_name(dest.name + TEMP_SUFFIX)
            with tmp.open('xb') as f:
                f.write(blob)
            staged.append(tmp)
        for dest in changes:
            original = originals[dest]
            if original is not None:
                b = dest.with_name(dest.name + BACKUP_SUFFIX)
                with b.open('xb') as f:
                    f.write(original)
                backups.append(b)
            dest.with_name(dest.name + TEMP_SUFFIX).replace(dest)
            written.append(dest)
        temp_manifest = root / (MANIFEST + '.tmp')
        with temp_manifest.open('x', encoding='utf-8', newline='\n') as f:
            json.dump({'version':'12.0','files':records}, f, indent=2)
        temp_manifest.replace(manifest)
    except Exception:
        for dest in reversed(written):
            if dest.is_file() and digest(dest.read_bytes()) == digest(changes[dest]):
                original = originals[dest]
                if original is None:
                    dest.unlink()
                else:
                    dest.write_bytes(original)
        for b in backups:
            b.unlink(missing_ok=True)
        (root / (MANIFEST + '.tmp')).unlink(missing_ok=True)
        raise
    finally:
        for t in staged:
            t.unlink(missing_ok=True)
    return list(records)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('root', nargs='?', type=Path, default=Path.cwd())
    args = p.parse_args(argv)
    try:
        changes = install(args.root)
    except (OSError, ValueError, UnicodeError, json.JSONDecodeError) as exc:
        print(f'ERROR: {exc}', file=sys.stderr)
        return 1
    if changes:
        print('API-012.0 installed:')
        for rel in changes:
            print('  ' + rel)
    else:
        print('API-012.0 already present; no files changed.')
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
