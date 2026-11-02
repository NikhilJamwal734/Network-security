"""Rollback only when every API-011.6 target still matches installed bytes."""
from __future__ import annotations
import json
from pathlib import Path
import sys

from install_all_api_011_6 import BACKUP, MANIFEST, checksum

ALLOWED = {
    'app/api/main.py',
    'app/api/hardened_analysis.py',
    'app/core/input_hardening.py',
    'frontend/src/api/universal.ts',
    'frontend/src/utils/normalizedPdf.ts',
}


def rollback(root: Path) -> list[str]:
    root = root.resolve()
    manifest = root / MANIFEST
    if not manifest.is_file() or manifest.is_symlink():
        raise ValueError('No API-011.6 manifest in this project')
    value = json.loads(manifest.read_text(encoding='utf-8'))
    files = value.get('files')
    if value.get('version') != '11.6' or not isinstance(files, dict) or not files or not set(files) <= ALLOWED:
        raise ValueError('Unsupported or malformed rollback manifest')
    paths = []
    for rel, record in files.items():
        target = root / rel
        if target.is_symlink() or not target.resolve().is_relative_to(root) or not target.is_file():
            raise ValueError(f'Unsafe or missing rollback target: {rel}')
        if not isinstance(record, dict) or checksum(target.read_bytes()) != record.get('new_sha256'):
            raise ValueError(f'File changed since installation: {rel}; rollback refused')
        backup = target.with_name(target.name + BACKUP)
        if record.get('original_exists'):
            if not backup.is_file() or backup.is_symlink() or checksum(backup.read_bytes()) != record.get('original_sha256'):
                raise ValueError(f'Original backup missing or altered: {rel}')
        else:
            if backup.exists():
                raise ValueError(f'Unexpected backup present: {rel}')
        paths.append((rel, target, backup, record['original_exists']))
    for rel, target, backup, original_exists in paths:
        if original_exists:
            backup.replace(target)
        else:
            target.unlink()
    manifest.unlink()
    return [x[0] for x in paths]


if __name__ == '__main__':
    if len(sys.argv) > 2:
        sys.exit('Usage: rollback_api_011_6.py [project-root]')
    try:
        restored = rollback(Path(sys.argv[1]) if len(sys.argv) == 2 else Path.cwd())
    except (OSError, ValueError, UnicodeError) as exc:
        sys.exit(f'ERROR: {exc}')
    print('API-011.6 reverted:')
    for rel in restored:
        print('  ' + rel)
