"""Rollback only the installed API-012.0 files when they remain unchanged."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys

from install_all_api_012_0 import (MANIFEST, BACKUP_SUFFIX, TARGET_MAIN,
                                 TARGET_MODULE, digest, safe_target)


def rollback(root: Path) -> list[str]:
    root = root.resolve()
    path = root / MANIFEST
    if not path.is_file() or path.is_symlink():
        raise ValueError('API-012.0 rollback manifest is missing')
    data = json.loads(path.read_text(encoding='utf-8'))
    files = data.get('files')
    if data.get('version') != '12.0' or not isinstance(files, dict) or not files or not set(files) <= {TARGET_MAIN.as_posix(), TARGET_MODULE.as_posix()}:
        raise ValueError('Malformed API-012.0 rollback manifest')
    entries = []
    for rel, item in files.items():
        dest = safe_target(root, Path(rel))
        if not dest.is_file() or not isinstance(item, dict) or digest(dest.read_bytes()) != item.get('installed_sha256'):
            raise ValueError(f'File changed; rollback refused: {rel}')
        backup = dest.with_name(dest.name + BACKUP_SUFFIX)
        if item.get('had_original') is True:
            if not backup.is_file() or backup.is_symlink() or digest(backup.read_bytes()) != item.get('original_sha256'):
                raise ValueError(f'Backup missing/modified; rollback refused: {rel}')
        elif item.get('had_original') is False:
            if backup.exists():
                raise ValueError(f'Unexpected backup; rollback refused: {rel}')
        else:
            raise ValueError('Malformed rollback entry')
        entries.append((rel, dest, backup, bool(item['had_original'])))
    # Validate all targets first; no partial rollback on validation failure.
    for _, dest, backup, existed in entries:
        if existed:
            backup.replace(dest)
        else:
            dest.unlink()
    path.unlink()
    return [item[0] for item in entries]


def main(argv=None) -> int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('root', nargs='?', type=Path, default=Path.cwd())
    args=p.parse_args(argv)
    try:
        restored=rollback(args.root)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print('ERROR: ' + str(exc), file=sys.stderr)
        return 1
    print('Rolled back:', ', '.join(restored))
    return 0

if __name__=='__main__':
    raise SystemExit(main())
