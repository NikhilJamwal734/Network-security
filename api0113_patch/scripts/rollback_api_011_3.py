"""Refuse rollback if any file has changed since the 11.3 installer."""
from __future__ import annotations
from hashlib import sha256
import json
from pathlib import Path
import sys


def rollback(root:Path)->list[str]:
    root=root.resolve()
    package=Path(__file__).resolve().parents[1]
    manifest=root/'.api0113_install_manifest.json'
    if not manifest.is_file(): raise ValueError('Installation manifest not found; cannot safely roll back')
    files=json.loads(manifest.read_text(encoding='utf-8'))['files']
    for rel,meta in files.items():
        dst=root/rel
        if not dst.is_file() or sha256(dst.read_bytes()).hexdigest()!=meta['new_sha256']:
            raise ValueError(f'File edited since installation, refusing rollback: {rel}')
        backup=dst.with_name(dst.name+'.before_api0113.bak')
        if meta['original_exists'] and (not backup.is_file() or sha256(backup.read_bytes()).hexdigest()!=meta['original_sha256']):
            raise ValueError(f'Backup invalid or missing, refusing rollback: {rel}')
    for rel,meta in files.items():
        dst=root/rel
        backup=dst.with_name(dst.name+'.before_api0113.bak')
        if meta['original_exists']:
            dst.write_bytes(backup.read_bytes())
            backup.unlink()
        else: dst.unlink()
    manifest.unlink()
    return list(files)


if __name__=='__main__':
    root=Path(sys.argv[1]) if len(sys.argv)==2 else Path.cwd()
    if len(sys.argv)>2: sys.exit('Usage: rollback_api_011_3.py [project-root]')
    try: changes=rollback(root)
    except (OSError, ValueError) as exc: sys.exit(f'ERROR: {exc}')
    print('Restored:',changes)
