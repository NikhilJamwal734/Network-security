"""Roll back only if every installed file still matches the original patch."""
from __future__ import annotations
from hashlib import sha256
import json
from pathlib import Path
import sys


def sha(b:bytes)->str:return sha256(b).hexdigest()


def rollback(root:Path)->list[str]:
    root=root.resolve()
    manifest=root/'.api0114_install_manifest.json'
    if not manifest.is_file():raise ValueError('No API-011.4 installation manifest found')
    entries=json.loads(manifest.read_text(encoding='utf-8'))['files']
    for rel,info in entries.items():
        dest=root/rel
        if not dest.is_file() or sha(dest.read_bytes())!=info['new_sha256']:
            raise ValueError(f'File modified since installation; aborting rollback: {rel}')
        backup=dest.with_name(dest.name+'.before_api0114.bak')
        if info['original_exists'] and (not backup.is_file() or sha(backup.read_bytes())!=info['original_sha256']):
            raise ValueError(f'Backup missing/modified; aborting rollback: {rel}')
    for rel,info in entries.items():
        dest=root/rel
        backup=dest.with_name(dest.name+'.before_api0114.bak')
        if info['original_exists']:
            dest.write_bytes(backup.read_bytes())
            backup.unlink()
        else:dest.unlink()
    manifest.unlink()
    return list(entries)


if __name__=='__main__':
    if len(sys.argv)>2:sys.exit('Usage: rollback_api_011_4.py [project-root]')
    root=Path(sys.argv[1]) if len(sys.argv)==2 else Path.cwd()
    try:changed=rollback(root)
    except (OSError,ValueError,UnicodeError) as exc:sys.exit(f'ERROR: {exc}')
    print('Rolled back API-011.4:', changed)
