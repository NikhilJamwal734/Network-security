"""Atomic-as-practical staged API-011.4 installer with verified rollback manifest.

Prevalidates every backend/frontend patch and writes a manifest scoped to the
actual user project. On ordinary exceptions, restores already-replaced files.
"""
from __future__ import annotations
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

PACKAGE=Path(__file__).resolve().parents[1]


def load(path:Path,name:str):
    spec=importlib.util.spec_from_file_location(name,path)
    if spec is None or spec.loader is None: raise ValueError(f'Missing installer: {path}')
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sha(blob:bytes) -> str: return hashlib.sha256(blob).hexdigest()


def install(root:Path) -> list[str]:
    root=root.resolve()
    backend=load(PACKAGE/'scripts/install_api_011_4.py','api114_backend')
    frontend=load(PACKAGE/'frontend_patch/scripts/install_api_011_4_frontend.py','api114_frontend')
    changes={**backend.plan(root), **frontend.plan(root/'frontend')}
    manifest=root/'.api0114_install_manifest.json'
    if manifest.exists():
        if changes: raise ValueError('API-011.4 manifest exists but files changed; refusing reinstallation')
        return []
    if not changes: return []
    original={dst:dst.read_bytes() if dst.is_file() else None for dst in changes}
    for dst in changes:
        backup=dst.with_name(dst.name+'.before_api0114.bak')
        tmp=dst.with_name(dst.name+'.api0114.tmp')
        if backup.exists() or tmp.exists():
            raise ValueError(f'Backup or temporary file already exists: {dst}')
    details={dst.relative_to(root).as_posix(): {
        'original_exists': original[dst] is not None,
        'original_sha256': sha(original[dst]) if original[dst] is not None else None,
        'new_sha256': sha(changes[dst]),
    } for dst in changes}
    staged={}
    completed=[]
    try:
        for dst,data in changes.items():
            dst.parent.mkdir(parents=True,exist_ok=True)
            tmp=dst.with_name(dst.name+'.api0114.tmp')
            tmp.write_bytes(data)
            staged[dst]=tmp
        for dst,tmp in staged.items():
            old=original[dst]
            if old is not None:
                dst.with_name(dst.name+'.before_api0114.bak').write_bytes(old)
            tmp.replace(dst)
            completed.append(dst)
        tmp_manifest=manifest.with_suffix('.json.tmp')
        if tmp_manifest.exists(): raise ValueError(f'Manifest temp already exists: {tmp_manifest}')
        tmp_manifest.write_text(json.dumps({'api_version':'11.4','files':details},indent=2),encoding='utf-8')
        tmp_manifest.replace(manifest)
    except Exception:
        for dst in reversed(completed):
            if original[dst] is None:
                if dst.exists() and sha(dst.read_bytes())==sha(changes[dst]): dst.unlink()
            else:
                if dst.exists() and sha(dst.read_bytes())==sha(changes[dst]): dst.write_bytes(original[dst])
        for dst in changes:
            dst.with_name(dst.name+'.before_api0114.bak').unlink(missing_ok=True)
        manifest.with_suffix('.json.tmp').unlink(missing_ok=True)
        raise
    finally:
        for tmp in staged.values():tmp.unlink(missing_ok=True)
    return list(details)


if __name__=='__main__':
    if len(sys.argv)>2:sys.exit('Usage: install_all_api_011_4.py [project-root]')
    root=Path(sys.argv[1]) if len(sys.argv)==2 else Path.cwd()
    try:changes=install(root)
    except (OSError,ValueError,UnicodeError) as exc:sys.exit(f'ERROR: {exc}')
    print('API-011.4 installed:' if changes else 'API-011.4 already installed / no changes:')
    for x in changes: print('  '+x)
