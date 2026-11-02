"""Single-command API-011.3 installer: prevalidate both halves, safe rollback manifest."""
from __future__ import annotations
import hashlib
import importlib.util
import json
from pathlib import Path
import sys


def load(path:Path, name:str):
    spec=importlib.util.spec_from_file_location(name,path)
    if spec is None or spec.loader is None: raise ValueError('Missing installer: '+str(path))
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sha(data:bytes)->str: return hashlib.sha256(data).hexdigest()


def install(root:Path)->list[str]:
    root=root.resolve()
    package=Path(__file__).resolve().parents[1]
    backend=load(package/'scripts/install_api_011_3.py','backend113')
    frontend=load(package/'frontend_patch/scripts/install_api_011_3_frontend.py','frontend113')
    changes={**backend.plan(root),**frontend.plan(root/'frontend')}
    manifest=root/'.api0113_install_manifest.json'
    if manifest.exists():
        if changes: raise ValueError('Unexpected file modifications after API-011.3 install; refusing to overwrite')
        return []
    if not changes: return []
    backups={}
    for dst in changes:
        rel=dst.relative_to(root).as_posix()
        backups[rel]={'original_exists':dst.is_file(), 'new_sha256':sha(changes[dst])}
        if dst.is_file(): backups[rel]['original_sha256']=sha(dst.read_bytes())
    # Verify paths and write staged temp files before touching project source.
    staged={}
    try:
        for dst,data in changes.items():
            dst.parent.mkdir(parents=True,exist_ok=True)
            temp=dst.with_name(dst.name+'.api0113.tmp')
            if temp.exists(): raise ValueError(f'Temporary file exists: {temp}')
            temp.write_bytes(data)
            staged[dst]=temp
        for dst,temp in staged.items():
            backup=dst.with_name(dst.name+'.before_api0113.bak')
            if dst.exists() and backup.exists(): raise ValueError(f'Backup already exists: {backup}')
        for dst,temp in staged.items():
            if dst.exists():
                backup=dst.with_name(dst.name+'.before_api0113.bak')
                backup.write_bytes(dst.read_bytes())
            temp.replace(dst)
        manifest.write_text(json.dumps({'version':'11.3','files':backups},indent=2),encoding='utf-8')
    except Exception:
        # Restore any files already replaced, but do not discard unrelated edits.
        for dst in changes:
            backup=dst.with_name(dst.name+'.before_api0113.bak')
            rel=dst.relative_to(root).as_posix()
            if backup.exists():
                dst.write_bytes(backup.read_bytes()); backup.unlink()
            elif not backups[rel]['original_exists'] and dst.is_file() and sha(dst.read_bytes())==backups[rel]['new_sha256']:
                dst.unlink()
        raise
    finally:
        for temp in staged.values(): temp.unlink(missing_ok=True)
    return list(backups)


if __name__=='__main__':
    if len(sys.argv)>2: sys.exit('Usage: install_all_api_011_3.py [project-root]')
    root=Path(sys.argv[1]) if len(sys.argv)==2 else Path.cwd()
    try: changes=install(root)
    except (OSError, ValueError, UnicodeError) as exc: sys.exit(f'ERROR: {exc}')
    print('API-011.3 installed:' if changes else 'API-011.3 already installed / no changes:')
    for rel in changes: print('  '+rel)
