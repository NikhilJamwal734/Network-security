"""Safe F5 Phase 1 compatibility installer.  Preserves all existing F5 modules."""
from __future__ import annotations
import argparse
import hashlib
import json
import sys
from pathlib import Path

BUNDLE = Path(__file__).resolve().parents[1]
FILES = tuple('app/f5_phase1_addon/' + x for x in (
  '__init__.py', 'parser.py', 'checks.py', 'profiles.py', 'api.py'))
MAIN = 'app/api/main.py'
REQUIRED = 'app/core/input_hardening.py'
MANIFEST = '.f5_phase1_addon_manifest.json'
BACKUP_SUFFIX = '.before_f5_phase1_addon.bak'
IMPORT = 'from app.f5_phase1_addon.api import router as f5_phase1_addon_router\n'
REGISTER = 'app.include_router(f5_phase1_addon_router)\n'
ANCHOR_IMPORT = 'from app.api.release_status import router as release_status_router\n'
ANCHOR_REGISTER = 'app.include_router(release_status_router)\n'

def _hash(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def _path(root: Path, rel: str) -> Path:
    p = root / rel
    if not p.resolve().is_relative_to(root.resolve()):
        raise ValueError(f'Unsafe destination: {rel}')
    if p.is_symlink() or any(parent.is_symlink() for parent in p.parents if parent != root.parent):
        raise ValueError(f'Symlink in destination path: {rel}')
    return p

def _update_main(raw: bytes) -> bytes:
    bom = raw.startswith(b'\xef\xbb\xbf')
    text = raw.decode('utf-8-sig')
    if '\r' in text.replace('\r\n','') or ('\r\n' in text and '\n' in text.replace('\r\n','')):
        raise ValueError('Mixed or invalid line endings in app/api/main.py')
    eol = '\r\n' if '\r\n' in text else '\n'
    txt = text.replace('\r\n', '\n')
    if txt.count(IMPORT) != txt.count(REGISTER) or txt.count(IMPORT) > 1:
        raise ValueError('F5 addon router partly installed or duplicated; review main.py')
    if not txt.count(IMPORT):
        # Older F5 installer may already have registered the same endpoint.
        if 'from app.api.f5_analysis import router as f5_phase1_router' in txt or 'include_router(f5_phase1_router)' in txt:
            raise ValueError('Original F5 Phase 1 API router already installed; avoid duplicate endpoints')
        if txt.count(ANCHOR_IMPORT) != 1 or txt.count(ANCHOR_REGISTER) != 1:
            raise ValueError('Required API-012.0 release_status anchor missing or duplicated')
        txt = txt.replace(ANCHOR_IMPORT, ANCHOR_IMPORT + IMPORT, 1)
        txt = txt.replace(ANCHOR_REGISTER, ANCHOR_REGISTER + REGISTER, 1)
    return (b'\xef\xbb\xbf' if bom else b'') + txt.replace('\n', eol).encode('utf-8')

def plan(root: Path) -> dict[str, bytes]:
    root = root.resolve()
    for name in (MAIN, REQUIRED):
        if not _path(root, name).is_file():
            raise ValueError(f'Required existing file missing: {name}')
    changes = {}
    old = _path(root, MAIN).read_bytes()
    new = _update_main(old)
    if new != old:
        changes[MAIN] = new
    for rel in FILES:
        src = (BUNDLE/rel).read_bytes()
        target = _path(root, rel)
        if target.exists():
            if not target.is_file() or target.read_bytes() != src:
                raise ValueError(f'Existing custom addon file at {rel}; refusing to overwrite')
        else:
            changes[rel] = src
    return changes

def install(root: Path, dry_run: bool=False) -> list[str]:
    root = root.resolve()
    changes = plan(root)
    manifest = _path(root, MANIFEST)
    if manifest.exists():
        if changes:
            raise ValueError('Existing addon manifest with changed files; no changes made')
        return []
    if dry_run: return list(changes)
    if not changes: return []
    for rel in changes:
        target = _path(root, rel)
        if target.with_name(target.name+BACKUP_SUFFIX).exists():
            raise ValueError(f'Previous backup exists for {rel}; no changes made')
    tmp = _path(root, MANIFEST+'.tmp')
    if tmp.exists():
        raise ValueError('Previous temporary manifest exists; no changes made')
    old = {rel: (_path(root,rel).read_bytes() if _path(root,rel).is_file() else None) for rel in changes}
    written = []
    try:
        for rel, data in changes.items():
            dest = _path(root, rel)
            dest.parent.mkdir(parents=True,exist_ok=True)
            if old[rel] is not None:
                dest.with_name(dest.name+BACKUP_SUFFIX).write_bytes(old[rel])
            dest.write_bytes(data)
            written.append(rel)
        metadata = {'version':1,'files':{rel:{'created':old[rel] is None,'installed_hash':_hash(changes[rel]),'original_hash':_hash(old[rel]) if old[rel] is not None else None} for rel in changes}}
        tmp.write_text(json.dumps(metadata,indent=2),encoding='utf-8')
        tmp.replace(manifest)
    except Exception:
        for rel in reversed(written):
            target = _path(root, rel)
            if old[rel] is None: target.unlink(missing_ok=True)
            else:
                target.write_bytes(old[rel]); target.with_name(target.name+BACKUP_SUFFIX).unlink(missing_ok=True)
        tmp.unlink(missing_ok=True)
        raise
    return list(changes)

def rollback(root: Path) -> list[str]:
    root = root.resolve()
    manifest = _path(root, MANIFEST)
    if not manifest.is_file(): raise ValueError('Addon manifest not found')
    metadata = json.loads(manifest.read_text(encoding='utf-8'))
    records = metadata.get('files')
    if metadata.get('version') != 1 or not isinstance(records, dict) or not set(records).issubset({MAIN,*FILES}):
        raise ValueError('Invalid addon manifest')
    for rel, record in records.items():
        target = _path(root, rel)
        if not target.is_file() or _hash(target.read_bytes()) != record['installed_hash']:
            raise ValueError(f'File changed since install, refusing rollback: {rel}')
        if not record['created']:
            backup=target.with_name(target.name+BACKUP_SUFFIX)
            if not backup.is_file() or _hash(backup.read_bytes()) != record['original_hash']:
                raise ValueError(f'Missing or changed backup for {rel}')
    for rel, record in records.items():
        target = _path(root,rel)
        if record['created']: target.unlink()
        else:
            backup=target.with_name(target.name+BACKUP_SUFFIX)
            target.write_bytes(backup.read_bytes()); backup.unlink()
    manifest.unlink()
    return list(records)

def main() -> int:
    ap=argparse.ArgumentParser(description='Install isolated F5 Phase 1 without overwriting existing F5 code')
    ap.add_argument('root',nargs='?',default='.')
    ap.add_argument('--dry-run',action='store_true')
    ap.add_argument('--rollback',action='store_true')
    args=ap.parse_args()
    try:
        results = rollback(Path(args.root)) if args.rollback else install(Path(args.root),dry_run=args.dry_run)
        print(('Rolled back' if args.rollback else ('Would update' if args.dry_run else 'Installed'))+':')
        print('\n'.join('  '+x for x in results) if results else '  No changes needed')
        return 0
    except (ValueError,OSError,UnicodeError,KeyError) as e:
        print('ERROR:',str(e),file=sys.stderr)
        return 1
if __name__=='__main__': raise SystemExit(main())
