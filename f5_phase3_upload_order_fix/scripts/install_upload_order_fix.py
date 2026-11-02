"""Safe one-line F5 Phase 3 file-picker order fix.

Preserve JSON evidence selected before the FIRST config file; reset evidence only
when an existing config is replaced. Reject unknown/customized frontend layouts.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import sys
from pathlib import Path

TARGET = 'frontend/src/pages/UniversalAnalysis.tsx'
MANIFEST = '.f5_phase3_upload_order_fix_manifest.json'
BACKUP = '.f5_phase3_upload_order_fix_backup.bin'
OLD = '    setF5EvidenceFile(null); // Do not reuse evidence with a different configuration.'
NEW = ('    setF5EvidenceFile((previous) => file ? null : previous); '
       '// Keep JSON selected before the first config; clear when replacing a config.')
REQUIRED = ('const [f5EvidenceFile, setF5EvidenceFile]',
            'await analyzeF5Phase1(file, controller.signal, f5EvidenceFile)',
            'Choose optional F5 operator evidence JSON')

def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()

def safe(root: Path, rel: str) -> Path:
    root = root.resolve()
    p = root
    for part in Path(rel).parts:
        p /= part
        if p.is_symlink():
            raise ValueError(f'Symlink not permitted: {rel}')
    if not p.resolve().is_relative_to(root):
        raise ValueError(f'Path outside project: {rel}')
    return p

def transform(raw: bytes) -> bytes:
    bom = raw.startswith(b'\xef\xbb\xbf')
    src = raw.decode('utf-8-sig')
    if '\r' in src.replace('\r\n',''):
        raise ValueError('Unsupported/mixed file line endings')
    eol = '\r\n' if '\r\n' in src else '\n'
    src = src.replace('\r\n','\n')
    if any(req not in src for req in REQUIRED):
        raise ValueError('The expected Phase 3 F5 upload flow is not installed')
    if src.count(NEW) == 1 and src.count(OLD) == 0:
        return raw
    if src.count(OLD) != 1 or NEW in src:
        raise ValueError('Expected Phase 3 upload-reset code not found exactly once; refusing changes')
    fixed = src.replace(OLD, NEW, 1)
    return (b'\xef\xbb\xbf' if bom else b'') + fixed.replace('\n',eol).encode('utf-8')

def install(root: Path, dry_run: bool=False) -> list[str]:
    root = root.resolve()
    target = safe(root, TARGET)
    manifest = safe(root, MANIFEST)
    backup = safe(root, BACKUP)
    if not target.is_file():
        raise ValueError('Missing frontend/src/pages/UniversalAnalysis.tsx')
    current = target.read_bytes()
    modified = transform(current)
    if manifest.exists():
        if modified != current:
            raise ValueError('Existing manifest conflicts with modified Phase 3 frontend')
        info = json.loads(manifest.read_text('utf-8'))
        if info.get('version') != 1 or info.get('installed_sha256') != sha(current):
            raise ValueError('Patch manifest does not match installed frontend')
        return []
    if modified == current:
        return []
    if backup.exists():
        raise ValueError('Existing backup file would be overwritten')
    if dry_run:
        return [TARGET]
    try:
        backup.write_bytes(current)
        target.write_bytes(modified)
        manifest.write_text(json.dumps({'version':1,'file':TARGET,
             'original_sha256':sha(current),'installed_sha256':sha(modified)},indent=2),encoding='utf-8')
    except Exception:
        target.write_bytes(current)
        manifest.unlink(missing_ok=True)
        backup.unlink(missing_ok=True)
        raise
    return [TARGET]

def rollback(root: Path) -> list[str]:
    root = root.resolve()
    target=safe(root,TARGET)
    manifest=safe(root,MANIFEST)
    backup=safe(root,BACKUP)
    if not manifest.is_file() or not backup.is_file():
        raise ValueError('No complete upload-order fix installation to roll back')
    info=json.loads(manifest.read_text('utf-8'))
    original=backup.read_bytes()
    if info.get('version') != 1 or info.get('file') != TARGET or sha(original) != info.get('original_sha256') or sha(target.read_bytes()) != info.get('installed_sha256'):
        raise ValueError('Files changed since installation; refusing unsafe rollback')
    target.write_bytes(original)
    manifest.unlink()
    backup.unlink()
    return [TARGET]

def main() -> int:
    ap=argparse.ArgumentParser(description='Phase 3 upload-order evidence preservation fix')
    ap.add_argument('root', nargs='?', default='.')
    ap.add_argument('--dry-run',action='store_true')
    ap.add_argument('--rollback',action='store_true')
    args=ap.parse_args()
    try:
        result = rollback(Path(args.root)) if args.rollback else install(Path(args.root),args.dry_run)
        print(('Rolled back:' if args.rollback else 'Would update:' if args.dry_run else 'Updated:'))
        print('\n'.join('  '+x for x in result) if result else '  No changes needed')
        return 0
    except (ValueError,OSError,UnicodeError,KeyError,TypeError) as exc:
        print('ERROR:',exc,file=sys.stderr)
        return 1

if __name__=='__main__':
    raise SystemExit(main())
