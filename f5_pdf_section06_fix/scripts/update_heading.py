#!/usr/bin/env python3
"""Conservative, reversible change to only F5 section 06's PDF heading."""
import argparse
import hashlib
import json
from pathlib import Path

TARGET = Path('frontend/src/utils/normalizedPdf.ts')
OLD = b'section("F5 BIG-IP Phases 1 + 2 - Detailed technical evidence");'
NEW = b'section("F5 BIG-IP LTM & Advanced WAF - Detailed Technical Evidence");'
BACKUP = Path('f5_pdf_section06_fix/backup/normalizedPdf.ts.original')
META = Path('f5_pdf_section06_fix/backup/change.json')

def digest(data):
    return hashlib.sha256(data).hexdigest()

def operation(root, dry_run=False, rollback=False):
    target=root/TARGET
    backup=root/BACKUP
    meta=root/META
    if not target.is_file():
        raise RuntimeError(f'Missing source file: {TARGET}')
    original=target.read_bytes()
    if rollback:
        if not backup.is_file() or not meta.is_file():
            raise RuntimeError('No installed-patch backup/metadata for rollback')
        m=json.loads(meta.read_text(encoding='utf-8'))
        backed=backup.read_bytes()
        if digest(original)!=m['after_sha256'] or digest(backed)!=m['before_sha256']:
            raise RuntimeError('Source/backup changed since installation; refusing rollback')
        if not dry_run:
            target.write_bytes(backed)
            meta.unlink()
            backup.unlink()
        return 'DRY-RUN ROLLBACK PASS' if dry_run else 'ROLLBACK PASS: Original PDF generator restored'
    nold=original.count(OLD)
    nnew=original.count(NEW)
    if nold==0 and nnew==1:
        return 'ALREADY INSTALLED: Heading updated; nothing modified'
    if nold!=1 or nnew!=0:
        raise RuntimeError(f'Unsupported generator layout: expected one original heading (old={nold}, new={nnew}); refusing to change any file')
    changed=original.replace(OLD,NEW)
    if changed.count(NEW)!=1 or changed.count(OLD)!=0:
        raise RuntimeError('Unsafe replacement result')
    if backup.exists() or meta.exists():
        raise RuntimeError('Backup already exists; refusing to overwrite it')
    if dry_run:
        return 'DRY RUN PASS: only section 06 heading would change in frontend/src/utils/normalizedPdf.ts'
    backup.parent.mkdir(parents=True,exist_ok=True)
    backup.write_bytes(original)
    meta.write_text(json.dumps({'target':str(TARGET),'before_sha256':digest(original),'after_sha256':digest(changed)},indent=2)+'\n',encoding='utf-8')
    target.write_bytes(changed)
    return 'INSTALLED: section 06 professional heading; original saved for rollback'

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('root', nargs='?', default='.')
    p.add_argument('--dry-run', action='store_true')
    p.add_argument('--rollback', action='store_true')
    a=p.parse_args()
    try:
        print(operation(Path(a.root).resolve(),dry_run=a.dry_run,rollback=a.rollback))
    except Exception as e:
        print(f'REFUSED: {e}')
        return 2
    return 0

if __name__=='__main__':
    raise SystemExit(main())
