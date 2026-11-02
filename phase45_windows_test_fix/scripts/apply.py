"""Guarded, reversible repair of the Windows CRLF unit test fixture.

Does not change the production installer or any application source files.
"""
from __future__ import annotations
import argparse
from pathlib import Path
import sys

REL = Path('phase4_5_bundle/tests/test_install.py')
BACKUP_SUFFIX = '.pre_windows_fixture_fix.bak'
OLD = b"p.write_bytes(p.read_bytes().replace(b'\\n',b'\\r\\n'))"
NEW = b"p.write_bytes(p.read_bytes().replace(b'\\r\\n',b'\\n').replace(b'\\n',b'\\r\\n'))"


def apply(root: Path, dry_run: bool = False, rollback: bool = False) -> str:
    root = root.resolve()
    target = root / REL
    if not target.is_file() or target.is_symlink():
        raise ValueError(f'Expected original test missing or symlink: {REL}')
    backup = target.with_name(target.name + BACKUP_SUFFIX)
    contents = target.read_bytes()
    if rollback:
        if not backup.is_file() or backup.is_symlink():
            raise ValueError('No original test backup for rollback')
        original = backup.read_bytes()
        if contents.count(NEW) != 1 or original.count(OLD) != 1:
            raise ValueError('Test or backup differs: refusing unsafe rollback')
        target.write_bytes(original)
        backup.unlink()
        return 'ROLLBACK PASS: original unit test restored'
    if contents.count(NEW) == 1 and contents.count(OLD) == 0:
        return 'ALREADY PATCHED: Windows CRLF fixture corrected'
    if contents.count(OLD) != 1 or contents.count(NEW) != 0:
        raise ValueError('Expected old unit-test anchor not found exactly once; no changes made')
    if backup.exists():
        raise ValueError('Preexisting backup; refusing overwrite')
    if dry_run:
        return 'DRY RUN PASS: exactly one unit-test line would change; no source modified'
    backup.write_bytes(contents)
    target.write_bytes(contents.replace(OLD, NEW, 1))
    return 'PATCH PASS: Windows CRLF fixture corrected; rollback backup saved'


def main() -> int:
    p=argparse.ArgumentParser(description='Repair only phase4_5_bundle/tests/test_install.py CRLF test')
    p.add_argument('root', nargs='?', default='.')
    mode=p.add_mutually_exclusive_group()
    mode.add_argument('--dry-run', action='store_true')
    mode.add_argument('--rollback', action='store_true')
    a=p.parse_args()
    try:
        print(apply(Path(a.root), a.dry_run, a.rollback))
        return 0
    except (ValueError, OSError) as exc:
        print('ERROR: '+str(exc),file=sys.stderr)
        return 1

if __name__=='__main__':
    raise SystemExit(main())
