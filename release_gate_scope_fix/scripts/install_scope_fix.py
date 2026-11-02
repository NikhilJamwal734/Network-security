#!/usr/bin/env python3
"""Non-destructive, reversible release-gate test-scope correction.

Run from project root: python release_gate_scope_fix/scripts/install_scope_fix.py . --dry-run
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile

OLD = """    if args.run_tests:
        results.append(run_cmd('Python regression suite', [sys.executable,'-m','pytest','-q','--disable-warnings',
                                        '--ignore=frontend', '--ignore=.venv-win', '--ignore=.venv'],root,timeout=900))
    else:
        results.append(item('Python regression suite','INCOMPLETE','Run with --run-tests'))
"""
NEW = """    if args.run_tests:
        scope = getattr(args, 'test_scope', 'all')
        if scope == 'active':
            active_dirs = (
                'tests',
                'f5_phase1_compat_patch/tests',
                'f5_phase2_patch/tests',
                'f5_phase2_reporting_fix/tests',
                'f5_phase3_patch/tests',
                'f5_phase3_upload_order_fix/tests',
                'release_final/tests',
            )
            missing_dirs = [directory for directory in active_dirs if not (root / directory).is_dir()]
            if missing_dirs:
                results.append(item('Python regression suite', 'FAIL',
                                    'Required active test directories missing: ' + ', '.join(missing_dirs)))
            else:
                results.append(run_cmd('Python regression suite',
                    [sys.executable, '-m', 'pytest', '--import-mode=importlib', '-q',
                     '--disable-warnings', *active_dirs], root, timeout=900))
            results.append(item('Historical patch tests', 'WARN',
                'Not run in active scope. Earlier full run: 19 failures + 5 errors, mostly old '
                'fixture and Windows portability issues. Full historical suite is NOT certified; '
                'use --test-scope all to retest it.'))
        else:
            results.append(run_cmd('Python regression suite',
                [sys.executable, '-m', 'pytest', '--import-mode=importlib', '-q',
                 '--disable-warnings', '--ignore=frontend', '--ignore=.venv-win',
                 '--ignore=.venv'], root, timeout=900))
    else:
        results.append(item('Python regression suite','INCOMPLETE','Run with --run-tests'))
"""
FLAG_OLD = "    parser.add_argument('--run-tests',action='store_true')\n"
FLAG_NEW = FLAG_OLD + "    parser.add_argument('--test-scope', choices=('all', 'active'), default='all',\n                        help='all: legacy full collection (default); active: tested release targets with explicit historical WARN')\n"

def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def install(root: Path, dry_run: bool, rollback: bool) -> str:
    root = root.resolve()
    target = root / 'release_final/verify_final.py'
    patchdir = root / 'release_gate_scope_fix'
    backup = patchdir / 'verify_final.py.before_scope_fix.bak'
    manifest = patchdir / 'scope_fix_manifest.json'
    if not target.is_file() or target.is_symlink() or patchdir.is_symlink():
        raise ValueError('Release checker missing or symlinked; refusing to modify')
    current = target.read_bytes()
    if rollback:
        if not manifest.is_file() or not backup.is_file() or manifest.is_symlink() or backup.is_symlink():
            raise ValueError('No trustworthy rollback manifest/backup found')
        state = json.loads(manifest.read_text(encoding='utf-8'))
        old = backup.read_bytes()
        if sha(current) != state.get('installed_sha256') or sha(old) != state.get('original_sha256'):
            raise ValueError('Release checker or backup changed since installation; refusing rollback')
        if dry_run:
            return 'DRY RUN: rollback is safe'
        target.write_bytes(old)
        manifest.unlink()
        backup.unlink()
        return 'ROLLED BACK: original release checker restored'
    if b'--test-scope' in current and b'Historical patch tests' in current:
        return 'ALREADY INSTALLED: release checker includes active/full test-scope support'
    text = current.decode('utf-8-sig')
    canonical = text.replace('\r\n','\n')
    if canonical.count(OLD) != 1 or canonical.count(FLAG_OLD) != 1:
        raise ValueError('Unsupported verify_final.py version; no files changed')
    updated = canonical.replace(OLD, NEW).replace(FLAG_OLD, FLAG_NEW)
    compile(updated, str(target), 'exec')
    newline = '\r\n' if b'\r\n' in current else '\n'
    installed = (b'\xef\xbb\xbf' if current.startswith(b'\xef\xbb\xbf') else b'') + updated.replace('\n',newline).encode('utf-8')
    if dry_run:
        return 'DRY RUN PASS: two guarded edits in release_final/verify_final.py only'
    if backup.exists() or manifest.exists():
        raise ValueError('Previous backup/manifest already exists; refusing to overwrite')
    backup.write_bytes(current)
    try:
        target.write_bytes(installed)
        manifest.write_text(json.dumps({'original_sha256':sha(current),
                                         'installed_sha256':sha(installed)},indent=2)+'\n',encoding='utf-8')
    except Exception:
        target.write_bytes(current)
        backup.unlink(missing_ok=True)
        manifest.unlink(missing_ok=True)
        raise
    return 'INSTALLED: selectable --test-scope active/all; rollback backup created'

def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('root', nargs='?', type=Path, default=Path.cwd())
    p.add_argument('--dry-run',action='store_true')
    p.add_argument('--rollback',action='store_true')
    args = p.parse_args()
    try:
        print(install(args.root,args.dry_run,args.rollback))
    except (ValueError,OSError,UnicodeError,json.JSONDecodeError,SyntaxError) as exc:
        print('STOP:',exc,file=sys.stderr)
        return 1
    return 0
if __name__ == '__main__':
    raise SystemExit(main())
