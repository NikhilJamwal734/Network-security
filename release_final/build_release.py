"""Guarded Windows builder for an already-passing local release gate.

Does not overwrite project source, change dependencies, disable AV, or sign code.
Builds the current project via the existing desktop_packaging scripts.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

from verify_final import source_fingerprint


def check_gate(root: Path, path: Path) -> dict:
    if path.is_symlink() or not path.is_file():
        raise ValueError('Release gate JSON not found or symlinked')
    data = json.loads(path.read_text(encoding='utf-8'))
    if data.get('release') != 'FirewallAnalyzer-final-F5-Phase3' or data.get('gate') != 'PASS':
        raise ValueError('Final gate must report PASS before packaging')
    if data.get('counts', {}).get('failed') != 0 or data.get('counts', {}).get('incomplete') != 0:
        raise ValueError('Release gate is not complete')
    checks=data.get('checks')
    if not isinstance(checks,list) or not checks or any(not isinstance(x,dict) or x.get('status') not in ('PASS','WARN') for x in checks):
        raise ValueError('Release gate entries invalid')
    required = {'Python regression suite','React production build','F5 evidence PDF',
                'Health API','JSON Logs API','F5 live API',
                'cisco_asa API','fortios API','snort API','suricata API'}
    by_name = {x.get('name'):x.get('status') for x in checks}
    missing = sorted(name for name in required if by_name.get(name) != 'PASS')
    if missing:
        raise ValueError('Missing required PASS checks: ' + ', '.join(missing))
    fingerprints = data.get('source_sha256')
    current = source_fingerprint(root)
    if not isinstance(fingerprints,dict) or fingerprints != current:
        raise ValueError('Tracked application source changed after verification; rerun final gate')
    return data


def detect_bad_npm_runner(builder: Path) -> bool:
    source=builder.read_text(encoding='utf-8-sig')
    return bool(re.search(r'\[\s*[\"\']npm[\"\']\s*,', source))


def run(argv: list[str], cwd: Path) -> None:
    print('Running:', ' '.join(argv))
    subprocess.run(argv, cwd=cwd, check=True)


def main(argv=None) -> int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root',type=Path,default=Path.cwd())
    p.add_argument('--gate',type=Path,default=Path('release_final_gate.json'))
    p.add_argument('--onedir',action='store_true',help='Bundle executable as folder instead of a single EXE')
    p.add_argument('--check-only',action='store_true',help='Check gate, source and packager compatibility without building')
    args=p.parse_args(argv)
    root=args.root.resolve()
    gate=args.gate.resolve()
    if sys.platform!='win32':
        print('STOP: Windows EXE packaging must run on Windows with the project venv Python.')
        return 2
    try:
        check_gate(root,gate)
        builder=root/'desktop_packaging/build_complete_exe.py'
        smoke=root/'desktop_packaging/smoke_complete_exe.py'
        if not builder.is_file() or not smoke.is_file():
            raise ValueError('Complete Windows EXE builder or smoke tester missing')
        if detect_bad_npm_runner(builder):
            raise ValueError('Builder still launches bare npm: apply your existing Windows npm.cmd build fix, rerun gate')
        if args.check_only:
            print('PASS: complete release gate and source unchanged; compatible builder detected')
            return 0
        run([sys.executable,str(builder),'--check'],root)
        command=[sys.executable,str(builder)]
        if args.onedir:
            command.append('--onedir')
        run(command,root)
        exe=(root/'desktop_release_folder/FirewallAnalyzer/FirewallAnalyzer.exe' if args.onedir
             else root/'desktop_release_single/FirewallAnalyzer.exe')
        if not exe.is_file() or exe.stat().st_size < 100_000:
            raise ValueError('Packaged EXE missing or implausibly small')
        run([sys.executable,str(smoke),'--exe',str(exe)],root)
        h=hashlib.sha256()
        with exe.open('rb') as f:
            for chunk in iter(lambda:f.read(1024*1024),b''):
                h.update(chunk)
        result={
            'release':'FirewallAnalyzer-final-F5-Phase3',
            'build_utc':datetime.now(timezone.utc).isoformat(),
            'local_exe_smoke':'PASS',
            'user_acceptance':'PENDING',
            'production_certified':False,
            'exe_sha256':h.hexdigest(), 'exe_bytes':exe.stat().st_size,
            'package_kind':'onedir' if args.onedir else 'onefile',
            'notes':['Test a fresh F5 upload with and without JSON metadata in this exact EXE.',
                     'Test Cisco ASA, FortiOS, Snort, Suricata, Logs and PDF in the EXE.',
                     'Binary is unsigned unless separately signed; PyInstaller output is not tamper-proof.']}
        out=root/'release_final_build_result.json'
        if out.is_symlink():
            raise ValueError('Release build receipt path is a symlink; refusing overwrite')
        out.write_text(json.dumps(result,indent=2)+'\n',encoding='utf8')
        print('BUILD AND EXE SMOKE PASSED:',exe)
        print('SHA256:',h.hexdigest())
        print('Final desktop manual acceptance remains required.')
        return 0
    except (ValueError, OSError, json.JSONDecodeError, subprocess.CalledProcessError) as exc:
        print('RELEASE BUILD BLOCKED:',exc, file=sys.stderr)
        return 1

if __name__ == '__main__':
    raise SystemExit(main())
