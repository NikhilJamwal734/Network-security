"""API-012.0 LOCAL release gate: checks installation and optional real workflows.

Outputs a sanitized JSON record and human summary. It does not certify security,
PDF appearance, or a public deployment. Optional tests/build need local tools.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from urllib.parse import urlsplit

REQUIRED_FILES = (
    'app/api/main.py', 'app/api/release_status.py',
    'app/api/hardened_analysis.py', 'app/core/input_hardening.py',
    'app/api/pipeline_validation.py', 'app/core/pipeline_validation.py',
    'frontend/package.json', 'frontend/src/api/universal.ts',
    'frontend/src/utils/normalizedPdf.ts',
)


def check(name, state, summary, *, category='local', recommendation=''):
    return {'name':name, 'status':state, 'summary':summary,
            'category': category, 'recommendation':recommendation}


def structural_checks(root: Path) -> list[dict]:
    results=[]
    for rel in REQUIRED_FILES:
        f=root / rel
        state = 'pass' if f.is_file() and not f.is_symlink() and f.resolve().is_relative_to(root) else 'fail'
        results.append(check('file: ' + rel, state, 'Required release component ' + ('present' if state=='pass' else 'missing/unsafe')))
    p=root/'app/api/main.py'
    if p.is_file():
        try:
            src=p.read_text(encoding='utf-8-sig')
            seen=(src.count('app.include_router(release_status_router)')==1 and
                  src.count('from app.api.release_status import router as release_status_router')==1 and
                  src.count('app.include_router(hardened_analysis_router)')==1)
            results.append(check('release router registration','pass' if seen else 'fail',
                                 'Release/status and validated upload routers registered once' if seen else 'Expected API registrations missing or duplicated'))
        except (UnicodeError,OSError):
            results.append(check('release router registration','fail','Unable to decode API router source'))
    f=root/'frontend/src/api/universal.ts'
    if f.is_file():
        try:
            src=f.read_text(encoding='utf-8-sig')
            found='/api/v1/analyze/hardened' in src
            results.append(check('validated upload wiring','pass' if found else 'fail',
                                  'Frontend references the hardened endpoint' if found else 'Frontend not configured for hardened uploads'))
        except (UnicodeError,OSError):
            results.append(check('validated upload wiring','fail','Frontend API source cannot be decoded'))
    else:
        results.append(check('validated upload wiring','fail','Frontend API source absent'))
    # Earlier endpoints remain callable; report it as a deployment restriction.
    results.append(check('legacy API exposure','warn',
                         'Earlier non-hardened API routes may still be accessible',
                         category='deployment',
                         recommendation='Protect/remove old routes at deployment, enforce auth and gateway limits'))
    results.append(check('production deployment controls','warn',
                         'Authentication, TLS, network policy, proxy upload limits and isolation cannot be verified from local sources',
                         category='deployment',
                         recommendation='Validate authenticated access, proxy limits, allowlist, TLS, audit logging and resource isolation'))
    return results


def execute(label: str, args: list[str], cwd: Path, timeout: int) -> dict:
    # File-backed logs avoid keeping very large pytest output in memory.
    try:
        with tempfile.TemporaryDirectory(prefix='api0120_') as work:
            logfile = Path(work)/'result.txt'
            with logfile.open('w', encoding='utf-8', errors='replace') as out:
                try:
                    proc = subprocess.run(args, cwd=cwd, stdin=subprocess.DEVNULL,
                                          stdout=out, stderr=subprocess.STDOUT,
                                          timeout=timeout, check=False)
                    code=proc.returncode
                    suffix='exit code '+str(code)
                except subprocess.TimeoutExpired:
                    code=-1
                    suffix='timed out'
            # Tail without storing the entire log; no user input content is emitted.
            with logfile.open('rb') as f:
                f.seek(0,2)
                length=f.tell()
                f.seek(max(0,length-2048))
                tail=f.read().decode('utf-8',errors='replace')
        lines=[s.strip() for s in tail.splitlines() if s.strip()]
        # Avoid leaking filenames, secrets, or test sample contents into JSON.
        count_line=next((s for s in reversed(lines) if re.fullmatch(r'\d+ passed(?:, \d+ (?:skipped|warnings?|failed|errors?))* in [\d.]+s',s)),None)
        summary=f'{label}: {count_line}' if count_line else f'{label}: {suffix}'
        return check(label, 'pass' if code==0 else 'fail', summary)
    except (OSError,ValueError) as exc:
        return check(label,'fail',f'{label} could not run ({type(exc).__name__})')


def pdf_check(path: Path) -> dict:
    if not path.is_file() or path.is_symlink():
        return check('saved PDF audit','fail','No regular saved PDF found')
    if path.stat().st_size>80*1024*1024:
        return check('saved PDF audit','fail','PDF exceeds 80 MiB offline audit cap')
    try:
        from pypdf import PdfReader
    except ImportError:
        return check('saved PDF audit','fail','pypdf not installed; cannot parse saved PDF',
                     recommendation='Run python -m pip install pypdf in the selected environment')
    try:
        with path.open('rb') as f:
            signature=f.read(5)
            if signature!=b'%PDF-':
                return check('saved PDF audit','fail','Invalid PDF signature')
            f.seek(0)
            reader=PdfReader(f,strict=True)
            pages=len(reader.pages)
            if pages<=0:
                return check('saved PDF audit','fail','No PDF pages parsed')
            if reader.is_encrypted:
                return check('saved PDF audit','fail','Encrypted PDF cannot be independently inspected')
            page_text=' '.join((page.extract_text() or '') for page in reader.pages[:min(pages,100)])
            if not page_text.strip():
                return check('saved PDF audit','warn',f'PDF has {pages} page(s), but no extractable text')
            return check('saved PDF audit','pass',f'PDF parsed with {pages} page(s) and extractable text')
    except Exception:
        return check('saved PDF audit','fail','Independent PDF parser rejected report or extraction failed')


def validate_loopback(url: str) -> None:
    u=urlsplit(url)
    if u.scheme!='http' or u.hostname not in ('127.0.0.1','localhost') or u.username or u.password or u.path not in ('','/') or u.query or u.fragment:
        raise ValueError('Only localhost HTTP base URLs are supported')


def audit(root: Path, *, run_tests=False, run_frontend_build=False,
          pdf=None, smoke_file=None, platform=None, url='http://127.0.0.1:8000') -> dict:
    root=root.resolve()
    if not root.is_dir():
        raise ValueError('Project root is not a directory')
    validate_loopback(url)
    findings=structural_checks(root)
    if run_tests:
        findings.append(execute('backend regression tests', [sys.executable,'-m','pytest','-q','--disable-warnings',
                  '--ignore=frontend','--ignore=api0120_patch'],root,timeout=240))
    else:
        findings.append(check('backend regression tests','not_run','Not requested'))
    if run_frontend_build:
        npm=shutil.which('npm.cmd' if os.name=='nt' else 'npm')
        findings.append(execute('frontend production build',[npm,'run','build'],root/'frontend',240) if npm
                        else check('frontend production build','fail','npm executable missing'))
    else:
        findings.append(check('frontend production build','not_run','Not requested'))
    findings.append(pdf_check(Path(pdf).resolve()) if pdf is not None else
                    check('saved PDF audit','not_run','No downloaded PDF supplied'))
    if smoke_file is not None:
        src=Path(smoke_file).resolve()
        if not src.is_file():
            findings.append(check('localhost upload smoke','fail','Configuration sample not found'))
        else:
            script=Path(__file__).with_name('smoke_test.py')
            args=[sys.executable,str(script),'--file',str(src),'--url',url]
            if platform: args+=['--platform',platform]
            findings.append(execute('localhost upload smoke',args,root,90))
    else:
        findings.append(check('localhost upload smoke','not_run','No sample configuration supplied'))
    fail=sum(x['status']=='fail' for x in findings)
    local_incomplete=sum(x['status']=='not_run' for x in findings)
    deployment_warn=sum(x['category']=='deployment' and x['status']=='warn' for x in findings)
    return {
       'release':'12.0', 'generated_utc':datetime.now(timezone.utc).isoformat(),
       'local_gate':'failed' if fail else 'incomplete' if local_incomplete else 'passed',
       'production_ready': False,
       'message':'Local checks do not attest authentication, network restrictions, or deployment safety.',
       'counts': {'failed':fail,'not_run':local_incomplete,'deployment_warnings':deployment_warn},
       'checks':findings,
    }


def main(argv=None) -> int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root',type=Path,default=Path.cwd())
    p.add_argument('--run-tests',action='store_true',help='Execute complete backend pytest suite')
    p.add_argument('--run-frontend-build',action='store_true',help='Execute npm run build')
    p.add_argument('--pdf',type=Path,help='Saved PDF to audit offline')
    p.add_argument('--smoke-file',type=Path,help='Configuration to upload to a running localhost server')
    p.add_argument('--platform',choices=('cisco_asa','fortios','snort','suricata'))
    p.add_argument('--url',default='http://127.0.0.1:8000')
    p.add_argument('--json-out',type=Path,help='Explicit destination for release audit JSON')
    a=p.parse_args(argv)
    try:
        info=audit(a.root,run_tests=a.run_tests,run_frontend_build=a.run_frontend_build,
                   pdf=a.pdf,smoke_file=a.smoke_file,platform=a.platform,url=a.url)
    except (OSError,ValueError) as exc:
        p.error(str(exc))
    for item in info['checks']:
        print(f"[{item['status'].upper()}] {item['name']}: {item['summary']}")
    print('LOCAL GATE:',info['local_gate'].upper(), '| Production readiness: NOT CERTIFIED')
    if a.json_out:
        out=a.json_out.resolve()
        out.parent.mkdir(parents=True,exist_ok=True)
        if out.is_symlink():
            p.error('Refusing to write to a symlink')
        out.write_text(json.dumps(info,indent=2)+'\n',encoding='utf-8')
        print('Audit JSON:',out)
    return 1 if info['local_gate']=='failed' else 2 if info['local_gate']=='incomplete' else 0

if __name__=='__main__':
    raise SystemExit(main())
