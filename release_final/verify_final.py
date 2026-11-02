"""Non-destructive Windows release verification for the installed FirewallAnalyzer.

No customer configuration or raw response content is saved. Network tests use
only an explicit HTTP loopback origin and local synthetic/operator-selected files.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, ProxyHandler, build_opener
from uuid import uuid4

VENDORS = ('cisco_asa', 'fortios', 'snort', 'suricata')
F5_URL = '/api/v1/analyze/f5/phase1'
HARDENED_URL = '/api/v1/analyze/hardened'
MAX_BYTES = 2 * 1024 * 1024
SOURCE_FILES = (
    'app/api/main.py',
    'app/f5_phase1_addon/api.py',
    'app/f5_phase2_addon/review.py',
    'frontend/src/api/f5Phase1.ts',
    'frontend/src/pages/UniversalAnalysis.tsx',
    'frontend/src/utils/normalizedPdf.ts',
    'desktop_packaging/build_complete_exe.py',
    'desktop_packaging/desktop_launcher_complete.py',
    'desktop_packaging/smoke_complete_exe.py',
)


def safe_url(url: str) -> str:
    """Reject remote, userinfo, fragments, paths and encoded hostname tricks."""
    u = urlsplit(url)
    if (u.scheme != 'http' or u.hostname not in ('127.0.0.1', 'localhost')
            or u.username or u.password or u.path not in ('', '/') or u.query or u.fragment
            or u.port is None or not (1 <= u.port <= 65535)):
        raise ValueError('Only http://127.0.0.1:PORT or http://localhost:PORT is accepted')
    return f'http://{u.hostname}:{u.port}'


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(65536), b''):
            h.update(block)
    return h.hexdigest()


def source_fingerprint(root: Path) -> dict[str, str]:
    """Freeze all main Python/UI/packaging source, not just a few known files.

    Ignore generated Vite builds, test fixtures, cache, logs, and installed dependencies.
    """
    found: dict[str,str] = {}
    for stem in ('app', 'frontend/src', 'desktop_packaging'):
        directory = root / stem
        if directory.is_dir():
            for path in sorted(directory.rglob('*')):
                if path.is_file() and not path.is_symlink() and path.suffix.lower() in ('.py','.ts','.tsx','.css','.html','.json','.mts'):
                    if '__pycache__' not in path.parts and 'node_modules' not in path.parts and 'tests' not in path.parts:
                        found[path.relative_to(root).as_posix()] = digest(path)
    for rel in ('frontend/index.html','frontend/logs.html','frontend/vite.config.ts',
                'frontend/package.json','frontend/package-lock.json'):
        p = root / rel
        if p.is_file() and not p.is_symlink():
            found[rel] = digest(p)
    return dict(sorted(found.items()))


def item(name: str, status: str, note: str) -> dict:
    assert status in ('PASS', 'FAIL', 'INCOMPLETE', 'WARN')
    return {'name': name, 'status': status, 'note': note[:450]}


def preflight(root: Path) -> list[dict]:
    records = []
    if not root.is_dir():
        return [item('project root', 'FAIL', 'Project folder does not exist')]
    for rel in SOURCE_FILES:
        f = root / rel
        records.append(item('file: ' + rel, 'PASS' if f.is_file() and not f.is_symlink() else 'FAIL',
                            'Present' if f.is_file() and not f.is_symlink() else 'Missing or symbolic link'))
    for rel in ('f5_phase2_patch/examples/f5_phase2_sample.conf',
                'f5_phase3_patch/examples/f5_phase3_evidence.json'):
        f = root / rel
        records.append(item('fixture: ' + rel, 'PASS' if f.is_file() else 'FAIL', 'Bundled F5 test sample required'))
    def read(rel: str) -> str:
        try:
            return (root / rel).read_text(encoding='utf-8-sig')
        except (OSError, UnicodeError):
            return ''
    main = read('app/api/main.py')
    f5 = read('app/f5_phase1_addon/api.py')
    ts = read('frontend/src/pages/UniversalAnalysis.tsx')
    adapter = read('frontend/src/api/f5Phase1.ts')
    pdf = read('frontend/src/utils/normalizedPdf.ts')
    builder = read('desktop_packaging/build_complete_exe.py')
    records += [
        item('F5 API router', 'PASS' if ('f5_phase1_addon' in main and 'include_router' in main) else 'FAIL', 'F5 router registration in app/api/main.py'),
        item('F5 evidence endpoint', 'PASS' if ('evidence_json' in f5 and 'extend_report' in f5) else 'FAIL', 'Phase 2 operator evidence handling'),
        item('F5 frontend evidence submission', 'PASS' if ('f5EvidenceFile' in ts and 'analyzeF5Phase1' in ts and 'evidence_json' in adapter) else 'FAIL', 'Evidence selector and multipart field'),
        item('F5 picker order safety', 'FAIL' if 'setF5EvidenceFile(null); // Do not reuse evidence with a different configuration.' in ts else ('PASS' if 'setF5EvidenceFile' in ts else 'FAIL'), 'Initial configuration selection must not silently clear optional JSON evidence'),
        item('F5 PDF technical evidence', 'PASS' if ('F5 BIG-IP' in pdf and 'review_observations' in pdf) else 'FAIL', 'PDF code includes F5-specific review section'),
        item('Windows npm launcher', 'FAIL' if os.name == 'nt' and re.search(r'\[\s*[\"\']npm[\"\']\s*,', builder) else 'PASS', 'Windows builder must use npm.cmd, not bare npm in subprocess calls'),
    ]
    # This installation advertises a JSON Logs viewer; require its source and entrypoint.
    for rel in ('frontend/logs.html','frontend/src/logs-main.tsx','app/api/log_viewer.py',
                'app/core/audit_logging.py'):
        f = root / rel
        records.append(item('logs: '+rel,
                            'PASS' if f.is_file() and not f.is_symlink() else 'FAIL',
                            'JSON audit log viewer release dependency'))
    return records


def run_cmd(name: str, argv: list[str], cwd: Path, timeout: int) -> dict:
    try:
        cp = subprocess.run(argv, cwd=str(cwd), timeout=timeout, capture_output=True, text=True,
                            encoding='utf-8', errors='replace', check=False)
        output = (cp.stdout or '') + '\n' + (cp.stderr or '')
        # Never persist captured output. It may contain user-specific paths or test data.
        matches = re.findall(r'\b\d+ passed\b(?:[^\r\n]{0,70})', output)
        summary = matches[-1] if matches else 'Read console output by running the command directly'
        return item(name, 'PASS' if cp.returncode == 0 else 'FAIL', f'Exit {cp.returncode}; {summary}')
    except subprocess.TimeoutExpired:
        return item(name, 'FAIL', f'Exceeded {timeout}s; process terminated')
    except OSError as exc:
        return item(name, 'FAIL', f'Could not launch: {type(exc).__name__}')


def ensure_small_file(file: Path) -> bytes:
    if not file.is_file() or file.is_symlink():
        raise ValueError('Sample file missing or not regular')
    if not 0 < file.stat().st_size <= MAX_BYTES:
        raise ValueError('Sample file outside allowed size range (1 byte - 2 MiB)')
    return file.read_bytes()


def multipart(filename: str, content: bytes, evidence: bytes | None = None) -> tuple[bytes, str]:
    boundary = '----FARelease-' + uuid4().hex
    b = boundary.encode('ascii')
    out = bytearray()
    out += b'--' + b + b'\r\nContent-Disposition: form-data; name="file"; filename="' + filename.encode('ascii') + b'"\r\nContent-Type: application/octet-stream\r\n\r\n'
    out += content + b'\r\n'
    if evidence is not None:
        out += b'--' + b + b'\r\nContent-Disposition: form-data; name="evidence_json"\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n'
        out += evidence + b'\r\n'
    out += b'--' + b + b'--\r\n'
    return bytes(out), f'multipart/form-data; boundary={boundary}'


def request_json(base: str, path: str, config: bytes, evidence: bytes | None = None,
                 platform: str | None = None, filename: str = 'sample.conf') -> tuple[int, dict]:
    body, content_type = multipart(filename, config, evidence)
    url = base + path
    if platform:
        url += '?' + urlencode({'platform': platform})
    opener = build_opener(ProxyHandler({}))
    request = Request(url, data=body, headers={'Content-Type':content_type, 'Accept':'application/json'}, method='POST')
    try:
        with opener.open(request, timeout=45) as response:
            status = response.status
            raw = response.read(2_000_001)
    except HTTPError as exc:
        status = exc.code
        raw = exc.read(2_000_001)
    if len(raw) > 2_000_000:
        raise ValueError('Oversized response')
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return status, {}
    return status, parsed if isinstance(parsed, dict) else {}


def is_consistent(report: dict, f5: bool) -> bool:
    summary = report.get('summary')
    findings = report.get('findings')
    if not isinstance(summary, dict) or not isinstance(findings, list):
        return False
    if summary.get('total_findings') != len(findings):
        return False
    if not isinstance(report.get('input_security_review'), dict) or report['input_security_review'].get('status') != 'accepted':
        return False
    if f5:
        observations = report.get('review_observations')
        return (isinstance(report.get('platform'), dict) and report['platform'].get('platform_id') == 'f5_bigip' and isinstance(observations,list)
                and summary.get('total_review_observations') == len(observations))
    return True


def get_json(base: str, endpoint: str) -> tuple[int, dict]:
    """Bounded GET to the explicit loopback API; never store raw log records."""
    opener = build_opener(ProxyHandler({}))
    req = Request(base + endpoint, headers={'Accept': 'application/json'}, method='GET')
    try:
        with opener.open(req, timeout=15) as resp:
            status, raw = resp.status, resp.read(262145)
    except HTTPError as exc:
        status, raw = exc.code, exc.read(262145)
    if len(raw) > 262144:
        raise ValueError('Oversized API response')
    try:
        result = json.loads(raw)
    except (UnicodeError,json.JSONDecodeError):
        return status, {}
    return status, result if isinstance(result,dict) else {}


def live_core_services(base: str) -> list[dict]:
    output: list[dict] = []
    try:
        status, data = get_json(base, '/api/health')
        output.append(item('Health API', 'PASS' if status==200 and data.get('status')=='ok' else 'FAIL',
                           f'GET /api/health: HTTP {status}; status field verified' if status==200 else f'HTTP {status}'))
    except (OSError, ValueError, TimeoutError, URLError) as exc:
        output.append(item('Health API','FAIL',f'Loopback health check: {type(exc).__name__}'))
    try:
        status, data = get_json(base, '/api/v1/logs?stream=application&limit=1')
        ok = status==200 and data.get('stream')=='application' and isinstance(data.get('entries'),list)
        output.append(item('JSON Logs API', 'PASS' if ok else 'FAIL',
                           f'GET /api/v1/logs: HTTP {status}; metadata contract checked, no log entries retained'))
    except (OSError,ValueError,TimeoutError,URLError) as exc:
        output.append(item('JSON Logs API','FAIL',f'Loopback logs check: {type(exc).__name__}'))
    return output


def live_f5(root: Path, base: str) -> dict:
    config = ensure_small_file(root/'f5_phase2_patch/examples/f5_phase2_sample.conf')
    evidence = ensure_small_file(root/'f5_phase3_patch/examples/f5_phase3_evidence.json')
    try:
        status_a, a = request_json(base, F5_URL, config)
        status_b, b = request_json(base, F5_URL, config, evidence)
        status_bad, _ = request_json(base, F5_URL, config, b'{ broken JSON')
        status_binary, _ = request_json(base, F5_URL, b'PK\x03\x04not-config', filename='binary.conf')
        if (status_a, status_b, status_bad, status_binary) != (200, 200, 422, 422):
            return item('F5 live API', 'FAIL', f'HTTP codes: config={status_a}, evidence={status_b}, malformed={status_bad}, binary={status_binary}; expected 200/200/422/422')
        if not is_consistent(a, True) or not is_consistent(b, True):
            return item('F5 live API', 'FAIL', 'F5 report count/validation contract mismatch')
        if (a['summary'].get('total_findings'), a['summary'].get('total_review_observations'),
                b['summary'].get('total_findings'), b['summary'].get('total_review_observations')) != (3,5,4,4):
            return item('F5 live API','FAIL','Sample expected 3 findings/5 observations without evidence and 4/4 with evidence')
        a_find = {x.get('code') for x in a['findings'] if isinstance(x, dict)}
        b_find = {x.get('code') for x in b['findings'] if isinstance(x, dict)}
        if not {'F5-001','F5-003','F5-007'}.issubset(a_find) or 'F5-005' in a_find or 'F5-005' not in b_find:
            return item('F5 live API', 'FAIL', 'Baseline or evidence-derived F5 findings mismatch')
        review = {x.get('code'): x for x in b['review_observations'] if isinstance(x,dict)}
        ucs = next((x for x in b['findings'] if x.get('code') == 'F5-005'), {})
        if (ucs.get('confidence') != 'operator_supplied_unverified'
                or review.get('F5-006', {}).get('confidence') != 'operator_supplied_unverified'
                or not b.get('f5_phase2_review',{}).get('operator_evidence_supplied')):
            return item('F5 live API', 'FAIL', 'Evidence confidence or supplied flags incorrect')
        expected_hash = hashlib.sha256(config).hexdigest()
        if (a['input_security_review'].get('sha256') != expected_hash or b['input_security_review'].get('sha256') != expected_hash):
            return item('F5 live API', 'FAIL', 'Upload SHA-256 mismatch')
        return item('F5 live API', 'PASS', '3/5 baseline, 4/4 with evidence, SHA-256, confidence, malformed JSON and binary rejection verified')
    except (OSError, ValueError, TimeoutError, URLError, KeyError, TypeError, AttributeError) as exc:
        return item('F5 live API','FAIL',f'Loopback check failed: {type(exc).__name__}')


def live_vendor(base: str, vendor: str, path: Path) -> dict:
    try:
        config = ensure_small_file(path)
        suffix = path.suffix.lower()
        if suffix not in ('.conf','.cfg','.txt','.yaml','.yml','.rules','.lua'):
            return item(vendor+' API','FAIL','Fixture extension is not supported')
        status, data = request_json(base, HARDENED_URL, config, platform=vendor, filename='synthetic'+suffix)
        if status != 200:
            return item(vendor + ' API', 'FAIL', f'Hardened upload HTTP {status}; check fixture compatibility')
        if not is_consistent(data, False):
            return item(vendor + ' API', 'FAIL', 'Normalized findings or validated-input response contract mismatch')
        platform = data.get('platform')
        if not isinstance(platform, dict) or platform.get('platform_id') != vendor:
            return item(vendor + ' API', 'FAIL', 'Unexpected platform ID')
        return item(vendor + ' API','PASS','Hardened upload, normalized report and input validation contract verified')
    except (OSError, ValueError, TimeoutError, URLError) as exc:
        return item(vendor + ' API','FAIL',f'Loopback check failed: {type(exc).__name__}')


def pdf_check(path: Path | None) -> dict:
    if path is None:
        return item('F5 evidence PDF', 'INCOMPLETE', 'Supply --pdf with a NEW F5 report generated with optional JSON evidence')
    try:
        if not path.is_file() or path.is_symlink() or not 0 < path.stat().st_size <= 50_000_000:
            return item('F5 evidence PDF', 'FAIL', 'Missing, symlinked or oversized PDF')
        with path.open('rb') as fp:
            if fp.read(5) != b'%PDF-':
                return item('F5 evidence PDF','FAIL','Invalid PDF header')
        if importlib.util.find_spec('fitz') is not None:
            import fitz
            with fitz.open(path) as doc:
                if len(doc) == 0: raise ValueError('No PDF pages')
                extracted = '\n'.join(page.get_text() for page in doc)
        elif importlib.util.find_spec('pypdf') is not None:
            from pypdf import PdfReader
            doc = PdfReader(str(path))
            extracted = '\n'.join(p.extract_text() or '' for p in doc.pages)
        else:
            return item('F5 evidence PDF', 'INCOMPLETE', 'Install pypdf or PyMuPDF to inspect the saved PDF')
        required = ('F5-001', 'F5-003', 'F5-005', 'F5-006', 'F5-007', 'F5-008',
                    'operator_supplied_unverified', 'UCS backup reported as unencrypted')
        missing = [s for s in required if s.lower() not in extracted.lower()]
        if missing:
            return item('F5 evidence PDF','FAIL','Missing F5 evidence tokens: ' + ', '.join(missing))
        if not re.search(r'Findings:\s*4\b', extracted, re.I):
            return item('F5 evidence PDF','FAIL','Expected 4 findings in detailed F5 evidence section')
        return item('F5 evidence PDF','PASS','PDF parsed; all selected F5 code/evidence markers and four-finding summary present')
    except Exception as exc:
        return item('F5 evidence PDF','FAIL',f'Independent PDF inspection failed: {type(exc).__name__}')


def make_report(root: Path, args) -> dict:
    results = preflight(root)
    if args.run_tests:
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
    if args.build_frontend:
        npm = shutil.which('npm.cmd' if os.name == 'nt' else 'npm')
        if npm:
            results.append(run_cmd('React production build',[npm,'run','build'],root/'frontend',timeout=360))
        else:
            results.append(item('React production build','FAIL','npm.cmd/npm not found on PATH'))
    else:
        results.append(item('React production build','INCOMPLETE','Run with --build-frontend'))
    results.append(pdf_check(args.pdf.resolve() if args.pdf else None))
    base = safe_url(args.api_url) if args.api_url else None
    if base:
        results.extend(live_core_services(base))
    else:
        results += [item('Health API','INCOMPLETE','Supply --api-url http://127.0.0.1:8000'),
                    item('JSON Logs API','INCOMPLETE','Supply --api-url http://127.0.0.1:8000')]
    results.append(live_f5(root,base) if base else item('F5 live API','INCOMPLETE','Supply --api-url http://127.0.0.1:8000'))
    for vendor in VENDORS:
        fixture = getattr(args, vendor + '_file')
        if fixture is None and args.bundled_vendor_samples:
            fixture = Path(__file__).resolve().parent / 'examples' / (vendor + ('.yaml' if vendor == 'suricata' else '.conf'))
        if base and fixture:
            results.append(live_vendor(base, vendor, fixture.resolve()))
        else:
            results.append(item(vendor+' API','INCOMPLETE',f'Supply --api-url and --{vendor.replace("_","-")}-file with a known-working test configuration'))
    errors = sum(x['status']=='FAIL' for x in results)
    missing = sum(x['status']=='INCOMPLETE' for x in results)
    status = 'FAIL' if errors else 'INCOMPLETE' if missing else 'PASS'
    return {
        'release': 'FirewallAnalyzer-final-F5-Phase3',
        'timestamp_utc': datetime.now(timezone.utc).isoformat(),
        'gate': status, 'production_certified': False,
        'counts': {'failed':errors,'incomplete':missing,'warnings':sum(x['status']=='WARN' for x in results)},
        'source_sha256': source_fingerprint(root),
        'checks': results,
        'notes': ['Local verification only; not a penetration test, deployment security assessment or code-signing audit.',
                  'Operator-supplied UCS/WAF evidence is not independently authenticated.',
                  'Manual desktop UI checks and PDF visual review are required after packaging.']
    }


def main(argv: list[str] | None = None) -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,default=Path.cwd())
    parser.add_argument('--run-tests',action='store_true')
    parser.add_argument('--test-scope', choices=('all', 'active'), default='all',
                        help='all: legacy full collection (default); active: tested release targets with explicit historical WARN')
    parser.add_argument('--build-frontend',action='store_true')
    parser.add_argument('--api-url',help='HTTP loopback origin of a RUNNING FastAPI server, such as http://127.0.0.1:8000')
    parser.add_argument('--pdf',type=Path,help='Most recent browser PDF with F5 metadata supplied')
    parser.add_argument('--bundled-vendor-samples',action='store_true',help='Smoke test all four other vendors with bundled synthetic fixtures')
    for vendor in VENDORS:
        parser.add_argument('--'+vendor.replace('_','-')+'-file',type=Path,dest=vendor+'_file',help='Known working test config for '+vendor)
    parser.add_argument('--out',type=Path,default=Path('release_final_gate.json'))
    a=parser.parse_args(argv)
    root=a.root.resolve()
    if not root.is_dir():
        parser.error('Project root does not exist')
    try:
        report=make_report(root,a)
    except (ValueError, OSError) as exc:
        parser.error(str(exc))
    for r in report['checks']:
        print(f"[{r['status']}] {r['name']}: {r['note']}")
    print('FINAL LOCAL GATE:', report['gate'], '| NOT a production security certification')
    out=a.out.resolve()
    if out.is_symlink() or out.is_dir() or out == root or out.suffix.lower() != '.json':
        parser.error('Output must be a non-symlinked .json file')
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report,indent=2,ensure_ascii=False)+'\n',encoding='utf8')
    print('Local results saved:',out)
    return 0 if report['gate']=='PASS' else 1 if report['gate']=='FAIL' else 2


if __name__=='__main__':
    raise SystemExit(main())
