"""Read-only Windows desktop acceptance for an existing FirewallAnalyzer.exe.

This program launches ONE child copy of the selected EXE, sends synthetic
configurations to its dynamically allocated loopback port, inspects log
metadata and local log activity, and attempts a graceful CTRL_BREAK shutdown.
It never changes source code, security configuration, or the executable.
It saves only PASS/FAIL metadata, not raw device data, log records, HTTP
responses, tokens, or configuration contents.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import queue
import re
import signal
import subprocess
import sys
import threading
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import ProxyHandler, Request, build_opener
from uuid import uuid4

VENDORS = ('cisco_asa', 'fortios', 'snort', 'suricata')
URL_RE = re.compile(r'Open in browser:\s*(http://127\.0\.0\.1:(\d+)/)')
MAX_SAMPLE_BYTES = 2 * 1024 * 1024
MAX_REPLY_BYTES = 2 * 1024 * 1024
MAX_HTML_BYTES = 2 * 1024 * 1024
LOG_STREAMS = ('application', 'api_access', 'upload_audit', 'security_analysis', 'error')


def entry(name: str, status: str, detail: str) -> dict:
    assert status in ('PASS', 'FAIL', 'INCOMPLETE')
    return {'name': name, 'status': status, 'detail': detail}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as fp:
        for block in iter(lambda: fp.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def integrity_check(exe: Path, receipt: Path) -> dict:
    if exe.is_symlink() or not exe.is_file() or exe.stat().st_size < 100_000:
        return entry('EXE integrity', 'FAIL', 'Missing, symlinked, or implausibly small EXE')
    if receipt.is_symlink() or not receipt.is_file():
        return entry('EXE integrity', 'INCOMPLETE', 'Build receipt missing: release_final_build_result.json')
    try:
        data = json.loads(receipt.read_text(encoding='utf-8-sig'))
        recorded = data.get('exe_sha256')
        actual = sha256_file(exe)
        if not isinstance(recorded, str) or not re.fullmatch('[a-fA-F0-9]{64}', recorded):
            return entry('EXE integrity', 'FAIL', 'Build receipt missing valid SHA-256')
        if recorded.lower() != actual:
            return entry('EXE integrity', 'FAIL', 'EXE SHA-256 differs from build receipt')
        if data.get('local_exe_smoke') != 'PASS':
            return entry('EXE integrity', 'FAIL', 'Build receipt does not confirm successful EXE smoke')
        return entry('EXE integrity', 'PASS', 'SHA-256 matches build receipt; previous EXE smoke marked PASS')
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return entry('EXE integrity', 'FAIL', 'Unable to parse or hash EXE/receipt')


def safe_sample(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file() or not (0 < path.stat().st_size <= MAX_SAMPLE_BYTES):
        raise ValueError('Missing, symlinked or oversized synthetic test configuration')
    return path.read_bytes()


def multipart(filename: str, content: bytes, evidence: bytes | None = None) -> tuple[bytes, str]:
    if not re.fullmatch(r'[a-zA-Z0-9_.-]{1,100}', filename):
        raise ValueError('Unsafe fixture filename')
    boundary = '---FADesktopAcceptance-' + uuid4().hex
    b = boundary.encode('ascii')
    data = bytearray()
    data.extend(b'--' + b + b'\r\nContent-Disposition: form-data; name="file"; filename="' + filename.encode('ascii') + b'"\r\nContent-Type: application/octet-stream\r\n\r\n')
    data.extend(content + b'\r\n')
    if evidence is not None:
        data.extend(b'--' + b + b'\r\nContent-Disposition: form-data; name="evidence_json"\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n')
        data.extend(evidence + b'\r\n')
    data.extend(b'--' + b + b'--\r\n')
    return bytes(data), 'multipart/form-data; boundary=' + boundary


def fetch(base: str, path: str, *, content: bytes | None = None, filename: str = 'sample.conf',
          evidence: bytes | None = None, platform: str | None = None,
          max_bytes: int = MAX_REPLY_BYTES, timeout: int = 35) -> tuple[int, bytes, str]:
    # The origin is discovered from the child process output, never user-provided remote URL.
    if not re.fullmatch(r'http://127\.0\.0\.1:\d+/', base):
        raise ValueError('Non-loopback or malformed EXE origin')
    url = base.rstrip('/') + path
    if platform is not None:
        if platform not in VENDORS:
            raise ValueError('Unexpected platform')
        url += '?' + urlencode({'platform': platform})
    headers = {'Accept': 'application/json'}
    if content is None:
        req = Request(url, headers=headers, method='GET')
    else:
        data, mime = multipart(filename, content, evidence)
        headers['Content-Type'] = mime
        req = Request(url, data=data, headers=headers, method='POST')
    opener = build_opener(ProxyHandler({}))
    try:
        with opener.open(req, timeout=timeout) as resp:
            status, body, typ = resp.status, resp.read(max_bytes + 1), resp.headers.get('Content-Type', '')
    except HTTPError as exc:
        status, body, typ = exc.code, exc.read(max_bytes + 1), exc.headers.get('Content-Type', '')
    if len(body) > max_bytes:
        raise ValueError('Oversized HTTP response')
    return status, body, typ


def read_json(body: bytes) -> dict:
    result = json.loads(body.decode('utf-8'))
    if not isinstance(result, dict):
        raise ValueError('JSON response is not an object')
    return result


def is_consistent(data: dict, vendor: str) -> bool:
    plat = data.get('platform')
    summary = data.get('summary')
    findings = data.get('findings')
    input_check = data.get('input_security_review')
    return (isinstance(plat, dict) and plat.get('platform_id') == vendor
            and isinstance(summary, dict) and isinstance(findings, list)
            and summary.get('total_findings') == len(findings)
            and isinstance(input_check, dict) and input_check.get('status') == 'accepted')


def check_vendor(base: str, vendor: str, fixture: Path) -> dict:
    try:
        content = safe_sample(fixture)
        suffix = fixture.suffix.lower()
        if suffix not in ('.conf', '.cfg', '.txt', '.rules', '.yaml', '.yml'):
            return entry(vendor + ' EXE upload', 'FAIL', 'Unsupported fixture extension')
        status, raw, _ = fetch(base, '/api/v1/analyze/hardened', content=content,
                               filename='synthetic' + suffix, platform=vendor)
        if status != 200:
            return entry(vendor + ' EXE upload', 'FAIL', 'HTTP ' + str(status) + ' from packaged API')
        data = read_json(raw)
        if not is_consistent(data, vendor):
            return entry(vendor + ' EXE upload', 'FAIL', 'Normalized report or input-validation contract mismatch')
        return entry(vendor + ' EXE upload', 'PASS',
                     'HTTP 200; vendor=' + vendor + '; findings=' + str(data['summary']['total_findings']) + '; validated upload')
    except (OSError, ValueError, TimeoutError, URLError, UnicodeError, json.JSONDecodeError) as exc:
        return entry(vendor + ' EXE upload', 'FAIL', 'Error: ' + type(exc).__name__)


def check_f5(base: str, config_path: Path, evidence_path: Path) -> dict:
    try:
        conf, evidence = safe_sample(config_path), safe_sample(evidence_path)
        s0, r0, _ = fetch(base, '/api/v1/analyze/f5/phase1', content=conf, filename='test.conf')
        s1, r1, _ = fetch(base, '/api/v1/analyze/f5/phase1', content=conf, filename='test.conf', evidence=evidence)
        if (s0, s1) != (200, 200):
            return entry('F5 packaged upload regression', 'FAIL', f'HTTP {s0}/{s1}')
        a, b = read_json(r0), read_json(r1)
        if not is_consistent(a, 'f5_bigip') or not is_consistent(b, 'f5_bigip'):
            return entry('F5 packaged upload regression', 'FAIL', 'Normalized result mismatch')
        if (a['summary'].get('total_findings'), a['summary'].get('total_review_observations'),
            b['summary'].get('total_findings'), b['summary'].get('total_review_observations')) != (3, 5, 4, 4):
            return entry('F5 packaged upload regression', 'FAIL', 'Expected baseline 3/5 and evidence 4/4 counts')
        f5 = next((f for f in b['findings'] if f.get('code') == 'F5-005'), {})
        review = next((o for o in b.get('review_observations', []) if o.get('code') == 'F5-006'), {})
        if f5.get('confidence') != 'operator_supplied_unverified' or review.get('confidence') != 'operator_supplied_unverified':
            return entry('F5 packaged upload regression', 'FAIL', 'F5 JSON evidence confidence mismatch')
        if a['input_security_review'].get('sha256') != hashlib.sha256(conf).hexdigest():
            return entry('F5 packaged upload regression', 'FAIL', 'F5 input SHA-256 mismatch')
        return entry('F5 packaged upload regression', 'PASS', '3/5 without JSON, 4/4 with JSON; evidence confidence and config SHA-256 verified')
    except (OSError, ValueError, TimeoutError, URLError, UnicodeError, KeyError, TypeError, json.JSONDecodeError) as exc:
        return entry('F5 packaged upload regression', 'FAIL', 'Error: ' + type(exc).__name__)


def check_dashboard(base: str) -> dict:
    try:
        status, raw, ctype = fetch(base, '/', max_bytes=MAX_HTML_BYTES)
        if status != 200 or 'html' not in ctype.lower() or b'<html' not in raw.lower():
            return entry('Packaged dashboard', 'FAIL', 'Root is not an HTTP 200 HTML document')
        # Does not attempt to claim that React rendered successfully in a browser.
        return entry('Packaged dashboard', 'PASS', 'HTML delivered by dynamically bound packaged server; browser rendering requires manual check')
    except (OSError, ValueError, TimeoutError, URLError) as exc:
        return entry('Packaged dashboard', 'FAIL', 'Error: ' + type(exc).__name__)


def check_health(base: str) -> dict:
    try:
        status, raw, _ = fetch(base, '/api/health', max_bytes=65536)
        if status == 200 and read_json(raw).get('status') == 'ok':
            return entry('Packaged health API', 'PASS', 'HTTP 200; status=ok')
        return entry('Packaged health API', 'FAIL', 'Unexpected HTTP status or JSON response')
    except (OSError, ValueError, TimeoutError, URLError, UnicodeError, json.JSONDecodeError) as exc:
        return entry('Packaged health API', 'FAIL', 'Error: ' + type(exc).__name__)


def check_log_page_api(base: str) -> list[dict]:
    out: list[dict] = []
    try:
        status, raw, content_type = fetch(base, '/logs.html', max_bytes=MAX_HTML_BYTES)
        if status != 200 or 'html' not in content_type.lower() or b'<html' not in raw.lower():
            out.append(entry('JSON Logs HTML', 'FAIL', 'Missing or invalid logs.html'))
        else:
            out.append(entry('JSON Logs HTML', 'PASS', 'Packaged HTML served; visual colors and rendering require manual review'))
    except (OSError, ValueError, TimeoutError, URLError) as exc:
        out.append(entry('JSON Logs HTML', 'FAIL', 'Error: ' + type(exc).__name__))
    try:
        status, raw, _ = fetch(base, '/api/v1/logs?stream=application&limit=1', max_bytes=262144)
        data = read_json(raw)
        if status != 200 or data.get('stream') != 'application' or not isinstance(data.get('entries'), list):
            out.append(entry('JSON Logs API', 'FAIL', 'Logs API contract mismatch'))
        else:
            out.append(entry('JSON Logs API', 'PASS', 'HTTP 200; application stream and entries array; content not retained'))
    except (OSError, ValueError, TimeoutError, URLError, UnicodeError, json.JSONDecodeError) as exc:
        out.append(entry('JSON Logs API', 'FAIL', 'Error: ' + type(exc).__name__))
    return out


def log_snapshot(path: Path) -> tuple[int, int] | None:
    if path.is_symlink() or not path.is_file():
        return None
    stat = path.stat()
    return stat.st_size, stat.st_mtime_ns


def check_disk_logs(logdir: Path, before: tuple[int, int] | None) -> dict:
    file = logdir / 'api_access.log'
    try:
        if logdir.is_symlink() or file.is_symlink() or not file.is_file():
            return entry('JSON audit log file activity', 'FAIL', 'No regular api_access.log in LocalAppData')
        stat = file.stat()
        if not stat.st_size:
            return entry('JSON audit log file activity', 'FAIL', 'api_access.log is empty')
        changed = before is None or (stat.st_size, stat.st_mtime_ns) != before
        if not changed:
            return entry('JSON audit log file activity', 'FAIL', 'No log activity after packaged API requests')
        with file.open('rb') as fp:
            fp.seek(max(0, stat.st_size - 160_000))
            tail = fp.read(160_000)
        lines = tail.splitlines()
        if stat.st_size > 160_000 and lines:
            lines = lines[1:]
        # Only inspect records in memory; never retain log content in the acceptance report.
        good = 0
        for line in lines:
            try:
                obj = json.loads(line)
                if (isinstance(obj, dict) and obj.get('event') == 'http_request'
                        and isinstance(obj.get('timestamp_utc'), str)
                        and isinstance(obj.get('status_code'), int)):
                    good += 1
            except (UnicodeError, json.JSONDecodeError):
                continue
        if good < 1:
            return entry('JSON audit log file activity', 'FAIL', 'No valid JSON HTTP request event in recent log tail')
        return entry('JSON audit log file activity', 'PASS', 'LocalAppData log changed; valid JSON request events present; no records stored in report')
    except (OSError, ValueError) as exc:
        return entry('JSON audit log file activity', 'FAIL', 'Error: ' + type(exc).__name__)


def collect_output(stream, messages: queue.Queue[str]) -> None:
    for line in iter(stream.readline, ''):
        messages.put(line.rstrip('\r\n'))


def announce(proc: subprocess.Popen, messages: queue.Queue[str], timeout: int) -> str | None:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            line = messages.get(timeout=0.35)
            match = URL_RE.search(line)
            if match:
                return match.group(1)
        except queue.Empty:
            if proc.poll() is not None:
                return None
    return None


def await_readiness(base: str, timeout: int) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            status, _, _ = fetch(base, '/', timeout=3)
            if status == 200:
                return True
        except (OSError, ValueError, TimeoutError, URLError):
            pass
        time.sleep(0.4)
    return False


def endpoint_stopped(base: str) -> bool:
    try:
        fetch(base, '/api/health', timeout=2)
        return False
    except (OSError, URLError, TimeoutError):
        return True


def request_graceful_shutdown(proc: subprocess.Popen, base: str) -> dict:
    if sys.platform != 'win32' or not hasattr(signal, 'CTRL_BREAK_EVENT'):
        return entry('Clean EXE shutdown', 'INCOMPLETE', 'Windows CTRL_BREAK_EVENT unavailable')
    try:
        os.kill(proc.pid, signal.CTRL_BREAK_EVENT)
    except (OSError, ValueError, PermissionError):
        return entry('Clean EXE shutdown', 'INCOMPLETE', 'Cannot send graceful console break; manual Ctrl+C verification required')
    try:
        rc = proc.wait(timeout=20)
    except subprocess.TimeoutExpired:
        return entry('Clean EXE shutdown', 'FAIL', 'EXE did not stop after graceful signal')
    if not endpoint_stopped(base):
        return entry('Clean EXE shutdown', 'FAIL', 'Loopback backend remains reachable after EXE exit')
    if rc != 0:
        return entry('Clean EXE shutdown', 'INCOMPLETE', f'EXE stopped after break, but exit code={rc}; manual Ctrl+C required')
    return entry('Clean EXE shutdown', 'PASS', 'EXE exited with code 0 after console break; loopback API no longer responds')


def stop_child(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=8)
    except subprocess.TimeoutExpired:
        if sys.platform == 'win32':
            subprocess.run(['taskkill', '/PID', str(proc.pid), '/T', '/F'],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        else:
            proc.kill()
        try:
            proc.wait(timeout=4)
        except subprocess.TimeoutExpired:
            pass


def safe_write_result(path: Path, payload: dict) -> None:
    if path.is_symlink():
        raise ValueError('Refusing to overwrite symlinked acceptance result')
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(payload, indent=2, sort_keys=True) + '\n'
    tmp = path.with_name(path.name + '.tmp')
    if tmp.is_symlink():
        raise ValueError('Refusing symlinked temporary result')
    tmp.write_text(text, encoding='utf-8')
    tmp.replace(path)


def run(args: argparse.Namespace) -> tuple[dict, int]:
    root = args.root.resolve()
    exe = (args.exe if args.exe.is_absolute() else root / args.exe).absolute()
    receipt = (args.receipt if args.receipt.is_absolute() else root / args.receipt).absolute()
    report = (args.out if args.out.is_absolute() else root / args.out).absolute()
    records: list[dict] = []
    integrity = integrity_check(exe, receipt)
    records.append(integrity)
    origin = None
    proc = None
    if integrity['status'] != 'PASS':
        records.append(entry('Windows EXE execution', 'INCOMPLETE', 'Not launched: EXE hash verification must pass first'))
    elif sys.platform != 'win32':
        records.append(entry('Windows EXE execution', 'INCOMPLETE', 'Must run on Windows'))
    elif not exe.is_file() or exe.is_symlink():
        records.append(entry('Windows EXE execution', 'FAIL', 'Selected executable missing or symlinked'))
    else:
        log_base = Path(os.environ.get('LOCALAPPDATA') or (Path.home() / 'AppData' / 'Local'))
        logfile = log_base / 'FirewallAnalyzer' / 'logs' / 'api_access.log'
        initial = log_snapshot(logfile)
        try:
            creationflags = getattr(subprocess, 'CREATE_NEW_PROCESS_GROUP', 0)
            proc = subprocess.Popen([str(exe), '--no-browser'], cwd=str(exe.parent),
                                    creationflags=creationflags, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                                    bufsize=1, text=True, encoding='utf-8', errors='replace')
            if proc.stdout is None:
                raise RuntimeError('Failed to capture EXE output')
            messages: queue.Queue[str] = queue.Queue()
            threading.Thread(target=collect_output, args=(proc.stdout, messages), daemon=True).start()
            origin = announce(proc, messages, args.startup_timeout)
            if origin is None or not await_readiness(origin, 20):
                records.append(entry('Windows EXE execution', 'FAIL', 'EXE did not announce a ready loopback server'))
            else:
                print('EXE loopback server announced:', origin, flush=True)
                records.append(entry('Windows EXE execution', 'PASS', 'Independent EXE started and announced dynamic loopback URL'))
                records.append(check_dashboard(origin))
                records.append(check_health(origin))
                records.extend(check_log_page_api(origin))
                records.append(check_f5(origin,
                    root / 'f5_phase2_patch/examples/f5_phase2_sample.conf',
                    root / 'f5_phase3_patch/examples/f5_phase3_evidence.json'))
                for vendor in VENDORS:
                    fixture = root / 'release_final' / 'examples' / (vendor + ('.yaml' if vendor == 'suricata' else '.conf'))
                    result = check_vendor(origin, vendor, fixture)
                    records.append(result)
                records.append(check_disk_logs(logfile.parent, initial))
                records.append(request_graceful_shutdown(proc, origin))
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
            records.append(entry('Windows EXE execution', 'FAIL', 'Runner error: ' + type(exc).__name__))
        finally:
            if proc is not None:
                stop_child(proc)
                if origin is not None and not endpoint_stopped(origin):
                    records.append(entry('Backend after cleanup', 'FAIL', 'Packaged API remained reachable after child cleanup'))
    failed = sum(r['status'] == 'FAIL' for r in records)
    incomplete = sum(r['status'] == 'INCOMPLETE' for r in records)
    automated = 'FAIL' if failed else 'INCOMPLETE' if incomplete else 'PASS'
    result = {
        'suite': 'FirewallAnalyzer-packaged-Windows-EXE-acceptance',
        'created_at_utc': datetime.now(timezone.utc).isoformat(),
        'exe_name': exe.name,
        'automated_status': automated,
        'manual_ui_acceptance': 'PENDING',
        'production_security_certified': False,
        'checks': records,
        'counts': {'passed': sum(x['status']=='PASS' for x in records),
                   'failed': failed, 'incomplete': incomplete},
        'caveats': [
            'Synthetic sample tests do not establish real-device configuration security.',
            'HTTP 200 for a React page does not establish browser-side rendering or color accessibility.',
            'Manual PDF export, browser UI, log viewer colors, and clean-machine testing remain required.',
            'Earlier historical patch tests still include unresolved fixture/portability failures.'
        ]
    }
    safe_write_result(report, result)
    for record in records:
        print('[' + record['status'] + '] ' + record['name'] + ': ' + record['detail'], flush=True)
    print('AUTOMATED PACKAGED ACCEPTANCE:', automated)
    print('Manual UI acceptance: PENDING')
    print('Result saved:', report)
    return result, 1 if failed else 2 if incomplete else 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path.cwd())
    parser.add_argument('--exe', type=Path, default=Path('desktop_release_single/FirewallAnalyzer.exe'))
    parser.add_argument('--receipt', type=Path, default=Path('release_final_build_result.json'))
    parser.add_argument('--out', type=Path, default=Path('release_exe_acceptance_result.json'))
    parser.add_argument('--startup-timeout', type=int, default=120)
    args = parser.parse_args(argv)
    if args.startup_timeout < 10 or args.startup_timeout > 300:
        parser.error('--startup-timeout must be 10 to 300 seconds')
    _, code = run(args)
    return code


if __name__ == '__main__':
    raise SystemExit(main())
