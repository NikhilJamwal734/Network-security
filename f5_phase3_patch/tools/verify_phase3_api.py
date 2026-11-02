"""Local-only F5 Phase 3 smoke check: without and with operator metadata.

Requires running FastAPI on 127.0.0.1; does not modify files or devices.
Does not assert that operator evidence is independently verified.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from uuid import uuid4


def post(url: str, config: bytes, evidence_json: bytes | None) -> dict:
    boundary = '----FirewallAnalyzer-' + uuid4().hex
    b = boundary.encode('ascii')
    payload = bytearray()
    payload += b'--' + b + b'\r\n'
    payload += b'Content-Disposition: form-data; name="file"; filename="f5_phase2_sample.conf"\r\n'
    payload += b'Content-Type: text/plain\r\n\r\n' + config + b'\r\n'
    if evidence_json is not None:
        payload += b'--' + b + b'\r\n'
        payload += b'Content-Disposition: form-data; name="evidence_json"\r\n'
        payload += b'Content-Type: text/plain; charset=utf-8\r\n\r\n'
        payload += evidence_json + b'\r\n'
    payload += b'--' + b + b'--\r\n'
    req = Request(url, data=bytes(payload), headers={'Content-Type': 'multipart/form-data; boundary=' + boundary}, method='POST')
    with urlopen(req, timeout=15) as res:
        body = json.loads(res.read(2_000_000))
        if not isinstance(body, dict):
            raise ValueError('F5 API returned non-object JSON')
        return body


def find_code(items, code):
    return [x for x in items if isinstance(x,dict) and x.get('code') == code]


def verify(basic: dict, extra: dict) -> list[str]:
    issues: list[str] = []
    for name, result in (('without evidence', basic), ('with evidence', extra)):
        if result.get('platform', {}).get('platform_id') != 'f5_bigip':
            issues.append(name + ': unexpected platform')
        if result.get('summary', {}).get('total_findings') != len(result.get('findings', [])):
            issues.append(name + ': findings count mismatch')
        if result.get('summary', {}).get('total_review_observations') != len(result.get('review_observations', [])):
            issues.append(name + ': review observation count mismatch')
    baseline_codes = {f.get('code') for f in basic.get('findings', [])}
    if not {'F5-001', 'F5-003', 'F5-007'}.issubset(baseline_codes):
        issues.append('Baseline sample missing expected Phase 1 findings')
    for code in ('F5-005', 'F5-006'):
        items = find_code(basic.get('review_observations', []), code)
        if not items or items[0].get('confidence') != 'not_assessed':
            issues.append('Without evidence: ' + code + ' should be not_assessed')
    if not find_code(extra.get('findings', []), 'F5-005'):
        issues.append('With evidence: expected operator-reported unencrypted UCS F5-005')
    if not find_code(extra.get('review_observations', []), 'F5-006'):
        issues.append('With evidence: expected F5-006 update status review')
    if any(x.get('confidence') == 'not_assessed' for x in find_code(extra.get('review_observations', []),'F5-005')):
        issues.append('With evidence: stale F5-005 not_assessed marker')
    if not extra.get('f5_phase2_review',{}).get('operator_evidence_supplied'):
        issues.append('With evidence: missing operator evidence flag')
    return issues


def main() -> int:
    ap = argparse.ArgumentParser(description='F5 Phase 3: test existing F5 API with and without metadata')
    ap.add_argument('--api-url', default='http://127.0.0.1:8000', help='Local FastAPI origin (loopback only)')
    ap.add_argument('--root', default='.', help='Firewall Analyzer project root')
    args = ap.parse_args()
    base = urlparse(args.api_url)
    if base.scheme != 'http' or base.hostname not in ('127.0.0.1','localhost','::1') or base.username or base.password or base.path not in ('', '/') or base.query or base.fragment:
        print('ERROR: Only a bare HTTP loopback origin is accepted.',file=sys.stderr)
        return 2
    root=Path(args.root).resolve()
    sample=root/'f5_phase2_patch/examples/f5_phase2_sample.conf'
    evidence=root/'f5_phase3_patch/examples/f5_phase3_evidence.json'
    if not sample.is_file() or not evidence.is_file():
        print('ERROR: F5 Phase 2 sample or Phase 3 evidence JSON missing.',file=sys.stderr)
        return 2
    config=sample.read_bytes()
    metadata=evidence.read_bytes()
    url=args.api_url.rstrip('/') + '/api/v1/analyze/f5/phase1'
    try:
        basic=post(url,config,None)
        extra=post(url,config,metadata)
        issues=verify(basic,extra)
    except (HTTPError,URLError,ValueError,TimeoutError) as exc:
        print('FAIL: F5 API smoke test could not complete:',exc,file=sys.stderr)
        return 1
    if issues:
        for item in issues: print('FAIL:',item)
        return 1
    print('PASS: F5 Phase 2 endpoint handles configuration-only and optional JSON evidence uploads.')
    print('  Baseline findings:',basic['summary']['total_findings'])
    print('  With operator evidence findings:',extra['summary']['total_findings'])
    print('  F5-005: operator-asserted UCS encryption review; F5-006: operator-asserted signature update review')
    print('  Note: operator evidence is not independently verified.')
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
