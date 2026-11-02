"""Local-only smoke check for a running API-011.6 endpoint.

Requires installed httpx for multipart upload. Never sends bytes outside a
loopback-host API; does not display uploaded content.
"""
from __future__ import annotations
import argparse
from pathlib import Path
from urllib.parse import urlsplit


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--file', required=True, type=Path, help='Existing configuration file')
    ap.add_argument('--platform', choices=('cisco_asa','fortios','snort','suricata'))
    ap.add_argument('--url', default='http://127.0.0.1:8000')
    args = ap.parse_args(argv)
    u=urlsplit(args.url)
    if u.scheme != 'http' or u.hostname not in ('localhost','127.0.0.1') or u.username or u.password or u.path not in ('','/') or u.query or u.fragment:
        ap.error('Only loopback HTTP base URLs without path, query, or credentials are accepted')
    if not args.file.is_file():
        ap.error('Input file not found')
    if args.file.stat().st_size > 8*1024*1024:
        ap.error('Input exceeds API-011.6 8 MiB limit')
    try:
        import httpx
    except ImportError:
        ap.error('Install httpx into the same Python environment to run the smoke test')
    try:
        with args.file.open('rb') as inp:
            with httpx.Client(timeout=60.0,follow_redirects=False,trust_env=False) as client:
                res=client.post(args.url.rstrip('/') + '/api/v1/analyze/hardened',
                                params={'platform':args.platform} if args.platform else None,
                                files={'file':(args.file.name,inp,'application/octet-stream')})
        if res.status_code != 200:
            print(f'HTTP {res.status_code}: upload not accepted / upstream analysis failed')
            return 1
        payload=res.json()
        review=payload.get('input_security_review')
        if not isinstance(review,dict) or review.get('status') != 'accepted' or not isinstance(payload.get('findings'),list):
            print('Unexpected API-011.6 response contract')
            return 1
        summary=review.get('summary',{})
        print('API-011.6 loopback smoke check passed')
        print('Accepted input bytes:',summary.get('byte_count'))
        print('Validated lines:',summary.get('line_count'))
        print('Findings returned:',len(payload['findings']))
        print('PDF generation/download still require separate browser verification.')
        return 0
    except (OSError,ValueError,httpx.HTTPError) as exc:
        print(f'Unable to complete localhost smoke test: {type(exc).__name__}')
        return 1


if __name__=='__main__':
    raise SystemExit(main())
