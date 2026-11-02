"""Validate a representative upload using ONLY a loopback server.

This script does not read or print configuration contents. It verifies that
API-011.6 input acceptance and the unchanged normalized findings are returned.
"""
from __future__ import annotations
import argparse
from pathlib import Path
import sys
from urllib.parse import urlsplit


def loopback_url(url: str) -> str:
    u=urlsplit(url)
    if u.scheme!='http' or u.hostname not in ('localhost','127.0.0.1') or u.username or u.password or u.path not in ('','/') or u.query or u.fragment:
        raise ValueError('Only loopback HTTP base URLs without credentials or paths are accepted')
    return url.rstrip('/')


def smoke(path: Path, platform: str | None, url: str) -> tuple[bool,str]:
    base=loopback_url(url)
    if not path.is_file() or path.is_symlink():
        return False,'Configuration sample missing or not a regular file'
    if path.stat().st_size > 8*1024*1024:
        return False,'Configuration exceeds hardened upload size limit'
    try:
        import httpx
    except ImportError:
        return False,'httpx is not installed in the selected Python environment'
    try:
        with path.open('rb') as stream, httpx.Client(timeout=60,follow_redirects=False,trust_env=False) as client:
            resp=client.post(base+'/api/v1/analyze/hardened',
                       params={'platform':platform} if platform else None,
                       files={'file':(path.name,stream,'application/octet-stream')})
        if resp.status_code!=200:
            return False,f'Upload was rejected or upstream analysis failed: HTTP {resp.status_code}'
        payload=resp.json()
        if (not isinstance(payload,dict) or
            not isinstance(payload.get('findings'),list) or
            not isinstance(payload.get('input_security_review'),dict) or
            payload['input_security_review'].get('status')!='accepted'):
            return False,'Unexpected API-011.6 response contract'
        return True,'Hardened upload accepted and normalized findings returned'
    except (OSError,ValueError,httpx.HTTPError):
        return False,'Unable to complete the local upload smoke test'


def main(argv=None) -> int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--file',required=True,type=Path)
    p.add_argument('--platform',choices=('cisco_asa','fortios','snort','suricata'))
    p.add_argument('--url',default='http://127.0.0.1:8000')
    args=p.parse_args(argv)
    try:
        ok,message=smoke(args.file,args.platform,args.url)
    except ValueError as exc:
        p.error(str(exc))
    print(message)
    print('A successful upload does not verify browser PDF download or production security.')
    return 0 if ok else 1

if __name__=='__main__':
    raise SystemExit(main())
