"""Smoke-test an actual API-011.4 upload against a LOCAL running FastAPI server.

Uses stdlib only. Does not verify frontend PDF bytes or visual rendering.
Example:
 python api0114_patch/scripts/smoke_test_api_011_4.py --file configs/firewall.conf
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import secrets
import sys
import urllib.error
import urllib.parse
import urllib.request

EXPECTED_KEYS = (
    'platform', 'findings', 'consolidation_review', 'correlation_accuracy_review',
    'report_validation_review', 'pdf_export_review', 'pipeline_validation_review',
)


def check_report(data: dict) -> dict:
    if not isinstance(data, dict):
        raise ValueError('Response must be an object')
    missing = [key for key in EXPECTED_KEYS if key not in data]
    if missing:
        raise ValueError('Missing chained report sections: ' + ', '.join(missing))
    platform = data['platform']
    if not isinstance(platform,dict) or platform.get('platform_id') not in ('cisco_asa','fortios','snort','suricata'):
        raise ValueError('Unsupported normalized platform identifier')
    if not isinstance(data['findings'], list):
        raise ValueError('Normalized findings array is unavailable')
    stage=data['pipeline_validation_review']
    if not isinstance(stage,dict) or stage.get('platform_id')!=platform['platform_id']:
        raise ValueError('Invalid pipeline validation identity')
    stats=stage.get('summary')
    if not isinstance(stats,dict) or any(type(stats.get(k)) is not int for k in ('checks','passed','warnings','blockers','manual_required')):
        raise ValueError('Malformed stage counters')
    if sum(stats[k] for k in ('passed','warnings','blockers','manual_required')) != stats['checks']:
        raise ValueError('Pipeline stage counters do not reconcile')
    if not isinstance(stage.get('stages'),list) or len(stage['stages'])!=stats['checks']:
        raise ValueError('Pipeline stage entries do not reconcile')
    return {
        'platform_id': platform['platform_id'], 'findings':len(data['findings']),
        'pipeline_status':stage.get('status'), 'pipeline_summary':stats,
        'pdf_export_preflight':data['pdf_export_review'].get('status') if isinstance(data['pdf_export_review'],dict) else 'invalid',
        'manual_pdf_verification_required':True,
    }


def upload(base_url:str, filename:Path, platform:str|None, timeout:int=60)->dict:
    url=base_url.rstrip('/')+'/api/v1/analyze/pipeline-validation'
    parsed=urllib.parse.urlparse(url)
    if parsed.scheme!='http' or parsed.hostname not in ('localhost','127.0.0.1','::1'):
        raise ValueError('Smoke test allows only localhost HTTP to avoid accidental file disclosure')
    if platform: url+='?'+urllib.parse.urlencode({'platform':platform})
    if not filename.is_file():raise ValueError(f'File not found: {filename}')
    if filename.stat().st_size>8_000_000:raise ValueError('Smoke test refuses input larger than 8 MB')
    boundary='----api0114'+secrets.token_hex(8)
    raw=filename.read_bytes()
    body=(f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="sample.conf"\r\n'
          f'Content-Type: application/octet-stream\r\n\r\n').encode('ascii')+raw+(f'\r\n--{boundary}--\r\n').encode('ascii')
    req=urllib.request.Request(url,data=body,method='POST',headers={'Content-Type':f'multipart/form-data; boundary={boundary}', 'Accept':'application/json'})
    try:
        with urllib.request.urlopen(req,timeout=timeout) as result:
            if result.status!=200:raise ValueError(f'Unexpected status: {result.status}')
            if 'json' not in result.headers.get('Content-Type',''):
                raise ValueError('Response is not JSON')
            content=result.read(10_000_001)
            if len(content)>10_000_000:raise ValueError('Response exceeds 10 MB smoke-test limit')
            return json.loads(content)
    except urllib.error.HTTPError as exc:
        raise ValueError(f'API returned HTTP {exc.code}; inspect backend logs for the failing stage') from exc
    except urllib.error.URLError as exc:
        raise ValueError(f'Cannot connect to local backend: {exc.reason}') from exc


def main():
    parser=argparse.ArgumentParser(description='Local upload-to-normalized-report smoke test (PDF download requires browser)')
    parser.add_argument('--file',required=True,type=Path)
    parser.add_argument('--url',default='http://127.0.0.1:8000')
    parser.add_argument('--platform',choices=['cisco_asa','fortios','snort','suricata'])
    args=parser.parse_args()
    try:
        summary=check_report(upload(args.url,args.file,args.platform))
    except (OSError,ValueError,json.JSONDecodeError) as exc:
        sys.exit(f'FAILED: {exc}')
    print(json.dumps(summary,indent=2))
    if summary['pipeline_summary']['blockers']:
        sys.exit('INCOMPLETE: integration contract has blockers (see PDF detail).')
    print('HTTP/upload/report chain verified. Browser PDF export has NOT been verified.')


if __name__=='__main__':main()
