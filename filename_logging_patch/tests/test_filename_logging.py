from __future__ import annotations
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import pytest

BASE = Path(__file__).resolve().parents[1]
FIX = BASE / 'tests' / 'fixtures'
spec=importlib.util.spec_from_file_location('filename_upgrade', BASE/'scripts/install_filename_logging.py')
mod=importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

@pytest.fixture
def project(tmp_path):
    root=tmp_path/'project'
    for folder in ('app', 'app/api', 'app/core'):
        path=root/folder
        path.mkdir(parents=True, exist_ok=True)
        (path/'__init__.py').write_bytes(b'')
    (root/mod.AUDIT).write_bytes((FIX/'audit_logging_v1.py').read_bytes())
    (root/mod.HARDENED).write_bytes((FIX/'hardened_logging_v1.py').read_bytes())
    (root/'app/core/input_hardening.py').write_bytes((FIX/'input_hardening.py').read_bytes())
    (root/'app/api/release_status.py').write_bytes((FIX/'release_status.py').read_bytes())
    (root/'app/api/pipeline_validation.py').write_text('''\
from fastapi import HTTPException
async def analyze_pipeline_validation(*, file, platform):
    data = await file.read()
    if b'UPSTREAMFAIL' in data:
        raise HTTPException(status_code=422, detail='Upstream failed')
    return {'findings':[{'code':'FW-001'}], 'summary':{'total_findings':1}}
''', encoding='utf-8')
    (root/'app/api/main.py').write_text('''\
from fastapi import FastAPI
from app.core.audit_logging import AccessAuditMiddleware
from app.api.hardened_analysis import router as hardened_analysis_router
app=FastAPI()
app.add_middleware(AccessAuditMiddleware)
app.include_router(hardened_analysis_router)
''',encoding='utf-8')
    return root


def test_install_idempotent_and_rollback(project):
    orig={r: (project/r).read_bytes() for r in (mod.AUDIT,mod.HARDENED)}
    expected=['app/api/hardened_analysis.py','app/core/audit_logging.py']
    assert mod.install(project)==expected
    assert mod.install(project)==[]
    assert mod.rollback(project)==expected
    assert all((project/p).read_bytes()==raw for p,raw in orig.items())


def test_no_overwrite_later_edits(project):
    mod.install(project)
    p=project/mod.HARDENED
    p.write_bytes(p.read_bytes()+b'\n# updated after installation\n')
    with pytest.raises(ValueError,match='changed'):
        mod.rollback(project)
    assert (project/mod.MANIFEST).exists()


def test_preserve_crlf_utf8bom(project):
    for rel in (mod.AUDIT,mod.HARDENED):
        f=project/rel
        f.write_bytes(b'\xef\xbb\xbf'+f.read_bytes().replace(b'\r\n',b'\n').replace(b'\n',b'\r\n'))
    mod.install(project)
    for rel in (mod.AUDIT,mod.HARDENED):
        b=(project/rel).read_bytes()
        assert b.startswith(b'\xef\xbb\xbf')
        assert b.count(b'\n')==b.count(b'\r\n')
        assert b'\r\r\n' not in b
    mod.rollback(project)


def test_bad_utf8_fails_closed(project):
    f=project/mod.HARDENED; f.write_bytes(b'\x97')
    with pytest.raises(UnicodeError):mod.install(project)
    assert not (project/mod.MANIFEST).exists()


def test_unknown_layout_fails_closed(project):
    f=project/mod.HARDENED; f.write_text('unrecognized source', encoding='utf-8')
    before=(project/mod.AUDIT).read_bytes()
    with pytest.raises(ValueError,match='Existing logging patch'):
        mod.install(project)
    assert (project/mod.AUDIT).read_bytes()==before


def test_safe_filename_sanitizing(project):
    mod.install(project)
    spec2=importlib.util.spec_from_file_location('audit_test',project/mod.AUDIT)
    logger=importlib.util.module_from_spec(spec2);spec2.loader.exec_module(logger)
    cases={
      'site firewall.conf':'site firewall.conf',
      'ASA01.cfg':'ASA01.cfg',
      'subdir/ASA01.cfg':None,
      '..\\ASA01.cfg':None,
      '..':None,
      '../secret.cfg':None,
      'secret\r\nerror.log':None,
      'config;DROP.cfg':None,
      'ü.cfg':None,
      'a'*121+'.cfg':None,
    }
    for value, expected in cases.items():
        assert logger._safe_upload_filename(value)==expected
    assert logger._clean_fields({'filename':'ASA01.cfg'})['filename']=='ASA01.cfg'
    assert 'filename' not in logger._clean_fields({'filename':'../ASA01.cfg'})
    assert 'config' not in logger._clean_fields({'config':'TOP SECRET CONFIG'})


def test_request_logs_filename_without_contents(project):
    mod.install(project)
    script='''\
import json
from fastapi.testclient import TestClient
from app.api.main import app
from app.core.audit_logging import log_directory
with TestClient(app) as client:
    a=client.post('/api/v1/analyze/hardened?platform=cisco_asa',files={'file':('my-firewall.cfg',b'hostname PRIVATE_CONTENT', 'text/plain')})
    b=client.post('/api/v1/analyze/hardened?platform=snort',files={'file':('bad-encoding.cfg',b'\\x00\\x01','text/plain')})
    c=client.post('/api/v1/analyze/hardened?platform=snort',files={'file':('broken.rules',b'UPSTREAMFAIL', 'text/plain')})
assert a.status_code==200, (a.status_code,a.text)
assert b.status_code==422, (b.status_code,b.text)
assert c.status_code==422, (c.status_code,c.text)
files={p.name:p.read_text('utf-8') for p in log_directory().glob('*.log')}
up=[json.loads(x) for x in files['upload_audit.log'].splitlines()]
security=[json.loads(x) for x in files['security_analysis.log'].splitlines()]
assert any(x.get('filename')=='my-firewall.cfg' and x['event']=='upload_accepted' for x in up)
assert any(x.get('filename')=='bad-encoding.cfg' and x['event']=='upload_rejected' for x in up)
assert any(x.get('filename')=='my-firewall.cfg' and x['event']=='analysis_completed' for x in security)
assert any(x.get('filename')=='broken.rules' and x['event']=='analysis_failed' for x in security)
joined=''.join(files.values())
assert 'PRIVATE_CONTENT' not in joined
assert 'UPSTREAMFAIL' not in joined
assert 'platform=cisco_asa' not in joined
assert 'filename' not in files['api_access.log']
'''
    env=os.environ.copy();env['PYTHONPATH']=str(project)
    result=subprocess.run([sys.executable,'-c',script],cwd=project,env=env,capture_output=True,text=True)
    assert result.returncode==0,(result.stdout,result.stderr)


def test_no_new_code_outside_two_files(project):
    before={p.relative_to(project).as_posix() for p in project.rglob('*') if p.is_file()}
    mod.install(project)
    assert (project/'app/api/main.py').read_text('utf-8').find('AccessAuditMiddleware')!=-1
    assert (project/mod.AUDIT).exists() and (project/mod.HARDENED).exists()
    assert '.audit_filename_manifest.json' not in before
