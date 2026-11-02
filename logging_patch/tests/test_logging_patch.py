from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

THIS = Path(__file__).resolve().parents[1]
SCRIPT = THIS / 'scripts' / 'install_logging.py'
spec = importlib.util.spec_from_file_location('logging_patch_installer', SCRIPT)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
FIXTURES = THIS / 'tests' / 'fixtures'


@pytest.fixture
def project(tmp_path):
    root = tmp_path / 'project'
    for folder in ('app', 'app/api', 'app/core'):
        (root / folder).mkdir(parents=True, exist_ok=True)
        (root / folder / '__init__.py').write_text('', encoding='utf-8')
    for rel in ('app/api/hardened_analysis.py', 'app/core/input_hardening.py', 'app/api/release_status.py'):
        (root / rel).write_bytes((FIXTURES / Path(rel).name).read_bytes())
    (root / 'app/api/pipeline_validation.py').write_text('''\
from fastapi import HTTPException
async def analyze_pipeline_validation(*, file, platform):
    data = await file.read()
    if b'UPSTREAMFAIL' in data:
        raise HTTPException(status_code=422, detail='Upstream failed')
    return {'findings': [{'code':'FW-001'}], 'summary': {'total_findings': 1}}
''', encoding='utf-8')
    (root / 'app/api/main.py').write_text('''\
from fastapi import FastAPI
app = FastAPI()
from app.api.hardened_analysis import router as hardened_analysis_router
from app.api.release_status import router as release_status_router
app.include_router(hardened_analysis_router)
app.include_router(release_status_router)
''', encoding='utf-8')
    return root


def test_install_idempotence_and_rollback(project):
    src = (project / mod.MAIN).read_bytes()
    hard = (project / mod.HARDENED).read_bytes()
    changed = mod.install(project)
    assert changed == ['app/api/hardened_analysis.py', 'app/api/main.py', 'app/core/audit_logging.py']
    assert mod.install(project) == []
    newmain = (project / mod.MAIN).read_text('utf-8')
    assert newmain.count(mod.MAIN_REGISTER.strip()) == 1
    assert mod.rollback(project) == changed
    assert (project / mod.MAIN).read_bytes() == src
    assert (project / mod.HARDENED).read_bytes() == hard
    assert not (project / mod.MODULE).exists()


def test_rollback_refuses_later_edits(project):
    mod.install(project)
    file = project / mod.MAIN
    file.write_bytes(file.read_bytes() + b'\n# later user edit\n')
    with pytest.raises(ValueError, match='edited'):
        mod.rollback(project)
    assert (project / mod.MANIFEST).exists()


def test_bom_crlf_supported(project):
    for rel in (mod.MAIN, mod.HARDENED):
        f = project / rel
        # Normalize either LF or CRLF first; Windows write_text may already use CRLF.
        normalized = f.read_bytes().replace(b'\r\n', b'\n')
        assert b'\r' not in normalized
        f.write_bytes(b'\xef\xbb\xbf' + normalized.replace(b'\n', b'\r\n'))
        assert b'\r\r\n' not in f.read_bytes()
    mod.install(project)
    for rel in (mod.MAIN, mod.HARDENED):
        raw = (project / rel).read_bytes()
        assert raw.startswith(b'\xef\xbb\xbf')
        assert raw.count(b'\r\n') == raw.count(b'\n')
    mod.rollback(project)


def test_bad_layout_fails_before_writing(project):
    p = project / mod.HARDENED
    p.write_text('changed layout', encoding='utf-8')
    before = (project / mod.MAIN).read_bytes()
    with pytest.raises(ValueError, match='Unrecognized'):
        mod.install(project)
    assert (project / mod.MAIN).read_bytes() == before
    assert not (project / mod.MODULE).exists()


def test_bad_utf8_fails_closed(project):
    (project / mod.MAIN).write_bytes(b'\x97')
    with pytest.raises(UnicodeDecodeError):
        mod.install(project)
    assert not (project / mod.MODULE).exists()


def test_log_api_workflow_and_privacy(project):
    mod.install(project)
    script = '''\
import json
from pathlib import Path
from fastapi.testclient import TestClient
from app.api.main import app
from app.core.audit_logging import log_directory
with TestClient(app) as client:
    ok = client.post('/api/v1/analyze/hardened?platform=cisco_asa', files={'file':('private-SECRET.conf',b'hostname SAFE\\naccess-list x', 'text/plain')})
    bad = client.post('/api/v1/analyze/hardened', files={'file':('another-SECRET.conf',b'\\x00\\x01', 'text/plain')})
    other = client.get('/api/v1/release/status?token=SECRET')
assert ok.status_code == 200, (ok.status_code, ok.text)
assert bad.status_code == 422, (bad.status_code, bad.text)
assert other.status_code == 200
logs = {p.name:p.read_text('utf-8') for p in log_directory().glob('*.log')}
assert 'upload_accepted' in logs['upload_audit.log']
assert 'upload_rejected' in logs['upload_audit.log']
assert 'analysis_started' in logs['security_analysis.log']
assert 'analysis_completed' in logs['security_analysis.log']
assert 'http_request' in logs['api_access.log']
assert 'logging_initialized' in logs['application.log']
joined=''.join(logs.values())
for secret in ['private-SECRET.conf', 'another-SECRET.conf', 'hostname SAFE', 'token=SECRET', '127.0.0.1']:
    assert secret not in joined, secret
print(json.dumps({k:len(v.splitlines()) for k,v in logs.items()}))
'''
    env = os.environ.copy()
    env['PYTHONPATH'] = str(project)
    p = subprocess.run([sys.executable, '-c', script], env=env, cwd=project, text=True, capture_output=True)
    assert p.returncode == 0, (p.stdout, p.stderr)
    counts = json.loads(p.stdout.strip())
    assert counts['api_access.log'] >= 3


def test_failed_upstream_is_recorded(project):
    mod.install(project)
    script = '''\
from fastapi.testclient import TestClient
from app.api.main import app
from app.core.audit_logging import log_directory
with TestClient(app) as client:
    r = client.post('/api/v1/analyze/hardened?platform=snort', files={'file':('rules.lua',b'UPSTREAMFAIL', 'text/plain')})
assert r.status_code == 422, r.text
text = (log_directory()/'security_analysis.log').read_text('utf-8')
assert 'analysis_failed' in text
assert 'analysis_completed' not in text
'''
    env = os.environ.copy()
    env['PYTHONPATH'] = str(project)
    p = subprocess.run([sys.executable, '-c', script], env=env, cwd=project, text=True, capture_output=True)
    assert p.returncode == 0, (p.stdout, p.stderr)


def test_no_symlink_overwrite(project):
    mod.install(project)
    (project / mod.MANIFEST).unlink()
    (project / mod.MODULE).unlink()
    try:
        (project / mod.MODULE).symlink_to(project / 'app/api/main.py')
    except (OSError, NotImplementedError):
        pytest.skip('Windows symlink creation requires special permissions')
    with pytest.raises(ValueError, match='Unsafe path'):
        mod.install(project)


def test_small_log_rotation(tmp_path):
    spec2 = importlib.util.spec_from_file_location('isolated_logger_test', THIS / 'app/core/audit_logging.py')
    m = importlib.util.module_from_spec(spec2)
    spec2.loader.exec_module(m)
    m.log_directory = lambda: tmp_path
    m.MAX_BYTES = 1024
    for i in range(120):
        m.audit_event('api_access', 'http_request', route='/api/v1/release/status', method='GET', status_code=200, duration_ms=i)
    assert (tmp_path/'api_access.log').exists()
    assert (tmp_path/'api_access.log.1').exists()
    assert len(list(tmp_path.glob('api_access.log*'))) <= m.BACKUPS+1
    assert all(p.stat().st_size <= 1024 for p in tmp_path.glob('api_access.log*'))


def test_error_500_and_unknown_route_sanitization(project):
    mod.install(project)
    script = '''\
from fastapi import FastAPI
from fastapi.testclient import TestClient
from app.core.audit_logging import AccessAuditMiddleware, log_directory
app = FastAPI()
app.add_middleware(AccessAuditMiddleware)
@app.get('/api/SECRET/secret-info')
async def crash():
    raise RuntimeError('PRIVATE_MESSAGE')
with TestClient(app, raise_server_exceptions=False) as client:
    response = client.get('/api/SECRET/secret-info?key=PRIVATE_MESSAGE')
assert response.status_code == 500
logs = log_directory()
access = (logs/'api_access.log').read_text('utf-8')
err = (logs/'error.log').read_text('utf-8')
assert 'other_api' in access and 'api_failure' in err
assert 'PRIVATE_MESSAGE' not in (access+err)
assert 'SECRET' not in (access+err)
'''
    env = os.environ.copy()
    env['PYTHONPATH'] = str(project)
    p = subprocess.run([sys.executable, '-c', script], env=env, cwd=project, text=True, capture_output=True)
    assert p.returncode == 0, (p.stdout, p.stderr)


def test_existing_custom_logger_protected(project):
    dest = project / mod.MODULE
    dest.write_text('# custom logger code', encoding='utf8')
    with pytest.raises(ValueError, match='Refusing to overwrite'):
        mod.install(project)
    assert dest.read_text('utf8') == '# custom logger code'
    assert not (project / mod.MANIFEST).exists()
