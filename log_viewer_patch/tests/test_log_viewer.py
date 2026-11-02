import asyncio
import importlib.util
import json
import sys
from pathlib import Path
import types

import pytest

PATCH = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PATCH / 'scripts'))
from install_log_viewer import install, rollback, _patch_api, _patch_app, _plan  # noqa: E402


@pytest.fixture
def project(tmp_path):
    (tmp_path / 'app/api').mkdir(parents=True)
    (tmp_path / 'app/core').mkdir(parents=True)
    (tmp_path / 'frontend/src/pages').mkdir(parents=True)
    (tmp_path / 'frontend/src/api').mkdir(parents=True)
    (tmp_path / 'app/core/audit_logging.py').write_text('STREAMS = ()\n', encoding='utf-8')
    (tmp_path / 'app/api/main.py').write_text('''from fastapi import FastAPI
app = FastAPI()
from app.api.release_status import router as release_status_router
app.include_router(release_status_router)
''', encoding='utf-8')
    (tmp_path / 'frontend/src/App.tsx').write_text('''import { lazy, Suspense, useState } from "react";
const Dashboard = lazy(() => import("./pages/Dashboard"));
const navItems = [{label: "Dashboard", icon: "▦"}, {label: "Findings", icon: "⚠"}];
export default function App() {
const [activePage, setActivePage] = useState("Dashboard");
return <div><Suspense fallback={null}>
{report && activePage === "Dashboard" && <Dashboard />}
</Suspense></div>
}
''', encoding='utf-8')
    return tmp_path


def test_install_and_rollback(project):
    before_api = (project / 'app/api/main.py').read_bytes()
    before_app = (project / 'frontend/src/App.tsx').read_bytes()
    files = install(project)
    assert len(files) == 7
    app = (project / 'frontend/src/App.tsx').read_text(encoding='utf-8')
    main = (project / 'app/api/main.py').read_text(encoding='utf-8')
    assert 'activePage === "Logs"' in app
    assert 'from app.api.log_viewer import router' in main
    assert not install(project)
    changed = rollback(project)
    assert len(changed) == 7
    assert (project / 'app/api/main.py').read_bytes() == before_api
    assert (project / 'frontend/src/App.tsx').read_bytes() == before_app
    assert not (project / 'app/api/log_viewer.py').exists()


def test_preserves_bom_crlf(project):
    for rel in ('app/api/main.py', 'frontend/src/App.tsx'):
        p = project / rel
        p.write_bytes(b'\xef\xbb\xbf' + p.read_bytes().replace(b'\r\n', b'\n').replace(b'\n', b'\r\n'))
    install(project)
    for rel in ('app/api/main.py', 'frontend/src/App.tsx'):
        data = (project / rel).read_bytes()
        assert data.startswith(b'\xef\xbb\xbf')
        assert b'\r\r\n' not in data
        assert b'\r\n' in data
        assert b'\n' not in data.replace(b'\r\n', b'')


def test_abort_on_unsupported_app_without_edits(project):
    path = project / 'frontend/src/App.tsx'
    path.write_text('export function App() {return null}', encoding='utf-8')
    original = (project / 'app/api/main.py').read_bytes()
    with pytest.raises(ValueError, match='Dashboard lazy import'):
        install(project)
    assert (project / 'app/api/main.py').read_bytes() == original
    assert not (project / 'app/api/log_viewer.py').exists()


def test_refuses_rollback_over_user_edits(project):
    install(project)
    with (project / 'frontend/src/App.tsx').open('a') as f:
        f.write('// customized\n')
    with pytest.raises(ValueError, match='changed since installation'):
        rollback(project)
    assert (project / 'app/api/log_viewer.py').exists()


def test_typed_union_app():
    text = '''const Dashboard = lazy(() => import("./pages/Dashboard"));
type PageName =
  | "Dashboard"
  | "Findings";
const navItems = [{ label: "Dashboard", icon: "▦" }];
return <Suspense>
            {activePage === "Universal Analysis" && (
             <UniversalAnalysis />
            )}
            {activePage === "Dashboard" && (
             <Dashboard />
            )}
</Suspense>;
'''
    result = _patch_app(text.encode()).decode()
    assert '| "Logs"' in result
    assert result.count('{activePage === "Logs" && <Logs />}') == 1


def test_unsupported_line_endings_rejected(project):
    p = project / 'app/api/main.py'
    p.write_bytes(p.read_bytes().replace(b'\n', b'\r\r\n'))
    with pytest.raises(ValueError, match='line endings'):
        _plan(project)


def load_api(monkeypatch, temp):
    import fastapi
    audit = types.ModuleType('app.core.audit_logging')
    audit.BACKUPS = 3
    audit.STREAMS = ('application', 'api_access', 'upload_audit', 'security_analysis', 'error')
    audit.log_directory = lambda: temp
    monkeypatch.setitem(sys.modules, 'app', types.ModuleType('app'))
    monkeypatch.setitem(sys.modules, 'app.core', types.ModuleType('app.core'))
    monkeypatch.setitem(sys.modules, 'app.core.audit_logging', audit)
    module_name = 'test_dynamic_log_viewer'
    spec = importlib.util.spec_from_file_location(module_name, PATCH / 'payload/app/api/log_viewer.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    app = fastapi.FastAPI()
    app.include_router(mod.router)
    return mod, app


def test_api_read_filter_rotation_and_privacy(monkeypatch, tmp_path):
    from fastapi.testclient import TestClient
    mod, app = load_api(monkeypatch, tmp_path)
    (tmp_path / 'security_analysis.log.1').write_text('{"timestamp_utc":"2026-10-25T11:00:00+00:00","event":"analysis_started","password":"DO_NOT_RETURN"}\n')
    (tmp_path / 'security_analysis.log').write_text('junk\n' + json.dumps({
        'timestamp_utc': '2026-10-26T11:00:00+00:00', 'event': 'analysis_completed',
        'filename': 'ASA.cfg', 'finding_count': 13, 'secret': 'DO_NOT_RETURN',
    }) + '\n')
    with TestClient(app, base_url='http://127.0.0.1:8000', client=('127.0.0.1', 50000)) as c:
        result = c.get('/api/v1/logs?stream=security_analysis&limit=10')
        assert result.status_code == 200
        data = result.json()
        assert data['count'] == 2
        assert data['entries'][0]['filename'] == 'ASA.cfg'
        assert data['entries'][0]['level'] == 'success'
        assert data['entries'][1]['level'] == 'info'
        assert 'DO_NOT_RETURN' not in result.text
        assert result.headers['cache-control'] == 'no-store'
        assert c.get('/api/v1/logs?stream=../../etc/passwd').status_code == 422
        assert c.get('/api/v1/logs?stream=error&limit=501').status_code == 422
        assert c.get('/api/v1/logs', headers={'Origin': 'https://evil.example'}).status_code == 403
        assert c.get('/api/v1/logs', headers={'Origin': 'http://localhost:5173'}).status_code == 200
    with TestClient(app, base_url='http://192.168.1.50:8000', client=('192.168.1.50', 51000)) as c:
        # TestClient's peer address defaults to 'testclient', i.e. nonloopback.
        assert c.get('/api/v1/logs').status_code == 403


def test_symlinked_log_file_not_read(monkeypatch, tmp_path):
    outside = tmp_path.parent / 'private-log.jsonl'
    outside.write_text('{"event":"analysis_completed","secret":"SECRET"}\n')
    logdir = tmp_path / 'logs'
    logdir.mkdir()
    try:
        (logdir / 'error.log').symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip('Platform does not permit symlinks')
    mod, app = load_api(monkeypatch, logdir)
    assert mod.read_recent('error') == []


def test_failure_colour_levels(monkeypatch, tmp_path):
    mod, _ = load_api(monkeypatch, tmp_path)
    assert mod._level({'event': 'upload_rejected'}) == 'error'
    assert mod._level({'event': 'analysis_completed'}) == 'success'
    assert mod._level({'event': 'http_request', 'status_code': 404}) == 'warning'
    assert mod._level({'event': 'api_failure'}) == 'error'
