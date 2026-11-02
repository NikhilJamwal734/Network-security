from __future__ import annotations

import importlib.util
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('independent_json_logs_installer', ROOT / 'scripts/install_json_logs.py')
mod = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = mod
SPEC.loader.exec_module(mod)


@pytest.fixture()
def project(tmp_path):
    root = tmp_path / 'my-firewall-analyzer'
    for rel in mod.PREREQUISITES:
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        if rel == mod.MAIN:
            target.write_text('from fastapi import FastAPI\napp = FastAPI()\n', encoding='utf8')
        else:
            target.write_text('existing-user-code\n', encoding='utf8')
    return root


def test_installs_independent_json_page_and_retains_original_app(project):
    app_file = project / 'frontend/src/App.tsx'
    old_app = app_file.read_bytes()
    changed = mod.install(project)
    assert len(changed) == 8
    assert (project / 'frontend/logs.html').is_file()
    assert (project / 'frontend/src/pages/Logs.tsx').is_file()
    assert 'className="fa-json-line"' in (project / 'frontend/src/pages/Logs.tsx').read_text()
    assert 'fa-logs-summary' not in (project / 'frontend/src/pages/Logs.tsx').read_text()
    assert (project / 'frontend/src/api/logs.ts').is_file()
    assert 'app.include_router(json_audit_logs_router)' in (project / mod.MAIN).read_text()
    assert app_file.read_bytes() == old_app
    assert mod.install(project) == []


def test_rollback_restores_previous_state(project):
    original_main = (project / mod.MAIN).read_bytes()
    mod.install(project)
    restored = mod.rollback(project)
    assert len(restored) == 8
    assert (project / mod.MAIN).read_bytes() == original_main
    assert not (project / 'frontend/logs.html').exists()
    assert not (project / mod.MANIFEST).exists()


def test_crlf_and_utf8_bom_are_preserved(project):
    target = project / mod.MAIN
    target.write_bytes(b'\xef\xbb\xbffrom fastapi import FastAPI\r\napp = FastAPI()\r\n')
    mod.install(project)
    data = target.read_bytes()
    assert data.startswith(b'\xef\xbb\xbf')
    assert b'\r\n# JSON_LOGS_VIEWER_START\r\n' in data
    assert b'\r\r\n' not in data
    mod.rollback(project)
    assert target.read_bytes() == b'\xef\xbb\xbffrom fastapi import FastAPI\r\napp = FastAPI()\r\n'


def test_existing_custom_logs_tsx_is_never_overwritten(project):
    target = project / 'frontend/src/pages/Logs.tsx'
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text('CUSTOM CONTENT', encoding='utf8')
    orig_main = (project / mod.MAIN).read_bytes()
    with pytest.raises(ValueError, match='Existing file would be overwritten'):
        mod.install(project)
    assert target.read_text() == 'CUSTOM CONTENT'
    assert (project / mod.MAIN).read_bytes() == orig_main
    assert not (project / mod.MANIFEST).exists()


def test_missing_audit_logger_is_rejected_without_changes(project):
    (project / 'app/core/audit_logging.py').unlink()
    with pytest.raises(ValueError, match='Required existing project file missing'):
        mod.install(project)
    assert not (project / 'frontend/logs.html').exists()


def test_mixed_line_ending_is_rejected(project):
    target = project / mod.MAIN
    target.write_bytes(b'from fastapi import FastAPI\r\napp = FastAPI()\n')
    with pytest.raises(ValueError, match='Unsupported mixed line endings'):
        mod.install(project)
    assert not (project / 'frontend/logs.html').exists()


def test_unknown_modified_files_block_rollback(project):
    mod.install(project)
    target = project / 'frontend/logs.html'
    target.write_text('new editor changes', encoding='utf8')
    with pytest.raises(ValueError, match='File changed after installation'):
        mod.rollback(project)
    assert (project / mod.MANIFEST).exists()


def test_existing_logged_router_blocks_conflict(project):
    target = project / mod.MAIN
    target.write_text('from fastapi import FastAPI\napp = FastAPI()\nfrom app.api.log_viewer import router\n', encoding='utf8')
    with pytest.raises(ValueError, match='existing log viewer import'):
        mod.install(project)


def test_reject_symlinked_output(project, tmp_path):
    target = project / 'frontend/logs.html'
    external = tmp_path / 'outside.html'
    external.write_text('outside', encoding='utf8')
    try:
        target.symlink_to(external)
    except (OSError, NotImplementedError):
        pytest.skip('Symlink creation not supported')
    with pytest.raises(ValueError, match='symlink'):
        mod.install(project)
    assert external.read_text() == 'outside'


def test_ui_assets_and_python_compile():
    import ast
    ast.parse((ROOT / 'payload/app/api/log_viewer.py').read_text(encoding='utf8'))
    tsx = (ROOT / 'payload/frontend/src/pages/Logs.tsx').read_text(encoding='utf8')
    assert 'fa-json-line' in tsx
    assert 'fa-logs-summary' not in tsx
    assert 'loadAuditLogs' in tsx
    assert 'font-weight' in (ROOT / 'payload/frontend/src/pages/Logs.css').read_text()
