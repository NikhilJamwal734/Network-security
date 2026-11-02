"""Installer safeguards, including preservation of the previous upload fix."""
from pathlib import Path
import importlib.util
import pytest

INSTALLER = Path(__file__).resolve().parents[1] / 'scripts' / 'install_api_010_4.py'
spec = importlib.util.spec_from_file_location('api0104_install', INSTALLER)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

MAIN = '''from app.api.rule_correlation import router as rule_correlation_router\n\napp.include_router(rule_correlation_router)\n'''
OLD = '''async def f(file):
    await file.seek(0)
    data = await file.read(_MAX_CORRELATION_BYTES + 1)
    await file.seek(0)
    old_report = await _run_precision(file=file, platform=platform)
'''


def project(tmp_path, *, main=MAIN, old=OLD):
    root = tmp_path / 'config analyzer'
    for rel in ('app/api/main.py', 'app/api/rule_correlation.py',
                'app/core/rule_correlation.py', 'app/api/precision_review.py'):
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(main if rel.endswith('main.py') else old if rel.endswith('rule_correlation.py') else '# preexisting\n', encoding='utf8')
    return root


def test_install_and_repeat(tmp_path):
    root = project(tmp_path)
    changes = module.install(root)
    assert len(changes) == 4
    assert module.install(root) == []
    assert module.IMPORT in (root / 'app/api/main.py').read_text()
    assert module.ROUTE in (root / 'app/api/main.py').read_text()
    assert 'await file.seek(0)' in (root / 'app/api/rule_correlation.py').read_text()


def test_no_partial_write_on_unknown_main(tmp_path):
    root = project(tmp_path, main='from fastapi import FastAPI\napp = FastAPI()\n')
    with pytest.raises(ValueError):
        module.install(root)
    assert not (root / 'app/core/correlation_assurance.py').exists()


def test_refuses_unfixed_upload_route(tmp_path):
    root = project(tmp_path, old='old_report = await _run_precision(file=file, platform=platform)\nawait file.seek(0)\n')
    with pytest.raises(ValueError, match='closed-upload'):
        module.install(root)
    assert not (root / 'app/api/correlation_assurance.py').exists()


def test_backups_existing_files(tmp_path):
    root = project(tmp_path)
    target = root / 'app/core/correlation_assurance.py'
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text('old source\n')
    module.install(root)
    assert (target.parent / (target.name + module.BACKUP)).read_text() == 'old source\n'
