"""Installer safeguards: root resolution, preservation and all-or-nothing preflight."""
import importlib.util
from pathlib import Path
import pytest

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts' / 'install_api_010_5.py'
spec = importlib.util.spec_from_file_location('install_0105_backend', SCRIPT)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

MAIN = '''from app.api.correlation_assurance import router as correlation_assurance_router\n\napp.include_router(correlation_assurance_router)\n'''


def fixture(tmp_path):
    root = tmp_path / 'project root' / 'config analyzer'
    for rel in ('app/api/main.py', 'app/api/correlation_assurance.py', 'app/core/correlation_assurance.py',
                'app/api/rule_correlation.py', 'app/core/rule_correlation.py'):
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(MAIN if rel.endswith('/main.py') else '# from earlier milestone\n')
    return root


def test_install_idempotent_and_root_path(tmp_path):
    root = fixture(tmp_path)
    assert len(mod.install(root)) == 4
    assert mod.install(root) == []
    assert (root / 'app/api/object_resolution.py').is_file()
    assert mod.INCLUDE in (root / 'app/api/main.py').read_text()
    assert not (root.parent / 'app/api/object_resolution.py').exists()


def test_missing_prerequisite_no_mutation(tmp_path):
    root = fixture(tmp_path)
    (root / 'app/api/correlation_assurance.py').unlink()
    with pytest.raises(ValueError): mod.install(root)
    assert not (root / 'app/core/object_resolution.py').exists()


def test_unknown_main_no_mutation(tmp_path):
    root = fixture(tmp_path)
    (root / 'app/api/main.py').write_text('app = FastAPI()\n')
    with pytest.raises(ValueError): mod.install(root)
    assert not (root / 'tests/test_api_010_5_object_resolution.py').exists()


def test_backup_made_before_overwrite(tmp_path):
    root = fixture(tmp_path)
    target = root / 'app/core/object_resolution.py'
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text('old implementation')
    mod.install(root)
    assert target.with_name(target.name + mod.BACKUP_SUFFIX).read_text() == 'old implementation'


def test_partial_route_registration_is_rejected(tmp_path):
    root = fixture(tmp_path)
    path = root / 'app/api/main.py'
    path.write_text(MAIN + mod.IMPORT + '\n')
    with pytest.raises(ValueError): mod.install(root)
