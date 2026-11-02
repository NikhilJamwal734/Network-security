"""Smoke tests for safe backend installer behavior and route registration."""
from pathlib import Path
import importlib.util
import pytest

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts' / 'install_api_010_6.py'
spec = importlib.util.spec_from_file_location('api0106_installer', SCRIPT)
module = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(module)


def make_project(tmp_path: Path) -> Path:
    main = tmp_path / 'app' / 'api' / 'main.py'
    main.parent.mkdir(parents=True)
    main.write_text('from app.api.object_resolution import router as object_resolution_router\n'
                    'app.include_router(object_resolution_router)\n')
    (tmp_path / 'app' / 'api' / 'object_resolution.py').write_text('old api')
    (tmp_path / 'app' / 'core').mkdir(parents=True)
    (tmp_path / 'app' / 'core' / 'object_resolution.py').write_text('old core')
    return tmp_path


def test_backend_installs_and_is_repeatable(tmp_path):
    project = make_project(tmp_path)
    first = module.install(project)
    assert len(first) == 4
    main = (project / 'app/api/main.py').read_text()
    assert main.count(module.IMPORT) == 1
    assert main.count(module.INCLUDE) == 1
    assert module.install(project) == []
    assert (project / 'app/api/main.py.before_api0106.bak').exists()


def test_backend_preflight_missing_prerequisite(tmp_path):
    make_project(tmp_path)
    (tmp_path / 'app/core/object_resolution.py').unlink()
    with pytest.raises(ValueError):
        module.install(tmp_path)
    assert 'object_assurance' not in (tmp_path / 'app/api/main.py').read_text()


def test_backend_preflight_refuses_unknown_registration(tmp_path):
    project = make_project(tmp_path)
    (project / 'app/api/main.py').write_text('app = something\n')
    with pytest.raises(ValueError):
        module.install(project)
    assert not (project / 'app/core/object_assurance.py').exists()


def test_backend_partial_registration_is_error():
    with pytest.raises(ValueError):
        module.patch_main(module.IMPORT + '\n' + module.INCLUDE_ANCHOR)
