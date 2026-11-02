from __future__ import annotations
from pathlib import Path
from tempfile import TemporaryDirectory
import importlib.util

HERE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('backend110', HERE / 'scripts/install_api_011_0.py')
assert spec and spec.loader
backend = importlib.util.module_from_spec(spec)
spec.loader.exec_module(backend)


def setup(root: Path):
    for path, content in {
        'app/api/main.py': 'from app.api.ids_configuration import router as ids_configuration_router\napp.include_router(ids_configuration_router)\n',
        'app/api/ids_configuration.py': '# 10.9',
        'app/core/ids_configuration.py': '# 10.9',
    }.items():
        dst = root / path
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text(content)


def test_backend_install_is_idempotent_and_has_backups():
    with TemporaryDirectory() as tmp:
        root = Path(tmp)
        setup(root)
        assert len(backend.install(root)) == 4
        assert backend.install(root) == []
        assert (root / 'app/api/main.py.before_api0110.bak').exists()
        assert 'from app.api.consolidation import router' in (root / 'app/api/main.py').read_text()


def test_missing_anchor_preflight_no_changes():
    with TemporaryDirectory() as tmp:
        root = Path(tmp)
        setup(root)
        (root / 'app/api/main.py').write_text('# missing router')
        try:
            backend.install(root)
        except ValueError:
            pass
        else:
            assert False
        assert not (root / 'app/core/consolidation.py').exists()
