from __future__ import annotations
from pathlib import Path
from tempfile import TemporaryDirectory
import importlib.util

HERE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('install109', HERE / 'scripts/install_api_010_9.py')
assert spec and spec.loader
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


def fixture(root: Path):
    (root / 'app/api').mkdir(parents=True)
    (root / 'app/core').mkdir(parents=True)
    (root / 'app/api/main.py').write_text(
        'from app.api.nat_route_reachability import router as nat_route_router\n'
        'app.include_router(nat_route_router)\n')
    (root / 'app/api/nat_route_reachability.py').write_text('old endpoint')
    (root / 'app/core/nat_route_reachability.py').write_text('old engine')


def test_idempotent_and_preserve_previous_backend():
    with TemporaryDirectory() as d:
        root = Path(d)
        fixture(root)
        old = (root / 'app/api/main.py').read_bytes()
        assert len(installer.install(root)) == 4
        assert installer.install(root) == []
        assert (root / 'app/api/main.py.before_api0109.bak').read_bytes() == old
        assert (root / 'app/core/nat_route_reachability.py').read_text() == 'old engine'


def test_bad_layout_fails_without_partial_install():
    with TemporaryDirectory() as d:
        root = Path(d)
        fixture(root)
        main = root / 'app/api/main.py'
        main.write_text('different code')
        try:
            installer.install(root)
        except ValueError:
            pass
        else:
            assert False, 'invalid layout should fail'
        assert main.read_text() == 'different code'
        assert not (root / 'app/core/ids_configuration.py').exists()
