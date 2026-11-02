from __future__ import annotations
from pathlib import Path
from tempfile import TemporaryDirectory
import importlib.util

HERE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('nrr_installer', HERE / 'scripts/install_api_010_8.py')
assert spec and spec.loader
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def fixture(root: Path):
    (root / 'app/api').mkdir(parents=True)
    (root / 'app/core').mkdir(parents=True)
    (root / 'app/api/main.py').write_text('from app.api.service_ipv6 import router as service_ipv6_router\n\napp.include_router(service_ipv6_router)\n')
    (root / 'app/api/service_ipv6.py').write_text('existing prior api')
    (root / 'app/core/service_ipv6.py').write_text('existing prior core')


def test_install_idempotent_preserves_prior():
    with TemporaryDirectory() as td:
        root = Path(td)
        fixture(root)
        src = (root / 'app/api/main.py').read_bytes()
        assert mod.install(root)
        assert mod.install(root) == []
        assert (root / 'app/api/main.py.before_api0108.bak').read_bytes() == src
        assert (root / 'app/core/service_ipv6.py').read_text() == 'existing prior core'


def test_unrecognized_layout_fails_preflight_without_changes():
    with TemporaryDirectory() as td:
        root = Path(td)
        fixture(root)
        main = root / 'app/api/main.py'
        main.write_text('unknown')
        try:
            mod.install(root)
        except ValueError:
            pass
        else:
            assert False
        assert main.read_text() == 'unknown'
        assert not (root / 'app/core/nat_route_reachability.py').exists()
