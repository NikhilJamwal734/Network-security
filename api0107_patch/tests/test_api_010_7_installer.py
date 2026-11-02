from pathlib import Path
from tempfile import TemporaryDirectory
import importlib.util

SRC = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('installer', SRC / 'scripts/install_api_010_7.py')
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def fixture(root: Path):
    for rel in ('app/api/main.py', 'app/api/object_assurance.py', 'app/core/object_assurance.py'):
        f = root / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text('placeholder\n', encoding='utf-8')
    (root / 'app/api/main.py').write_text(
        'from app.api.object_assurance import router as object_assurance_router\n'
        'app.include_router(object_assurance_router)\n', encoding='utf-8')


def test_installer_registers_router_and_copies_tests():
    with TemporaryDirectory() as d:
        root = Path(d); fixture(root)
        changed = mod.install(root)
        assert len(changed) == 4
        main = (root / 'app/api/main.py').read_text(encoding='utf-8')
        assert 'app.include_router(service_ipv6_router)' in main
        assert (root / 'tests/test_api_010_7_service_ipv6.py').exists()


def test_installer_idempotent_and_keeps_backup():
    with TemporaryDirectory() as d:
        root = Path(d); fixture(root)
        assert mod.install(root)
        assert not mod.install(root)
        assert (root / 'app/api/main.py.before_api0107.bak').exists()


def test_installer_aborts_unfamiliar_structure_without_edits():
    with TemporaryDirectory() as d:
        root = Path(d); fixture(root)
        main = root / 'app/api/main.py'; main.write_text('different application', encoding='utf-8')
        before = main.read_bytes()
        try:
            mod.install(root)
        except ValueError:
            pass
        else:
            assert False, 'Unexpected layout must be rejected'
        assert main.read_bytes() == before
        assert not (root / 'app/core/service_ipv6.py').exists()


def test_installer_requires_api0106():
    with TemporaryDirectory() as d:
        root = Path(d)
        try:
            mod.install(root)
        except ValueError as error:
            assert 'prerequisite' in str(error)
        else:
            assert False
