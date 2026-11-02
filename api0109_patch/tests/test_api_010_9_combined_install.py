from __future__ import annotations
from pathlib import Path
from tempfile import TemporaryDirectory
import importlib.util

HERE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('combined109', HERE / 'scripts/install_all_api_010_9.py')
assert spec and spec.loader
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def fixture(root: Path):
    for rel, text in {
        'app/api/main.py': 'from app.api.nat_route_reachability import router as nat_route_router\napp.include_router(nat_route_router)\n',
        'app/api/nat_route_reachability.py': 'previous API',
        'app/core/nat_route_reachability.py': 'previous core',
        'frontend/package.json': '{}',
        'frontend/src/api/universal.ts': '  nat_route_reachability?: NatRouteReachabilityReview;\nurl="/api/v1/analyze/nat-route-reachability";',
        'frontend/src/pages/UniversalAnalysis.tsx': 'import NatRouteSnippet from "../components/NatRouteSnippet";\n<NatRouteSnippet review={report.nat_route_reachability} />',
        'frontend/src/utils/normalizedPdf.ts': '  section("Assessment coverage");\n',
    }.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)


def test_single_command_installs_and_is_idempotent():
    with TemporaryDirectory() as temp:
        root = Path(temp)
        fixture(root)
        assert len(mod.install(root)) == 9
        assert mod.install(root) == []


def test_invalid_pdf_blocks_backend_install_too():
    with TemporaryDirectory() as temp:
        root = Path(temp)
        fixture(root)
        (root / 'frontend/src/utils/normalizedPdf.ts').write_text('altered')
        before = (root / 'app/api/main.py').read_text()
        try:
            mod.install(root)
        except ValueError:
            pass
        else:
            assert False
        assert (root / 'app/api/main.py').read_text() == before
        assert not (root / 'app/core/ids_configuration.py').exists()
