from __future__ import annotations
from pathlib import Path
from tempfile import TemporaryDirectory
import importlib.util

HERE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('combined110', HERE / 'scripts/install_all_api_011_0.py')
assert spec and spec.loader
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def setup(root: Path):
    for path, value in {
        'app/api/main.py': 'from app.api.ids_configuration import router as ids_configuration_router\napp.include_router(ids_configuration_router)\n',
        'app/api/ids_configuration.py': '# installed 10.9',
        'app/core/ids_configuration.py': '# installed 10.9',
        'frontend/package.json': '{}',
        'frontend/src/api/universal.ts': '  ids_deep_review?: IdsDeepReview;\nconst endpoint = "/api/v1/analyze/ids-configuration";',
        'frontend/src/pages/UniversalAnalysis.tsx': 'import IdsDeepSnippet from "../components/IdsDeepSnippet";\n<IdsDeepSnippet review={report.ids_deep_review} />',
        'frontend/src/utils/normalizedPdf.ts': '  section("Assessment coverage");',
    }.items():
        file = root / path
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(value)


def test_single_command_install_and_rerun():
    with TemporaryDirectory() as d:
        root = Path(d)
        setup(root)
        assert len(mod.install(root)) == 9
        assert mod.install(root) == []


def test_bad_frontend_blocks_backend_too():
    with TemporaryDirectory() as d:
        root = Path(d)
        setup(root)
        (root / 'frontend/src/utils/normalizedPdf.ts').write_text('different')
        before = (root / 'app/api/main.py').read_bytes()
        try:
            mod.install(root)
        except ValueError:
            pass
        else:
            assert False
        assert (root / 'app/api/main.py').read_bytes() == before
        assert not (root / 'app/core/consolidation.py').exists()
