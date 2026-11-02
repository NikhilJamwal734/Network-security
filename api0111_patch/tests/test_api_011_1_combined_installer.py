from __future__ import annotations
from pathlib import Path
from tempfile import TemporaryDirectory
import importlib.util

HERE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('all111', HERE / 'scripts/install_all_api_011_1.py')
assert spec and spec.loader
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def setup(root: Path):
    for path, value in {
        'app/api/main.py': 'from app.api.consolidation import router as consolidation_router\napp.include_router(consolidation_router)\n',
        'app/api/consolidation.py': '# prior API',
        'app/core/consolidation.py': '# prior backend',
        'frontend/package.json': '{}',
        'frontend/src/api/universal.ts': '  consolidation_review?: ConsolidationReview;\nconst endpoint = "/api/v1/analyze/consolidated";',
        'frontend/src/pages/UniversalAnalysis.tsx': 'import ConsolidationSnippet from "../components/ConsolidationSnippet";\n<ConsolidationSnippet review={report.consolidation_review} />',
        'frontend/src/utils/normalizedPdf.ts': '  section("Assessment coverage");',
    }.items():
        target = root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(value, encoding='utf-8')


def test_combined_install_idempotent():
    with TemporaryDirectory() as d:
        root = Path(d)
        setup(root)
        assert len(mod.install(root)) == 9
        assert mod.install(root) == []
        main = (root / 'app/api/main.py').read_text(encoding='utf-8')
        assert main.count('app.include_router(consolidation_router)') == 1
        assert main.count('app.include_router(correlation_accuracy_router)') == 1


def test_frontend_validation_blocks_backend_writes():
    with TemporaryDirectory() as d:
        root = Path(d)
        setup(root)
        (root / 'frontend/src/utils/normalizedPdf.ts').write_text('wrong', encoding='utf-8')
        before = (root / 'app/api/main.py').read_bytes()
        try:
            mod.install(root)
        except ValueError:
            pass
        else:
            assert False
        assert (root / 'app/api/main.py').read_bytes() == before
        assert not (root / 'app/core/correlation_accuracy.py').exists()


def test_rollback_restores_originals():
    rollback_file = HERE / 'scripts/rollback_api_011_1.py'
    spec = importlib.util.spec_from_file_location('rollback111', rollback_file)
    assert spec and spec.loader
    rollback = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(rollback)
    with TemporaryDirectory() as d:
        root = Path(d)
        setup(root)
        old = {name: (root / name).read_bytes() for name in rollback.MODIFIED}
        mod.install(root)
        rollback.rollback(root)
        assert all((root / name).read_bytes() == payload for name, payload in old.items())
        assert not (root / 'app/core/correlation_accuracy.py').exists()
