"""Installer idempotence and atomic planning on 11.1-shaped project."""
from __future__ import annotations
import importlib.util
from pathlib import Path
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('all112', ROOT/'scripts/install_all_api_011_2.py')
assert spec and spec.loader
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def setup(root):
    data = {
        'app/api/main.py': 'from app.api.correlation_accuracy import router as correlation_accuracy_router\napp.include_router(correlation_accuracy_router)\n',
        'app/api/correlation_accuracy.py': '# API-11.1',
        'app/core/correlation_accuracy.py': '# API-11.1',
        'frontend/package.json': '{}',
        'frontend/src/api/universal.ts': '  correlation_accuracy_review?: CorrelationAccuracyReview;\nconst endpoint = "/api/v1/analyze/correlation-accuracy";',
        'frontend/src/pages/UniversalAnalysis.tsx': 'import CorrelationAccuracySnippet from "../components/CorrelationAccuracySnippet";\n<CorrelationAccuracySnippet review={report.correlation_accuracy_review} />',
        'frontend/src/utils/normalizedPdf.ts': '  section("Correlation accuracy and false-positive triage — Detailed evidence");\n  section("Assessment coverage");',
    }
    for key, value in data.items():
        path = root/key
        path.parent.mkdir(parents=True,exist_ok=True)
        path.write_text(value,encoding='utf-8')


def test_combined_install_idempotence():
    with TemporaryDirectory() as tmp:
        root = Path(tmp)
        setup(root)
        assert len(mod.install(root)) == 9
        assert mod.install(root) == []
        pdf = (root/'frontend/src/utils/normalizedPdf.ts').read_text(encoding='utf-8')
        dash = (root/'frontend/src/pages/UniversalAnalysis.tsx').read_text(encoding='utf-8')
        assert 'CONTRACT CHECK EVIDENCE' in pdf
        assert 'rv.checks.forEach' in pdf
        assert 'rv.checks.forEach' not in dash
        assert 'report_validation_review' in dash
        assert 'correlation_accuracy_review' in dash


def test_bad_frontend_blocks_backend_changes():
    with TemporaryDirectory() as tmp:
        root = Path(tmp)
        setup(root)
        (root/'frontend/src/utils/normalizedPdf.ts').write_text('bad layout',encoding='utf-8')
        old = (root/'app/api/main.py').read_bytes()
        try: mod.install(root)
        except ValueError: pass
        else: assert False
        assert (root/'app/api/main.py').read_bytes() == old
        assert not (root/'app/core/report_validation.py').exists()


def test_rollback_restores_pristine_11_1_state():
    spec = importlib.util.spec_from_file_location('rb112', ROOT/'scripts/rollback_api_011_2.py')
    assert spec and spec.loader
    rollback = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(rollback)
    with TemporaryDirectory() as tmp:
        root = Path(tmp)
        setup(root)
        original = {rel:(root/rel).read_bytes() for rel in rollback.MODIFIED}
        mod.install(root)
        rollback.rollback(root)
        assert all((root/rel).read_bytes() == src for rel,src in original.items())
        assert not (root/'app/core/report_validation.py').exists()
