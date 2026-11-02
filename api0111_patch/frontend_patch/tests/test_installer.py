from __future__ import annotations
import importlib.util
from pathlib import Path
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('frontend111', ROOT / 'scripts/install_api_011_1_frontend.py')
assert spec and spec.loader
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def setup(root: Path):
    files = {
        'package.json': '{}',
        'src/api/universal.ts': '  consolidation_review?: ConsolidationReview;\nconst endpoint = "/api/v1/analyze/consolidated";',
        'src/pages/UniversalAnalysis.tsx': 'import ConsolidationSnippet from "../components/ConsolidationSnippet";\n<ConsolidationSnippet review={report.consolidation_review} />',
        'src/utils/normalizedPdf.ts': '  section("Cross-platform review consolidation — Evidence quality and provenance");\n  section("Assessment coverage");',
    }
    for path, value in files.items():
        file = root / path
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(value, encoding='utf-8')  # explicit UTF-8 also on Windows


def test_pdf_first_idempotent_and_preserve_previous_review():
    with TemporaryDirectory() as d:
        root = Path(d)
        setup(root)
        assert len(mod.install(root)) == 5
        assert mod.install(root) == []
        pdf = (root / 'src/utils/normalizedPdf.ts').read_text(encoding='utf-8')
        dash = (root / 'src/pages/UniversalAnalysis.tsx').read_text(encoding='utf-8')
        assert 'Cross-platform review consolidation' in pdf
        assert 'LINK-BY-LINK VALIDATION' in pdf
        assert 'acc.decisions.forEach' in pdf
        assert 'acc.quality_observations.forEach' in pdf
        assert 'acc.decisions.forEach' not in dash
        assert 'CorrelationAccuracySnippet review={report.correlation_accuracy_review}' in dash
        assert 'Assessment coverage' in pdf


def test_bad_layout_fail_before_write():
    with TemporaryDirectory() as d:
        root = Path(d)
        setup(root)
        pdf = root / 'src/utils/normalizedPdf.ts'
        pdf.write_text('different', encoding='utf-8')
        before = (root / 'src/api/universal.ts').read_bytes()
        try:
            mod.install(root)
        except ValueError:
            pass
        else:
            assert False
        assert (root / 'src/api/universal.ts').read_bytes() == before
        assert not (root / 'src/components/CorrelationAccuracySnippet.tsx').exists()
