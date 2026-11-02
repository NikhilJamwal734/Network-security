"""Windows-friendly UTF-8 frontend-only installation checks."""
from __future__ import annotations
import importlib.util
from pathlib import Path
from tempfile import TemporaryDirectory
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('f112', ROOT/'scripts/install_api_011_2_frontend.py')
assert spec and spec.loader
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def setup(root):
    data = {
        'package.json': '{}',
        'src/api/universal.ts': '  correlation_accuracy_review?: CorrelationAccuracyReview;\nconst endpoint = "/api/v1/analyze/correlation-accuracy";',
        'src/pages/UniversalAnalysis.tsx': 'import CorrelationAccuracySnippet from "../components/CorrelationAccuracySnippet";\n<CorrelationAccuracySnippet review={report.correlation_accuracy_review} />',
        'src/utils/normalizedPdf.ts': '  section("Correlation accuracy and false-positive triage — Detailed evidence");\n  section("Assessment coverage");',
    }
    for key,val in data.items():
        file = root/key
        file.parent.mkdir(parents=True,exist_ok=True)
        file.write_text(val,encoding='utf-8')


def test_pdf_first_layout_and_repeatable():
    with TemporaryDirectory() as tmp:
        root=Path(tmp)
        setup(root)
        assert len(mod.install(root)) == 5
        assert mod.install(root) == []
        pdf=(root/'src/utils/normalizedPdf.ts').read_text(encoding='utf-8')
        dash=(root/'src/pages/UniversalAnalysis.tsx').read_text(encoding='utf-8')
        assert 'rv.checks.forEach' in pdf
        assert 'rv.checks.forEach' not in dash
        assert '<ReportValidationSnippet' in dash
        assert 'CorrelationAccuracySnippet' in dash
        assert 'report_validation_review?: ReportValidationReview' in (root/'src/api/universal.ts').read_text(encoding='utf-8')


def test_invalid_pdf_layout_no_writes():
    with TemporaryDirectory() as tmp:
        root=Path(tmp)
        setup(root)
        (root/'src/utils/normalizedPdf.ts').write_text('unexpected',encoding='utf-8')
        before=(root/'src/api/universal.ts').read_bytes()
        try: mod.install(root)
        except ValueError: pass
        else: assert False
        assert (root/'src/api/universal.ts').read_bytes() == before
        assert not (root/'src/components/ReportValidationSnippet.tsx').exists()
