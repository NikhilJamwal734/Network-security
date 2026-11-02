from __future__ import annotations

from pathlib import Path
import importlib.util
import tempfile

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/install_api_010_2_frontend.py'
spec = importlib.util.spec_from_file_location('api0102_frontend', SCRIPT)
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


def sample_frontend(folder: Path):
    p = folder / 'frontend'
    contents = {
        'package.json': '{}',
        'src/api/universal.ts': '/api/v1/analyze/deep-review\nexport interface VendorReview {\n}',
        'src/components/VendorDeepReviewPanel.tsx': '      {checks.length ? (\n',
        'src/utils/normalizedPdf.ts': '    section("Vendor-specific supplemental review");\n',
    }
    for rel, text in contents.items():
        target = p / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding='utf-8')
    return p


def test_idempotent_and_backups():
    with tempfile.TemporaryDirectory() as d:
        frontend = sample_frontend(Path(d))
        assert len(installer.install(frontend)) == 3
        assert installer.install(frontend) == []
        assert 'precision-review' in (frontend / 'src/api/universal.ts').read_text()
        assert 'precision?: {' in (frontend / 'src/api/universal.ts').read_text()
        assert (frontend / 'src/utils/normalizedPdf.ts.before_api0102.bak').exists()


def test_no_edits_on_unrecognized_pdf_layout():
    with tempfile.TemporaryDirectory() as d:
        frontend = sample_frontend(Path(d))
        (frontend / 'src/utils/normalizedPdf.ts').write_text('unexpected')
        before = (frontend / 'src/api/universal.ts').read_bytes()
        with pytest.raises(ValueError):
            installer.install(frontend)
        assert (frontend / 'src/api/universal.ts').read_bytes() == before
