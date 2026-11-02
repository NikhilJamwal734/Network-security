from __future__ import annotations
from pathlib import Path
from tempfile import TemporaryDirectory
import importlib.util

HERE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('front110', HERE / 'scripts/install_api_011_0_frontend.py')
assert spec and spec.loader
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def setup(root: Path):
    for path, content in {
        'package.json': '{}',
        'src/api/universal.ts': 'export interface NormalizedReport {\n  ids_deep_review?: IdsDeepReview;\n}\nconst endpoint = "/api/v1/analyze/ids-configuration";',
        'src/pages/UniversalAnalysis.tsx': 'import IdsDeepSnippet from "../components/IdsDeepSnippet";\n<IdsDeepSnippet review={report.ids_deep_review} />',
        'src/utils/normalizedPdf.ts': '  section("Snort and Suricata — Detailed IDS configuration evidence");\n  section("Assessment coverage");',
    }.items():
        dst = root / path
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text(content, encoding="utf-8")


def test_pdf_only_details_and_idempotence():
    with TemporaryDirectory() as tmp:
        root = Path(tmp)
        setup(root)
        assert len(mod.install(root)) == 5
        assert mod.install(root) == []
        pdf = (root / 'src/utils/normalizedPdf.ts').read_text(encoding="utf-8")
        dashboard = (root / 'src/pages/UniversalAnalysis.tsx').read_text(encoding="utf-8")
        api = (root / 'src/api/universal.ts').read_text(encoding="utf-8")
        comp = (root / 'src/components/ConsolidationSnippet.tsx').read_text(encoding="utf-8")
        assert 'Cross-platform review consolidation' in pdf
        assert 'con.issues.forEach' in pdf and 'con.links.forEach' in pdf
        assert 'con.issues.forEach' not in dashboard
        assert '<ConsolidationSnippet review={report.consolidation_review} />' in dashboard
        assert 'review.issues.slice(0, 2)' in comp
        assert 'item.recommendation' not in comp and 'item.observation' not in comp
        assert '/api/v1/analyze/consolidated' in api


def test_pdf_anchor_missing_fails_without_write():
    with TemporaryDirectory() as tmp:
        root = Path(tmp)
        setup(root)
        (root / 'src/utils/normalizedPdf.ts').write_text('changed')
        try:
            mod.install(root)
        except ValueError:
            pass
        else:
            assert False
        assert not (root / 'src/components/ConsolidationSnippet.tsx').exists()
