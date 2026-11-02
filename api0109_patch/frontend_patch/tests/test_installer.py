from __future__ import annotations
from pathlib import Path
from tempfile import TemporaryDirectory
import importlib.util

HERE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('front109', HERE / 'scripts/install_api_010_9_frontend.py')
assert spec and spec.loader
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


def fixture(root: Path):
    (root / 'package.json').write_text('{}')
    for rel, value in {
        'src/api/universal.ts': 'export interface NormalizedReport {\n  nat_route_reachability?: NatRouteReachabilityReview;\n}\nconst url = "/api/v1/analyze/nat-route-reachability";\n',
        'src/pages/UniversalAnalysis.tsx': 'import NatRouteSnippet from "../components/NatRouteSnippet";\nconst a = <NatRouteSnippet review={report.nat_route_reachability} />;\n',
        'src/utils/normalizedPdf.ts': '  section("NAT, routing and reachability — Detailed technical evidence");\n  section("Assessment coverage");\n',
    }.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(value, encoding='utf-8')


def test_pdf_evidence_snippet_dashboard_and_idempotence():
    with TemporaryDirectory() as d:
        root = Path(d)
        fixture(root)
        old = (root / 'src/pages/UniversalAnalysis.tsx').read_bytes()
        assert len(installer.install(root)) == 5
        assert installer.install(root) == []
        dash = (root / 'src/pages/UniversalAnalysis.tsx').read_text()
        pdf = (root / 'src/utils/normalizedPdf.ts').read_text()
        assert '<IdsDeepSnippet review={report.ids_deep_review} />' in dash
        assert 'ids.evidence.forEach' not in dash
        assert 'ids.evidence.forEach' in pdf and 'ids.limitations.forEach' in pdf
        assert 'item.recommendation' in pdf
        assert 'NAT, routing and reachability' in pdf
        assert (root / 'src/pages/UniversalAnalysis.tsx.before_api0109.bak').read_bytes() == old
        comp = (root / 'src/components/IdsDeepSnippet.tsx').read_text()
        assert 'review.evidence.slice(0, 2)' in comp
        assert 'item.recommendation' not in comp
        assert 'item.observation' not in comp


def test_bad_layout_does_not_touch_any_files():
    with TemporaryDirectory() as d:
        root = Path(d)
        fixture(root)
        path = root / 'src/utils/normalizedPdf.ts'
        path.write_text('different generator')
        old = (root / 'src/api/universal.ts').read_bytes()
        try:
            installer.install(root)
        except ValueError:
            pass
        else:
            assert False
        assert (root / 'src/api/universal.ts').read_bytes() == old
        assert not (root / 'src/components/IdsDeepSnippet.tsx').exists()
