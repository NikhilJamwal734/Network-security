from __future__ import annotations
from pathlib import Path
from tempfile import TemporaryDirectory
import importlib.util

HERE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('nrr_frontend_installer', HERE / 'scripts/install_api_010_8_frontend.py')
assert spec and spec.loader
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def fixture(root: Path):
    (root / 'package.json').write_text('{}')
    for rel, value in {
        'src/api/universal.ts': 'export interface NormalizedReport {\n  service_ipv6?: ServiceIPv6Review;\n}\nconst url = "/api/v1/analyze/service-ipv6";\n',
        'src/pages/UniversalAnalysis.tsx': 'import ServiceIPv6Snippet from "../components/ServiceIPv6Snippet";\nconst a = <ServiceIPv6Snippet review={report.service_ipv6} />;\n',
        'src/utils/normalizedPdf.ts': '  section("Assessment coverage");\n',
    }.items():
        dest = root / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(value)


def test_frontend_snippet_only_pdf_details_and_idempotent():
    with TemporaryDirectory() as td:
        root = Path(td)
        fixture(root)
        old = (root / 'src/pages/UniversalAnalysis.tsx').read_bytes()
        assert len(mod.install(root)) == 5
        assert mod.install(root) == []
        view = (root / 'src/pages/UniversalAnalysis.tsx').read_text()
        assert view.count('<NatRouteSnippet review={report.nat_route_reachability} />') == 1
        assert 'nr.evidence.forEach' not in view
        pdf = (root / 'src/utils/normalizedPdf.ts').read_text()
        assert 'nr.evidence.forEach' in pdf and 'nr.limitations.forEach' in pdf
        assert (root / 'src/pages/UniversalAnalysis.tsx.before_api0108.bak').read_bytes() == old


def test_bad_frontend_aborts_before_touching_any_file():
    with TemporaryDirectory() as td:
        root = Path(td)
        fixture(root)
        pdf = root / 'src/utils/normalizedPdf.ts'
        pdf.write_text('unknown layout')
        old = (root / 'src/api/universal.ts').read_bytes()
        try:
            mod.install(root)
        except ValueError:
            pass
        else:
            assert False
        assert (root / 'src/api/universal.ts').read_bytes() == old
        assert not (root / 'src/components/NatRouteSnippet.tsx').exists()
