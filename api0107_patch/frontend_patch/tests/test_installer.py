from pathlib import Path
from tempfile import TemporaryDirectory
import importlib.util

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('frontend_installer', HERE / 'scripts/install_api_010_7_frontend.py')
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def fixture(root: Path):
    (root / 'package.json').write_text('{"name":"frontend"}', encoding='utf-8')
    inputs = {
        'src/api/universal.ts': (
            'export interface NormalizedReport {\n'
            '  object_assurance?: ObjectAssurance;\n}\n'
            'export interface ObjectAssurance {}\n'
            'const endpoint = "/api/v1/analyze/object-assurance";\n'),
        'src/pages/UniversalAnalysis.tsx': (
            'import ObjectResolutionPanel from "../components/ObjectResolutionPanel";\n'
            'import ObjectAssurancePanel from "../components/ObjectAssurancePanel";\n'
            'const dashboard = (<div>\n'
            '  <ObjectResolutionPanel analysis={report.object_resolution} />\n'
            '  <ObjectAssurancePanel review={report.object_assurance} />\n'
            '</div>);\n'),
        'src/utils/normalizedPdf.ts': (
            'function render(report: NormalizedReport) {\n'
            '  section("Assessment coverage");\n'
            '}\n'),
    }
    for rel, value in inputs.items():
        file = root / rel
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(value, encoding='utf-8')
    (root / 'src/styles').mkdir(parents=True)
    (root / 'src/styles/Sidebar.css').write_text('color: original;', encoding='utf-8')


def test_compacts_only_object_panels_and_adds_new_snippet():
    with TemporaryDirectory() as d:
        root = Path(d); fixture(root)
        changed = mod.install(root)
        assert len(changed) == 6
        page = (root / 'src/pages/UniversalAnalysis.tsx').read_text()
        assert '<CompactObjectResolution' in page
        assert '<CompactObjectAssurance' in page
        assert '<ServiceIPv6Snippet' in page
        assert '<ObjectAssurancePanel' not in page
        assert '<ObjectResolutionPanel' not in page
        pdf = (root / 'src/utils/normalizedPdf.ts').read_text()
        assert 'Detailed technical evidence' in pdf
        assert 'sg6.objects.forEach' in pdf and 'sg6.pairs.forEach' in pdf
        assert (root / 'src/styles/Sidebar.css').read_text() == 'color: original;'


def test_repeat_installation_is_clean():
    with TemporaryDirectory() as d:
        root = Path(d); fixture(root)
        assert mod.install(root)
        assert mod.install(root) == []
        page = (root / 'src/pages/UniversalAnalysis.tsx').read_text()
        assert page.count('<ServiceIPv6Snippet') == 1


def test_preflight_failure_does_not_partially_modify_files():
    with TemporaryDirectory() as d:
        root = Path(d); fixture(root)
        page = root / 'src/pages/UniversalAnalysis.tsx'
        page.write_text('unknown layout', encoding='utf-8')
        original = (root / 'src/api/universal.ts').read_bytes()
        try:
            mod.install(root)
        except ValueError:
            pass
        else:
            assert False
        assert (root / 'src/api/universal.ts').read_bytes() == original
        assert not (root / 'src/components/ServiceIPv6Snippet.tsx').exists()


def test_backups_created_and_preserve_original():
    with TemporaryDirectory() as d:
        root = Path(d); fixture(root)
        previous = (root / 'src/pages/UniversalAnalysis.tsx').read_bytes()
        mod.install(root)
        assert (root / 'src/pages/UniversalAnalysis.tsx.before_api0107.bak').read_bytes() == previous


def test_pdf_does_not_point_details_to_dashboard():
    pdf = mod.patch_pdf('  section("Assessment coverage");\n')
    assert 'POLICY CORRELATION EVIDENCE' in pdf
    assert 'SOURCE' not in pdf or 'Source' in pdf
    assert 'dashboard' not in mod.PDF_SECTION.lower()


def test_bad_utf8_rejected_without_modifications():
    with TemporaryDirectory() as d:
        root = Path(d); fixture(root)
        f = root / 'src/utils/normalizedPdf.ts'
        f.write_bytes(b'\xff')
        original = (root / 'src/api/universal.ts').read_bytes()
        try:
            mod.install(root)
        except UnicodeError:
            pass
        else:
            assert False
        assert (root / 'src/api/universal.ts').read_bytes() == original
