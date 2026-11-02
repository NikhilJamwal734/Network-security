from pathlib import Path
import importlib.util
import pytest

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts' / 'install_api_010_4_frontend.py'
spec = importlib.util.spec_from_file_location('api0104_frontend', SCRIPT)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def fixture(tmp_path):
    root = tmp_path / 'frontend'
    (root / 'src/api').mkdir(parents=True)
    (root / 'src/pages').mkdir(parents=True)
    (root / 'src/utils').mkdir(parents=True)
    (root / 'package.json').write_text('{}')
    (root / 'src/api/universal.ts').write_text('''export interface NormalizedReport {
  rule_correlation?: RuleCorrelation;
}
const endpoint = "/api/v1/analyze/rule-correlation";
export interface RuleCorrelation { version: "1.0"; }
''')
    (root / 'src/pages/UniversalAnalysis.tsx').write_text('''import RuleCorrelationPanel from "../components/RuleCorrelationPanel";
export default function A(){ return <RuleCorrelationPanel review={report.rule_correlation} />; }
''')
    (root / 'src/utils/normalizedPdf.ts').write_text('''function section(x:string){};
  section("Assessment coverage");
''')
    return root


def test_install_idempotent(tmp_path):
    root = fixture(tmp_path)
    assert len(mod.install(root)) == 5
    assert mod.install(root) == []
    assert 'correlation-assurance' in (root / 'src/api/universal.ts').read_text()
    assert 'CorrelationAssurancePanel' in (root / 'src/pages/UniversalAnalysis.tsx').read_text()


def test_preserves_sidebar(tmp_path):
    root = fixture(tmp_path)
    p = root / 'src/styles/Sidebar.css'
    p.parent.mkdir(parents=True)
    p.write_text('/* original styling */')
    mod.install(root)
    assert p.read_text() == '/* original styling */'
    assert not (root / 'src/styles/SidebarGreen.css').exists()


def test_unknown_dashboard_does_not_mutate(tmp_path):
    root = fixture(tmp_path)
    dashboard = root / 'src/pages/UniversalAnalysis.tsx'
    dashboard.write_text('other dashboard')
    with pytest.raises(ValueError):
        mod.install(root)
    assert 'correlation-assurance' not in (root / 'src/api/universal.ts').read_text()


def test_pdf_appendix_is_bounded(tmp_path):
    root = fixture(tmp_path)
    mod.install(root)
    pdf = (root / 'src/utils/normalizedPdf.ts').read_text()
    assert 'items.slice(0, 35)' in pdf
    assert 'section("Assessment coverage")' in pdf
