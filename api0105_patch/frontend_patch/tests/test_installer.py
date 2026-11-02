import importlib.util
from pathlib import Path
import pytest

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts' / 'install_api_010_5_frontend.py'
spec = importlib.util.spec_from_file_location('install_0105_frontend', SCRIPT)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def fixture(tmp_path):
    root = tmp_path / 'frontend'
    for folder in ('src/api', 'src/pages', 'src/utils', 'src/styles'):
        (root / folder).mkdir(parents=True, exist_ok=True)
    (root / 'package.json').write_text('{}')
    (root / 'src/api/universal.ts').write_text('''export interface NormalizedReport {
  correlation_assurance?: CorrelationAssurance;
}
const endpoint = "/api/v1/analyze/correlation-assurance";
export interface CorrelationAssurance { version: "1.0"; }
''')
    (root / 'src/pages/UniversalAnalysis.tsx').write_text('''import CorrelationAssurancePanel from "../components/CorrelationAssurancePanel";
export default function View(){ return <CorrelationAssurancePanel assurance={report.correlation_assurance} />; }
''')
    (root / 'src/utils/normalizedPdf.ts').write_text('''function section(x: string) {}
  section("Assessment coverage");
''')
    (root / 'src/styles/Sidebar.css').write_text('/* original sidebar theme */')
    return root


def test_install_and_repeat(tmp_path):
    root = fixture(tmp_path)
    assert len(mod.install(root)) == 5
    assert mod.install(root) == []
    assert 'object-resolution' in (root / 'src/api/universal.ts').read_text()
    assert 'ObjectResolutionPanel' in (root / 'src/pages/UniversalAnalysis.tsx').read_text()
    assert 'Network object resolution and policy selectors' in (root / 'src/utils/normalizedPdf.ts').read_text()


def test_restored_sidebar_is_not_touched(tmp_path):
    root = fixture(tmp_path)
    mod.install(root)
    assert (root / 'src/styles/Sidebar.css').read_text() == '/* original sidebar theme */'
    assert not (root / 'src/styles/SidebarGreen.css').exists()


def test_missing_layout_no_partial_change(tmp_path):
    root = fixture(tmp_path)
    (root / 'src/pages/UniversalAnalysis.tsx').write_text('unsupported dashboard')
    with pytest.raises(ValueError): mod.install(root)
    assert '/object-resolution' not in (root / 'src/api/universal.ts').read_text()


def test_backup_before_overwrite(tmp_path):
    root = fixture(tmp_path)
    path = root / 'src/components/ObjectResolutionPanel.css'
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('old style')
    mod.install(root)
    assert path.with_name(path.name + mod.BACKUP_SUFFIX).read_text() == 'old style'


def test_no_raw_html_in_pdf_appendix(tmp_path):
    root = fixture(tmp_path)
    mod.install(root)
    pdf = (root / 'src/utils/normalizedPdf.ts').read_text()
    assert 'resolved.pairs.slice(0, 30)' in pdf
    assert 'section("Assessment coverage")' in pdf
    assert '<script' not in pdf
