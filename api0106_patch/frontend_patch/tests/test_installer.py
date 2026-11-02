"""API-010.6 React/PDF integration and idempotence tests."""
from pathlib import Path
import importlib.util
import pytest

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts' / 'install_api_010_6_frontend.py'
spec = importlib.util.spec_from_file_location('frontend0106', SCRIPT)
module = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(module)


def fixture_frontend(tmp_path: Path) -> Path:
    tmp_path.joinpath('package.json').write_text('{}')
    for rel, content in {
        'src/api/universal.ts': 'export const ENDPOINT = "/api/v1/analyze/object-resolution";\n'
                                'interface Report {\n  object_resolution?: ObjectResolution;\n}\n',
        'src/pages/UniversalAnalysis.tsx': 'import ObjectResolutionPanel from "../components/ObjectResolutionPanel";\n'
                                              'return (<ObjectResolutionPanel analysis={report.object_resolution} />);',
        'src/utils/normalizedPdf.ts': 'const COLORS = { navy: "#000", muted: "#999" };\n'
                                      '  section("Assessment coverage");\n',
    }.items():
        dest = tmp_path / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(content)
    return tmp_path


def test_frontend_installs_once(tmp_path):
    app = fixture_frontend(tmp_path)
    changed = module.install(app)
    assert len(changed) == 5
    assert module.install(app) == []
    api = (app / 'src/api/universal.ts').read_text()
    assert '/api/v1/analyze/object-assurance' in api
    assert api.count('  object_assurance?: ObjectAssurance;') == 1
    pdf = (app / 'src/utils/normalizedPdf.ts').read_text()
    assert pdf.count('section("Object reference integrity")') == 1
    assert (app / 'src/api/universal.ts.before_api0106.bak').is_file()


def test_frontend_refuses_missing_pdf_anchor(tmp_path):
    app = fixture_frontend(tmp_path)
    (app / 'src/utils/normalizedPdf.ts').write_text('broken')
    with pytest.raises(ValueError):
        module.install(app)
    assert '/api/v1/analyze/object-resolution' in (app / 'src/api/universal.ts').read_text()
    assert not (app / 'src/components/ObjectAssurancePanel.tsx').exists()


def test_does_not_modify_sidebar(tmp_path):
    app = fixture_frontend(tmp_path)
    sidebar = app / 'src/components/layout/Sidebar.css'
    sidebar.parent.mkdir(parents=True, exist_ok=True)
    sidebar.write_text('old sidebar unchanged')
    module.install(app)
    assert sidebar.read_text() == 'old sidebar unchanged'


def test_frontend_requires_react_directory(tmp_path):
    with pytest.raises(ValueError):
        module.install(tmp_path)
