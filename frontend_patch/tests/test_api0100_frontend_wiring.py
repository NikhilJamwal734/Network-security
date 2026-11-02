"""Run explicitly: python -m pytest -q frontend_patch/tests/test_api0100_frontend_wiring.py"""
import importlib.util
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/install_api_010_0_frontend.py"
SPEC = importlib.util.spec_from_file_location("api0100_frontend_install", SCRIPT)
install_module = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(install_module)


@pytest.fixture
def frontend(tmp_path, monkeypatch):
    root = tmp_path / "frontend"
    (root / "src/api").mkdir(parents=True)
    (root / "src/pages").mkdir(parents=True)
    (root / "package.json").write_text('{"name":"demo"}', encoding="utf-8")
    (root / "src/api/universal.ts").write_text('''export interface NormalizedReport {
  schema_version: string;
}
const endpoint = "/api/v1/analyze/assessment";
''', encoding="utf-8")
    (root / "src/pages/UniversalAnalysis.tsx").write_text('''import "./UniversalAnalysis.css";
export function Example({ report }: { report: any }) {
  return <div className="ua-results" aria-live="polite">{report.platform.platform_id}</div>;
}
''', encoding="utf-8")
    monkeypatch.setattr(install_module, "FRONTEND", root)
    return root


def test_frontend_install_and_idempotency(frontend):
    first = install_module.install()
    assert len(first) == 4
    assert all("Updated" in x for x in first)
    assert '/api/v1/analyze/validated' in (frontend / 'src/api/universal.ts').read_text()
    assert '<ReportQualityPanel quality={report.quality} />' in (frontend / 'src/pages/UniversalAnalysis.tsx').read_text()
    second = install_module.install()
    assert all('Unchanged' in x for x in second)


def test_existing_files_backed_up(frontend):
    original = (frontend / 'src/api/universal.ts').read_bytes()
    install_module.install()
    assert (frontend / 'src/api/universal.ts.before_api0100.bak').read_bytes() == original
    assert (frontend / 'src/pages/UniversalAnalysis.tsx.before_api0100.bak').is_file()


def test_unknown_layout_refuses_partial_install(frontend):
    (frontend / 'src/pages/UniversalAnalysis.tsx').write_text('custom dashboard')
    before = (frontend / 'src/api/universal.ts').read_bytes()
    with pytest.raises(RuntimeError):
        install_module.install()
    assert (frontend / 'src/api/universal.ts').read_bytes() == before


def test_no_duplicate_anchors(frontend):
    install_module.install()
    install_module.install()
    page = (frontend / 'src/pages/UniversalAnalysis.tsx').read_text()
    api = (frontend / 'src/api/universal.ts').read_text()
    assert page.count('<ReportQualityPanel quality={report.quality} />') == 1
    assert api.count('quality?: ReportQuality;') == 1
