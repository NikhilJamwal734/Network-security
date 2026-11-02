from __future__ import annotations

import importlib.util
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parents[1]
script = HERE / 'scripts/install_dashboard_cleanup.py'
spec = importlib.util.spec_from_file_location('dashboard_cleanup_installer', script)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

BASE = Path('/mnt/data/api0099_frontend_validation/frontend')
APP = Path('/mnt/data/API-009.7-All-Platform-Reports-PDF.zip')


class CleanupTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='dashboard-cleanup-')
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name) / 'frontend'
        self.frontend = root
        (root/'src/pages').mkdir(parents=True)
        (root/'src/components').mkdir(parents=True)
        (root/'src').mkdir(parents=True, exist_ok=True)
        (root/'package.json').write_text('{}', encoding='utf-8')
        (root/'src/pages/UniversalAnalysis.tsx').write_bytes((BASE/'src/pages/UniversalAnalysis.tsx').read_bytes())
        (root/'src/App.tsx').write_text('import "./index.css";\nimport "./AppResponsive.css";\nfunction App() {return null;}\nexport default App;\n', encoding='utf-8')
        import zipfile
        with zipfile.ZipFile('/mnt/data/API-009.8-Four-Platform-Assessment.zip') as z:
            txt = z.read('frontend_patch/src/components/AdvancedAssessmentPanel.tsx')
        (root/'src/components/AdvancedAssessmentPanel.tsx').write_bytes(txt)
        self.original_page = (root/'src/pages/UniversalAnalysis.tsx').read_text()

    def activate(self):
        with patch.object(module, 'FRONTEND', self.frontend):
            return module.install()

    def test_removes_optional_panel_without_erasing_findings(self):
        self.activate()
        page = (self.frontend/'src/pages/UniversalAnalysis.tsx').read_text()
        self.assertNotIn('IDSRuleBundlePanel', page)
        self.assertNotIn('NORMALIZED REPORT · SCHEMA', page)
        self.assertIn('Security findings', page)
        self.assertIn('Analysis coverage', page)
        self.assertIn('ua-download-ready', page)
        self.assertIn('Analyze configuration', page)

    def test_assessment_label_and_export_style(self):
        self.activate()
        panel = (self.frontend/'src/components/AdvancedAssessmentPanel.tsx').read_text()
        self.assertNotIn('API-009.8 / FOUR-PLATFORM ASSESSMENT', panel)
        self.assertIn('SECURITY REVIEW', panel)
        self.assertIn('report', self.original_page)
        css = (self.frontend/'src/DashboardDownloadHighlight.css').read_text()
        self.assertIn('.fa-topbar-downloads', css)
        self.assertIn('.normalized-downloads', css)
        self.assertIn('#dc2626', css)
        app = (self.frontend/'src/App.tsx').read_text()
        self.assertEqual(app.count('import "./DashboardDownloadHighlight.css";'), 1)

    def test_repeat_install_is_idempotent(self):
        self.activate()
        first = {p: p.read_bytes() for p in [self.frontend/'src/App.tsx', self.frontend/'src/pages/UniversalAnalysis.tsx', self.frontend/'src/components/AdvancedAssessmentPanel.tsx']}
        self.activate()
        for p, data in first.items():
            self.assertEqual(p.read_bytes(), data)
            self.assertTrue(p.with_name(p.name + '.before_dashboard_cleanup.bak').exists())

    def test_partial_widget_rejected_and_files_untouched(self):
        page = self.frontend/'src/pages/UniversalAnalysis.tsx'
        text = page.read_text()
        page.write_text(text.replace('import IDSRuleBundlePanel from "../components/IDSRuleBundlePanel";\n', ''), encoding='utf-8')
        app = (self.frontend/'src/App.tsx').read_bytes()
        with self.assertRaisesRegex(ValueError, 'partially modified'):
            self.activate()
        self.assertEqual((self.frontend/'src/App.tsx').read_bytes(), app)
        self.assertFalse((self.frontend/'src/DashboardDownloadHighlight.css').exists())

    def test_no_widget_already_present(self):
        page = self.frontend/'src/pages/UniversalAnalysis.tsx'
        text = page.read_text()
        text = text.replace('import IDSRuleBundlePanel from "../components/IDSRuleBundlePanel";\n','')
        text = text.replace('          <IDSRuleBundlePanel platformId={report.platform.platform_id} configurationFile={file} />\n', '')
        page.write_text(text, encoding='utf-8')
        self.activate()
        self.assertIn('ua-download-ready', page.read_text())


if __name__ == '__main__':
    unittest.main()
