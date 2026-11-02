"""Integration checks for the known API-009.7 merged dashboard variants."""
from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

PATCH_ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('install_unified_pdf', PATCH_ROOT / 'scripts/install_unified_pdf.py')
module = importlib.util.module_from_spec(spec)
assert spec and spec.loader
sys.modules[spec.name] = module
spec.loader.exec_module(module)
SOURCE = PATCH_ROOT / 'tests' / 'fixtures' / 'merged_App.tsx'

def fixture_app():
    return SOURCE.read_text(encoding="utf-8")

class InstallerTest(unittest.TestCase):
    def test_all_platforms_share_one_pdf_exporter(self):
        output = module.patch_app(fixture_app())
        self.assertIn('One PDF renderer for Cisco ASA, FortiOS, Snort and Suricata', output)
        self.assertNotIn('<PdfReportDownload', output)
        self.assertNotIn('<JsonReportDownload', output)
        self.assertNotIn('<Reports />', output)
        self.assertEqual(output.count('<NormalizedReportDownloads'), 1)
        self.assertEqual(output.count('<NormalizedReportsPage'), 1)
        self.assertNotIn('const Reports = lazy(', output)
        self.assertIn('activePage === "Reports" && unifiedReport', output)

    def test_idempotent(self):
        once = module.patch_app(fixture_app())
        twice = module.patch_app(once)
        self.assertEqual(once, twice)

    def test_ignores_asa_branch_when_missing(self):
        original = fixture_app().replace('className="topbar-right"', 'className="different-layout"')
        with self.assertRaisesRegex(ValueError, 'topbar'):
            module.patch_app(original)

    def test_complete_install_and_backup(self):
        old_frontend = module.FRONTEND
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            module.FRONTEND = root
            try:
                (root/'package.json').write_text('{}')
                for rel, content in {
                    'src/App.tsx': fixture_app(),
                    'src/pages/NormalizedReportsPage.tsx': 'export default function NormalizedReportsPage() { return null; }',
                    'src/utils/normalizedPdf.ts': 'export function renderNormalizedPdf() {}\nexport function downloadNormalizedPdf() {}\nsection("Executive summary"); section("Findings register"); section("Finding details and recommendations");',
                    'src/components/NormalizedReportDownloads.tsx': 'export default function NormalizedReportDownloads(){}',
                    'src/components/NormalizedReportDownloads.css': '.normalized-downloads {}',
                }.items():
                    target=root/rel
                    target.parent.mkdir(parents=True,exist_ok=True)
                    target.write_text(content)
                updates=module.install()
                self.assertGreaterEqual(len(updates),3)
                self.assertTrue((root/'src/App.tsx.before_unified_formal_pdf.bak').is_file())
                self.assertEqual(module.install(), ['Already installed: unified PDF report format'])
            finally:
                module.FRONTEND=old_frontend

    def test_pdf_only_variant(self):
        app = fixture_app().replace('import JsonReportDownload from "./components/JsonReportDownload";\n', '').replace('                <JsonReportDownload />\n', '')
        patched = module.patch_app(app)
        self.assertNotIn('PdfReportDownload', patched)
        self.assertNotIn('JsonReportDownload', patched)
        self.assertIn('NormalizedReportDownloads', patched)

    def test_zero_changes_to_report_data(self):
        patched = module.patch_app(fixture_app())
        self.assertIn('const [unifiedReport, setUnifiedReport]', patched)
        self.assertIn('onReportChange={setUnifiedReport}', patched)
        self.assertIn('<NormalizedReportsPage', patched)
        self.assertEqual(patched.count('activePage === "Reports"'), 1)

    def test_invalid_app_does_not_overwrite(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            old_frontend=module.FRONTEND
            module.FRONTEND=root
            try:
                for rel, content in {
                    'package.json':'{}',
                    'src/App.tsx':'invalid app source',
                    'src/pages/NormalizedReportsPage.tsx':'function NormalizedReportsPage(){}',
                    'src/utils/normalizedPdf.ts':'renderNormalizedPdf(); downloadNormalizedPdf();',
                    'src/components/NormalizedReportDownloads.tsx':'component',
                    'src/components/NormalizedReportDownloads.css':'css',
                }.items():
                    path=root/rel;path.parent.mkdir(parents=True,exist_ok=True);path.write_text(content)
                with self.assertRaises(ValueError):
                    module.install()
                self.assertEqual((root/'src/App.tsx').read_text(), 'invalid app source')
                self.assertFalse(list(root.rglob('*.bak')))
            finally:
                module.FRONTEND=old_frontend

if __name__ == '__main__': unittest.main()
