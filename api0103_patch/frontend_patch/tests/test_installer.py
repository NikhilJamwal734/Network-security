from __future__ import annotations
from pathlib import Path
import importlib.util
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts' / 'install_api_010_3_frontend.py'
spec = importlib.util.spec_from_file_location('api0103_frontend_installer', SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class FrontendInstallerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / 'frontend'
        (self.root / 'src/api').mkdir(parents=True)
        (self.root / 'src/pages').mkdir(parents=True)
        (self.root / 'src/utils').mkdir(parents=True)
        (self.root / 'src/styles').mkdir(parents=True)
        (self.root / 'package.json').write_text('{}')
        self.api = self.root / 'src/api/universal.ts'
        self.page = self.root / 'src/pages/UniversalAnalysis.tsx'
        self.pdf = self.root / 'src/utils/normalizedPdf.ts'
        self.sidebar = self.root / 'src/styles/SidebarGreen.css'
        self.api.write_text('export interface NormalizedReport {\n  vendor_review?: VendorReview;\n}\n'
                            'export interface VendorReview { checks: unknown[] }\n'
                            'const url = "/api/v1/analyze/precision-review";\n')
        self.page.write_text('import VendorDeepReviewPanel from "../components/VendorDeepReviewPanel";\n'
                             'import "./UniversalAnalysis.css";\n'
                             'function View({report}: {report: any}) {\n'
                             'return <div><VendorDeepReviewPanel review={report.vendor_review} /></div>\n}\n')
        self.pdf.write_text('const COLORS = {muted: 1, navy: 2};\n'
                            'function text(a: string, b: any) { return [a,b]; }\n'
                            'function section(a: string) { return a; }\n'
                            'function ensure(a: number) { return a; }\n'
                            'function run(report: any) {\n'
                            '  section("Assessment coverage");\n}\n')
        self.sidebar.write_text('/* User restored colors */')

    def test_install_idempotent_and_keeps_sidebar(self):
        first = module.install(self.root)
        self.assertEqual(len(first), 5)
        self.assertEqual(module.install(self.root), [])
        self.assertIn('/api/v1/analyze/rule-correlation', self.api.read_text())
        self.assertIn('rule_correlation?: RuleCorrelation;', self.api.read_text())
        self.assertEqual(self.page.read_text().count('<RuleCorrelationPanel review='), 1)
        self.assertIn('section("Rule correlation and conflict review")', self.pdf.read_text())
        self.assertEqual(self.sidebar.read_text(), '/* User restored colors */')
        self.assertTrue(Path(str(self.api) + module.BACKUP).exists())

    def test_unfamiliar_layout_refuses_before_modification(self):
        self.page.write_text('unknown')
        old_api = self.api.read_bytes()
        with self.assertRaisesRegex(ValueError, 'Unknown'):
            module.install(self.root)
        self.assertEqual(old_api, self.api.read_bytes())
        self.assertFalse(Path(str(self.api) + module.BACKUP).exists())

    def test_missing_package_file_refuses(self):
        (self.root / 'package.json').unlink()
        with self.assertRaisesRegex(ValueError, 'package.json'):
            module.install(self.root)

    def test_only_adds_advisory_interface(self):
        module.install(self.root)
        txt = self.api.read_text()
        self.assertIn('confidence: "conditional" | "informational";', txt)
        self.assertIn('status: "limited" | "reviewed_subset";', txt)
        self.assertNotIn('SidebarGreen', self.page.read_text())


if __name__ == '__main__':
    unittest.main()
