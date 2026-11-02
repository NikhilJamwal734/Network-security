"""Run: python -m unittest discover -s frontend_checks -p "check_*.py" -v"""
import importlib.util
from pathlib import Path
import unittest

MODULE = Path(__file__).resolve().parents[1] / 'scripts' / 'wire_api_009_7_frontend.py'
SPEC = importlib.util.spec_from_file_location('api0097_patch', MODULE)
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class FrontendWiringTests(unittest.TestCase):
    def setUp(self):
        self.sample = (Path(__file__).resolve().parents[1] / 'frontend_checks' / 'app_api0084_sample.txt').read_text(encoding='utf-8')

    def test_adds_universal_route_and_preserves_legacy_dashboard(self):
        result = module.patch_app(self.sample)
        self.assertIn('<UniversalAnalysis />', result)
        self.assertIn('<Dashboard />', result)
        self.assertIn('useState<PageName>("Universal Analysis")', result)
        self.assertIn('activePage !== "Universal Analysis"', result)
        self.assertIn('<PdfReportDownload />', result)

    def test_idempotent(self):
        result = module.patch_app(self.sample)
        self.assertEqual(module.patch_app(result), result)

    def test_refuses_missing_anchor_without_changes(self):
        with self.assertRaises(ValueError):
            module.patch_app(self.sample.replace('const Dashboard = lazy', 'const DashboardWidget = lazy'))

    def test_refuses_partial_wiring(self):
        with self.assertRaises(ValueError):
            module.patch_app(self.sample + '\nconst UniversalAnalysis = lazy(() => import("./pages/UniversalAnalysis"));')


if __name__ == '__main__':
    unittest.main()
