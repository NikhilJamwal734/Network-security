"""Self-contained installation checks; does not depend on real user project."""
import importlib.util
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts' / 'merge_dashboard_and_universal.py'
spec = importlib.util.spec_from_file_location('merge_dashboard', SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class DashboardMergeTests(unittest.TestCase):
    def test_old_universal_nav_is_removed(self):
        source = (ROOT / 'frontend_checks' / 'app_api0097_sample.txt').read_text()
        updated = module.patch_app(source)
        self.assertNotIn('label: "Universal Analysis"', updated)
        self.assertIn('report={unifiedReport}', updated)
        self.assertIn('onLegacyASAReadyChange={setLegacyASAReady}', updated)
        self.assertIn('useState<PageName>("Dashboard")', updated)

    def test_asa_exports_are_hidden_for_non_asa(self):
        source = (ROOT / 'frontend_checks' / 'app_api0097_sample.txt').read_text()
        updated = module.patch_app(source)
        self.assertIn('unifiedReport?.platform.platform_id === "cisco_asa" && legacyASAReady', updated)
        self.assertIn('item.label === "Dashboard" ||', updated)
        self.assertIn('onReportChange={setUnifiedReport}', updated)

    def test_idempotent_and_fail_closed(self):
        source = (ROOT / 'frontend_checks' / 'app_api0097_sample.txt').read_text()
        once = module.patch_app(source)
        self.assertEqual(once, module.patch_app(once))
        with self.assertRaises(ValueError):
            module.patch_app('function App() { return null; }')

    def test_installer_creates_backups_without_altering_api_client(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for path in (
                'src/App.tsx', 'src/pages/UniversalAnalysis.tsx',
                'src/api/universal.ts', 'src/context/AnalysisContext.tsx',
                'src/components/SummaryCard.tsx',
                'src/components/ConfigurationSummary.tsx',
                'src/components/FirewallInfo.tsx',
                'src/components/SecurityScore.tsx',
                'src/components/SeverityChart.tsx',
            ):
                p = root / path
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text('original')
            (root / 'src/App.tsx').write_text((ROOT / 'frontend_checks/app_api0097_sample.txt').read_text())
            (root / 'src/pages/UniversalAnalysis.tsx').write_text('function UniversalAnalysis() {}')
            shutil.copytree(ROOT / 'api0097_merge', root / 'api0097_merge')
            first = subprocess.run([sys.executable, str(SCRIPT)], cwd=root, capture_output=True, text=True)
            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertIn('report={unifiedReport}', (root / 'src/App.tsx').read_text())
            self.assertTrue((root / 'src/App.tsx.before_unified_dashboard.backup').exists())
            self.assertEqual((root / 'src/api/universal.ts').read_text(), 'original')
            again = subprocess.run([sys.executable, str(SCRIPT)], cwd=root, capture_output=True, text=True)
            self.assertEqual(again.returncode, 0, again.stderr)
            self.assertIn('already merged', again.stdout)


if __name__ == '__main__':
    unittest.main()
