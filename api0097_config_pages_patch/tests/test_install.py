import importlib.util
import unittest
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('installer', PACKAGE / 'scripts/install_configuration_pages.py')
module = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(module)

class InstallerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        patch = Path('/mnt/data/api0097_all_reports_patch')
        import sys
        sys.path.insert(0, str(patch / 'scripts'))
        from enable_multiplatform_reports import patch_app
        cls.app = patch_app((patch / 'tests/reference_merged_App.tsx').read_text())
        cls.universal = Path('/mnt/data/api0097_merge_work/api0097_merge/src/pages/UniversalAnalysis.tsx').read_text()

    def test_all_six_sections_available(self):
        out = module.patch_app(self.app)
        self.assertEqual(out.count('<PlatformConfigurationPage report='), 6)
        self.assertIn('.filter((item) => item.label === "Dashboard" || unifiedReport !== null)', out)

    def test_original_asa_views_remain(self):
        out = module.patch_app(self.app)
        for tag in ('<FirewallRules />','<NetworkObjects />','<ServiceObjects />','<NATRules />','<Routes />','<Configuration />'):
            self.assertIn(tag,out)
        self.assertIn('NormalizedReportsPage', out)

    def test_universal_upload_lifecycle(self):
        out = module.patch_universal(self.universal)
        self.assertIn('await getPlatformDetails(file, next.platform.platform_id', out)
        self.assertEqual(out.count('    onConfigurationChange(null);'), 3)
        self.assertIn('onConfigurationChange(details)', out)

    def test_idempotent(self):
        app = module.patch_app(self.app)
        universal = module.patch_universal(self.universal)
        self.assertEqual(app, module.patch_app(app))
        self.assertEqual(universal, module.patch_universal(universal))

    def test_unrecognized_layout_fails_closed(self):
        with self.assertRaises(ValueError): module.patch_app('function App() { return null; }')
        with self.assertRaises(ValueError): module.patch_universal('function UniversalAnalysis() {}')

if __name__ == '__main__': unittest.main()
