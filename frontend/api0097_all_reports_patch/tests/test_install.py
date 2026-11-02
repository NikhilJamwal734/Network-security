"""Patch installation smoke checks with the merged App sample bundled in this environment.
Run from the patch repository: python -m unittest discover -s tests -p 'test_install.py' -v
"""
import tempfile
import unittest
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from enable_multiplatform_reports import patch_app, FILES


class AppPatchTests(unittest.TestCase):
    def setUp(self):
        self.example = (ROOT / "tests/reference_merged_App.tsx").read_text(encoding="utf-8")

    def test_adds_generic_navigation_and_report_views(self):
        updated = patch_app(self.example)
        self.assertIn('item.label === "Coverage"', updated)
        self.assertIn('item.label === "Findings"', updated)
        self.assertIn('item.label === "Reports"', updated)
        self.assertIn("<NormalizedReportDownloads", updated)
        self.assertIn("<NormalizedFindingsPage", updated)
        self.assertIn("<NormalizedReportsPage", updated)
        self.assertIn("<NormalizedCoveragePage", updated)

    def test_keeps_legacy_asa_detail_components(self):
        updated = patch_app(self.example)
        for component in ('<FirewallRules />', '<NetworkObjects />', '<ServiceObjects />',
                          '<NATRules />', '<Routes />', '<Configuration />',
                          '<JsonReportDownload />', '<PdfReportDownload />'):
            self.assertIn(component, updated)

    def test_rerun_is_idempotent(self):
        once = patch_app(self.example)
        self.assertEqual(once, patch_app(once))

    def test_unrecognized_app_fails_closed(self):
        with self.assertRaises(ValueError):
            patch_app('function App() { return null; }')

    def test_all_declared_source_files_present(self):
        for name in FILES:
            self.assertTrue((ROOT / name).is_file(), name)


if __name__ == "__main__":
    unittest.main()
