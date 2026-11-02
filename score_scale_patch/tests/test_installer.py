"""Run with: python -m unittest discover -s score_scale_patch/tests -v"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path
import unittest
import zipfile

PACKAGE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PACKAGE / "scripts"))
from install_score_explanations import install

ROOT = Path(__file__).resolve().parents[2]


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory()
        self.addCleanup(self.work.cleanup)
        self.frontend = Path(self.work.name)
        (self.frontend / "package.json").write_text('{"name":"frontend"}', encoding="utf-8")
        fixtures = (
            ("API-009.8-Four-Platform-Assessment.zip", "frontend_patch/src/components/AdvancedAssessmentPanel.tsx", "src/components/AdvancedAssessmentPanel.tsx"),
            ("API-009.7-Universal-Severity-Chart.zip", "api0097_severity_upgrade/components/UniversalSeverityChart.tsx", "src/components/UniversalSeverityChart.tsx"),
            ("Professional-Security-PDF-Report.zip", "professional_pdf_patch/frontend_patch/src/utils/normalizedPdf.ts", "src/utils/normalizedPdf.ts"),
        )
        for zname, source, dest in fixtures:
            with zipfile.ZipFile(ROOT / zname) as z:
                content = z.read(source)
            output = self.frontend / dest
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(content)

    def test_installs_explanations_in_all_three_views(self):
        result = install(self.frontend)
        self.assertEqual(len(result), 5)
        score = (self.frontend / "src/components/AdvancedAssessmentPanel.tsx").read_text()
        sev = (self.frontend / "src/components/UniversalSeverityChart.tsx").read_text()
        pdf = (self.frontend / "src/utils/normalizedPdf.ts").read_text()
        self.assertIn('capped={score.capped_for_incomplete_coverage}', score)
        self.assertIn('<SeverityExplanation />', sev)
        self.assertIn('Review score (0-100):', pdf)
        self.assertIn('Unknown is unclassified', pdf)
        self.assertIn('function downloadNormalizedJson', pdf)  # no API changes

    def test_idempotent(self):
        install(self.frontend)
        before = (self.frontend / "src/utils/normalizedPdf.ts").read_bytes()
        self.assertEqual(install(self.frontend), [])
        self.assertEqual(before, (self.frontend / "src/utils/normalizedPdf.ts").read_bytes())

    def test_unknown_layout_aborts_before_writing(self):
        path = self.frontend / "src/components/UniversalSeverityChart.tsx"
        path.write_text('export default function Unknown() {}', encoding="utf-8")
        original = (self.frontend / "src/components/AdvancedAssessmentPanel.tsx").read_bytes()
        with self.assertRaisesRegex(ValueError, 'Unrecognized universal'):
            install(self.frontend)
        self.assertEqual(original, (self.frontend / "src/components/AdvancedAssessmentPanel.tsx").read_bytes())

    def test_cleansed_heading_still_installs(self):
        panel = self.frontend / "src/components/AdvancedAssessmentPanel.tsx"
        panel.write_text(panel.read_text().replace('API-009.8 / FOUR-PLATFORM ASSESSMENT', 'SECURITY REVIEW'))
        self.assertEqual(len(install(self.frontend)), 5)


if __name__ == '__main__':
    unittest.main()
