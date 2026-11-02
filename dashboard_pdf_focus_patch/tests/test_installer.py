from __future__ import annotations
import importlib.util
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts' / 'install_dashboard_pdf_focus.py'
spec = importlib.util.spec_from_file_location('dashboard_pdf_focus_installer', SCRIPT)
assert spec and spec.loader
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
DATA = Path(__file__).resolve().parent / 'fixtures'


def fixture_dashboard() -> str:
    return (DATA / 'UniversalAnalysis.baseline.tsx').read_text(encoding='utf-8')


def fixture_pdf() -> str:
    return (DATA / 'normalizedPdf.baseline.ts').read_text(encoding='utf-8')


class PatchTests(unittest.TestCase):
    def test_dashboard_preview_and_no_verbose_content(self):
        original = fixture_dashboard()
        updated = mod.patch_dashboard(original)
        self.assertIn('ExecutiveDashboardSummary', updated)
        self.assertIn('onReportChange(next)', updated)
        self.assertIn('analyzeLegacyASA(file)', updated)
        self.assertNotIn('visibleFindings', updated)
        self.assertNotIn('setSeverityFilter', updated)
        self.assertNotIn('CiscoASAOverview', updated)
        self.assertNotIn('Export normalized JSON', updated)
        self.assertIn('return (', updated)
        self.assertIn('export default UniversalAnalysis;', updated)
        self.assertEqual(updated, mod.patch_dashboard(updated))

    def test_api0106_panels_removed_from_dashboard_only(self):
        source = fixture_dashboard()
        source = 'import ObjectAssurancePanel from "../components/ObjectAssurancePanel";\n' + source
        source = source.replace('<div className="ua-results" aria-live="polite">',
                                '<div className="ua-results" aria-live="polite">\n'
                                '          <ObjectAssurancePanel review={report.object_assurance} />', 1)
        updated = mod.patch_dashboard(source)
        self.assertNotIn('ObjectAssurancePanel', updated)
        self.assertIn('ExecutiveDashboardSummary', updated)

    def test_full_multi_stage_dashboard_compacts_without_unused_imports(self):
        source = fixture_dashboard()
        panels = (
            ('ReportQualityPanel', 'quality={report.quality}'),
            ('AdvancedAssessmentPanel', 'assessment={report.assessment}'),
            ('VendorDeepReviewPanel', 'review={report.vendor_review}'),
            ('RuleCorrelationPanel', 'review={report.rule_correlation}'),
            ('CorrelationAssurancePanel', 'assurance={report.correlation_assurance}'),
            ('ObjectResolutionPanel', 'analysis={report.object_resolution}'),
            ('ObjectAssurancePanel', 'review={report.object_assurance}'),
        )
        for name, props in panels:
            source = f'import {name} from "../components/{name}";\n' + source
            source = source.replace('<div className="ua-results" aria-live="polite">',
                                    '<div className="ua-results" aria-live="polite">'
                                    f'\n          <{name} {props} />', 1)
        updated = mod.patch_dashboard(source)
        for name, _ in panels:
            self.assertNotIn(name, updated, name)
        self.assertIn('ExecutiveDashboardSummary', updated)
        self.assertIn('getSupportedPlatforms', updated)
        self.assertIn('analyzeNormalized', updated)

    def test_pdf_has_definitions_and_no_dashboard_json_direction(self):
        original = fixture_pdf()
        updated = mod.patch_pdf(original)
        self.assertIn('section("How to read this assessment")', updated)
        self.assertIn('Missing from upload', updated)
        self.assertIn('Provisional review score', updated)
        self.assertNotIn('consult the dashboard', updated)
        self.assertNotIn('see JSON', updated)
        self.assertNotIn('Export JSON for the complete set.', updated)
        self.assertIn('pdf.getNumberOfPages()', updated)
        self.assertEqual(updated, mod.patch_pdf(updated))

    def test_install_twice_and_preserve_sidebar(self):
        with TemporaryDirectory() as tmp:
            frontend = Path(tmp) / 'frontend'
            (frontend / 'src/pages').mkdir(parents=True)
            (frontend / 'src/utils').mkdir(parents=True)
            (frontend / 'src/styles').mkdir(parents=True)
            (frontend / 'package.json').write_text('{}', encoding="utf-8")
            page = frontend / 'src/pages/UniversalAnalysis.tsx'
            pdf = frontend / 'src/utils/normalizedPdf.ts'
            sidebar = frontend / 'src/styles/Sidebar.css'
            page.write_text(fixture_dashboard(), encoding="utf-8")
            pdf.write_text(fixture_pdf(), encoding="utf-8")
            sidebar.write_text('original sidebar layout', encoding="utf-8")
            changes = mod.install(frontend)
            self.assertEqual(len(changes), 4)
            self.assertEqual(mod.install(frontend), [])
            self.assertEqual(sidebar.read_text(), 'original sidebar layout')
            self.assertTrue(page.exists())
            self.assertTrue((frontend / 'src/pages/UniversalAnalysis.tsx.before_dashboard_pdf_focus.bak').exists())
            self.assertTrue((frontend / 'src/utils/normalizedPdf.ts.before_dashboard_pdf_focus.bak').exists())
            self.assertTrue((frontend / 'src/components/ExecutiveDashboardSummary.tsx').exists())

    def test_bad_layout_fails_before_writing(self):
        with TemporaryDirectory() as tmp:
            frontend = Path(tmp) / 'frontend'
            (frontend / 'src/pages').mkdir(parents=True)
            (frontend / 'src/utils').mkdir(parents=True)
            (frontend / 'package.json').write_text('{}', encoding="utf-8")
            source = frontend / 'src/pages/UniversalAnalysis.tsx'
            source.write_text('unknown application', encoding="utf-8")
            (frontend / 'src/utils/normalizedPdf.ts').write_text(fixture_pdf(), encoding="utf-8")
            with self.assertRaises(ValueError):
                mod.install(frontend)
            self.assertEqual(source.read_text(), 'unknown application')
            self.assertFalse((frontend / 'src/components/ExecutiveDashboardSummary.tsx').exists())


if __name__ == '__main__':
    unittest.main()
