from __future__ import annotations
import importlib.util
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / 'tests/fixtures'
SPEC = importlib.util.spec_from_file_location('selective_dashboard', ROOT / 'scripts/install_selective_dashboard.py')
assert SPEC and SPEC.loader
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)


def original_dashboard() -> str:
    text = (FIX / 'UniversalAnalysis.baseline.tsx').read_text(encoding='utf-8')
    for name, props in (
        ('AdvancedAssessmentPanel', 'assessment={report.assessment}'),
        ('VendorDeepReviewPanel', 'review={report.vendor_review}'),
        ('RuleCorrelationPanel', 'review={report.rule_correlation}'),
        ('CorrelationAssurancePanel', 'assurance={report.correlation_assurance}'),
    ):
        text = f'import {name} from "../components/{name}";\n' + text
        text = text.replace('<div className="ua-results" aria-live="polite">',
                            '<div className="ua-results" aria-live="polite">'
                            f'\n          <{name} {props} />', 1)
    return text


def mkfrontend(base: Path, compact: bool = True, backup: bool = True) -> tuple[Path, Path]:
    frontend = base / 'frontend'
    (frontend / 'src/pages').mkdir(parents=True)
    (frontend / 'src/components').mkdir(parents=True)
    (frontend / 'src/utils').mkdir(parents=True)
    (frontend / 'src/styles').mkdir(parents=True)
    (frontend / 'package.json').write_text('{}', encoding='utf-8')
    page = frontend / 'src/pages/UniversalAnalysis.tsx'
    original = original_dashboard()
    if compact:
        # Mimic only the latest dashboard replacement: original in the backup.
        current = original[:original.index('      {report && (')]
        current += '''      {report && (
        <div className="ua-results" aria-live="polite">
          <ExecutiveDashboardSummary report={report} filename={file?.name ?? "config"} />
        </div>
      )}
    </div>
  );
}
export default UniversalAnalysis;
'''
        current = 'import ExecutiveDashboardSummary from "../components/ExecutiveDashboardSummary";\n' + current
    else:
        current = original
    page.write_text(current, encoding='utf-8')
    if backup:
        (page.parent / (page.name + '.before_dashboard_pdf_focus.bak')).write_text(original, encoding='utf-8')
    for name in mod.PANELS:
        (frontend / 'src/components' / name).write_bytes((FIX / name).read_bytes())
    (frontend / 'src/utils/normalizedPdf.ts').write_text('formal pdf intact', encoding='utf-8')
    (frontend / 'src/styles/Sidebar.css').write_text('original sidebar intact', encoding='utf-8')
    return frontend, page


class Tests(unittest.TestCase):
    def test_restore_original_and_only_four_panels(self):
        with TemporaryDirectory() as folder:
            frontend, page = mkfrontend(Path(folder))
            changed, notes = mod.install(frontend)
            self.assertEqual(len(changed), 5)
            self.assertEqual(page.read_text(encoding='utf-8'), original_dashboard())
            self.assertIn('Original Dashboard', ''.join(notes) + 'Original Dashboard')
            for name in mod.PANELS:
                src = (frontend / 'src/components' / name).read_text(encoding='utf-8')
                self.assertIn('data-dashboard-snippet=', src)
                self.assertIn('.slice(0, 2)', src)
            self.assertEqual((frontend / 'src/utils/normalizedPdf.ts').read_text(), 'formal pdf intact')
            self.assertEqual((frontend / 'src/styles/Sidebar.css').read_text(), 'original sidebar intact')
            self.assertTrue((page.parent / (page.name + mod.BACKUP_SUFFIX)).is_file())
            self.assertEqual(mod.install(frontend)[0], [])

    def test_existing_original_dashboard_not_rewritten(self):
        with TemporaryDirectory() as folder:
            frontend, page = mkfrontend(Path(folder), compact=False, backup=False)
            original = page.read_bytes()
            changed, _ = mod.install(frontend)
            self.assertNotIn('src/pages/UniversalAnalysis.tsx', changed)
            self.assertEqual(page.read_bytes(), original)
            self.assertEqual(len(changed), 4)

    def test_missing_backup_safely_refuses(self):
        with TemporaryDirectory() as folder:
            frontend, page = mkfrontend(Path(folder), backup=False)
            current = page.read_bytes()
            with self.assertRaisesRegex(ValueError, 'backup'):
                mod.install(frontend)
            self.assertEqual(page.read_bytes(), current)
            self.assertFalse((page.parent / (page.name + mod.BACKUP_SUFFIX)).exists())

    def test_unknown_panel_layout_no_partial_changes(self):
        with TemporaryDirectory() as folder:
            frontend, page = mkfrontend(Path(folder))
            target = frontend / 'src/components/RuleCorrelationPanel.tsx'
            target.write_text('unrecognized layout', encoding='utf-8')
            before = page.read_bytes()
            with self.assertRaisesRegex(ValueError, 'RuleCorrelationPanel'):
                mod.install(frontend)
            self.assertEqual(page.read_bytes(), before)
            self.assertEqual(target.read_text(encoding='utf-8'), 'unrecognized layout')
            self.assertFalse((page.parent / (page.name + mod.BACKUP_SUFFIX)).exists())

    def test_preserves_score_explanation(self):
        src = (FIX / 'AdvancedAssessmentPanel.tsx').read_text(encoding='utf-8')
        src = src.replace('import type { AdvancedAssessment }',
                          'import { ReviewScoreExplanation } from "./AssessmentInterpretation";\nimport type { AdvancedAssessment }')
        anchor = '<small>Maximum {score.maximum}/100 while coverage is incomplete</small>'
        src = src.replace(anchor, anchor + '\n<ReviewScoreExplanation maximum={score.maximum} capped={score.capped_for_incomplete_coverage} />')
        edited = mod.summarize_advanced(src)
        self.assertIn('<ReviewScoreExplanation', edited)
        self.assertNotIn('check.detail', edited)
        self.assertIn('Configuration review evidence', edited)
        self.assertEqual(mod.summarize_advanced(edited), edited)

    def test_no_ui_recommendations_or_full_findings(self):
        for name, fn in mod.TRANSFORMS.items():
            original = (FIX / name).read_text(encoding='utf-8')
            updated = fn(original)
            self.assertNotIn('check.recommendation', updated)
            self.assertNotIn('item.recommendation', updated)
            self.assertNotIn('item.explanation', updated)
            self.assertIn('PDF', updated)
            self.assertEqual(fn(updated), updated)

    def test_utf8_non_ascii_fixture_handled(self):
        with TemporaryDirectory() as folder:
            frontend, _ = mkfrontend(Path(folder))
            component = frontend / 'src/components/VendorDeepReviewPanel.tsx'
            src = component.read_text(encoding='utf-8') + '\n// Reporting detail · use the PDF\n'
            component.write_text(src, encoding='utf-8')
            changes, _ = mod.install(frontend)
            self.assertEqual(len(changes), 5)
            self.assertIn('Reporting detail ·', component.read_text(encoding='utf-8'))


if __name__ == '__main__':
    unittest.main()
