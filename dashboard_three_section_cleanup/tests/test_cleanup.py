from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts' / 'install_dashboard_section_cleanup.py'
spec = importlib.util.spec_from_file_location('three_sections', SCRIPT)
assert spec and spec.loader
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)

PAGE_TEXT = '''import PdfExportReadinessSnippet from "../components/PdfExportReadinessSnippet";
import PipelineValidationSnippet from "../components/PipelineValidationSnippet";
import ReportValidationSnippet from "../components/ReportValidationSnippet";
export default function Main({report}) {
 return <main>
    <ReportValidationSnippet review={report.report_validation_review} />
    <PdfExportReadinessSnippet review={report.pdf_export_review} />
    <PipelineValidationSnippet review={report.pipeline_validation_review} />
    <p>Security metrics and severity distribution</p>
 </main>;
}
'''

PANEL_COMPACT = '''import type { AdvancedAssessment } from "../api/universal";
function label(v: string) { return v; }
export default function AdvancedAssessmentPanel({assessment}) {
  if (!assessment) return null;
  const { review_score: score, observations, coverage_review: coverage } = assessment;
  return (
    <section className="ua-panel advanced-assessment">
      <h2>Configuration review</h2>
      <div className="advanced-assessment-metrics"><strong>{score.value}</strong><strong>{coverage.assessed_domain_count}</strong></div>
      <div data-dashboard-snippet="configuration-evidence">
        <h3>Configuration review evidence</h3>
        <p>{observations.length} evidence observations</p>
        <div className="advanced-assessment-observations">
          {observations.slice(0,2).map((check) => (
             <div className="advanced-assessment-observation" key={check.code}>
               <strong>{check.title}</strong>
               <div><span>{label(check.status)}</span></div>
             </div>
          ))}
        </div>
        <p>See PDF for details</p>
      </div>
    </section>
  );
}
'''


def setup(root: Path, panel: str = PANEL_COMPACT, page: str = PAGE_TEXT, windows=False):
    values = {
        'package.json': '{"name":"frontend"}\n',
        'src/pages/UniversalAnalysis.tsx': page,
        'src/components/AdvancedAssessmentPanel.tsx': panel,
        'src/utils/normalizedPdf.ts': 'section("Assessment coverage"); // full evidence lives in PDF\n',
        'src/api/universal.ts': 'const API="/api/v1/analyze/pipeline-validation";\n',
        'src/pages/Findings.tsx': 'export default function Findings() {return null}\n',
    }
    for rel, val in values.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        if windows:
            data = b'\xef\xbb\xbf' + val.replace('\n', '\r\n').encode()
        else:
            data = val.encode()
        path.write_bytes(data)


class CleanupTests(unittest.TestCase):
    def test_precisely_removes_three_sections(self):
        with TemporaryDirectory() as temp:
            root = Path(temp); setup(root)
            changes, details = mod.plan(root)
            self.assertEqual(len(changes), 2)
            mod.install(root)
            page = (root / mod.PAGE).read_text(encoding='utf-8')
            panel = (root / mod.REVIEW).read_text(encoding='utf-8')
            for x in ('PdfExportReadinessSnippet', 'PipelineValidationSnippet', 'configuration-evidence', 'Configuration review evidence'):
                self.assertNotIn(x, page + panel)
            for x in ('ReportValidationSnippet', 'Security metrics', 'Configuration review', 'advanced-assessment-metrics', 'coverage.assessed_domain_count'):
                self.assertIn(x, page + panel)
            self.assertNotIn('observations', panel)

    def test_backend_and_pdf_and_findings_unchanged(self):
        with TemporaryDirectory() as temp:
            root = Path(temp); setup(root)
            protected = [root/'src/utils/normalizedPdf.ts', root/'src/api/universal.ts', root/'src/pages/Findings.tsx']
            snapshots = {p:p.read_bytes() for p in protected}
            mod.install(root)
            self.assertEqual({p:p.read_bytes() for p in protected}, snapshots)

    def test_dry_run_no_writes(self):
        with TemporaryDirectory() as temp:
            root = Path(temp); setup(root)
            originals = [(root/x).read_bytes() for x in (mod.PAGE, mod.REVIEW)]
            message = mod.install(root, dry_run=True)
            self.assertTrue(message and '[preview]' in message[0])
            self.assertEqual(originals, [(root/x).read_bytes() for x in (mod.PAGE, mod.REVIEW)])
            self.assertFalse((root/mod.MANIFEST_NAME).exists())

    def test_idempotent_and_rollback(self):
        with TemporaryDirectory() as temp:
            root = Path(temp); setup(root)
            originals = {x:(root/x).read_bytes() for x in (mod.PAGE, mod.REVIEW)}
            self.assertEqual(len(mod.install(root)), 2)
            self.assertIn('Already installed',mod.install(root)[0])
            self.assertEqual(len(mod.rollback(root)), 2)
            for name, before in originals.items():
                self.assertEqual((root/name).read_bytes(), before)
            self.assertFalse((root/mod.MANIFEST_NAME).exists())

    def test_windows_bom_crlf(self):
        with TemporaryDirectory() as temp:
            root = Path(temp); setup(root, windows=True)
            mod.install(root)
            for x in (mod.PAGE, mod.REVIEW):
                b = (root/x).read_bytes()
                self.assertTrue(b.startswith(b'\xef\xbb\xbf'))
                self.assertIn(b'\r\n', b)
                self.assertNotIn(b'\n', b.replace(b'\r\n', b''))

    def test_invalid_encoding_blocks_every_change(self):
        with TemporaryDirectory() as temp:
            root=Path(temp); setup(root)
            (root/mod.REVIEW).write_bytes(b'\x97 invalid')
            before=(root/mod.PAGE).read_bytes()
            with self.assertRaisesRegex(ValueError, 'invalid UTF-8'):
                mod.install(root)
            self.assertEqual(before,(root/mod.PAGE).read_bytes())

    def test_missing_import_fails_closed(self):
        with TemporaryDirectory() as temp:
            root=Path(temp); setup(root,page=PAGE_TEXT.replace('import PipelineValidationSnippet from "../components/PipelineValidationSnippet";\n',''))
            before=(root/mod.PAGE).read_bytes()
            with self.assertRaisesRegex(ValueError, 'missing expected'):
                mod.install(root)
            self.assertEqual(before,(root/mod.PAGE).read_bytes())

    def test_rollback_refuses_later_modification(self):
        with TemporaryDirectory() as temp:
            root=Path(temp); setup(root)
            mod.install(root)
            path = root/mod.PAGE
            path.write_bytes(path.read_bytes()+b'// future edit\n')
            with self.assertRaisesRegex(ValueError, 'modified after cleanup'):
                mod.rollback(root)
            self.assertTrue(path.read_bytes().endswith(b'// future edit\n'))

    def test_real_legacy_review_evidence(self):
        with TemporaryDirectory() as temp:
            root=Path(temp)
            old=(ROOT/'tests/AdvancedAssessmentPanel.tsx').read_text(encoding='utf-8')
            setup(root,panel=old)
            mod.install(root)
            modified=(root/mod.REVIEW).read_text(encoding='utf-8')
            self.assertNotIn('Visible configuration evidence', modified)
            self.assertNotIn('observations.map', modified)
            self.assertIn('<h3>Not assessed</h3>', modified)
            self.assertIn('<h2 id="advanced-assessment-heading">Configuration review</h2>', modified)

    def test_existing_target_removed_is_no_op(self):
        with TemporaryDirectory() as temp:
            root=Path(temp); setup(root)
            mod.install(root)
            (root/mod.MANIFEST_NAME).unlink()
            self.assertIn('No targeted',mod.install(root)[0])


if __name__ == '__main__':
    unittest.main()
