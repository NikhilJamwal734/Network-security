import importlib.util
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

PATCH = Path(__file__).resolve().parents[1]
FIXTURES = PATCH / 'tests/fixtures'
SPEC = importlib.util.spec_from_file_location('install_dashboard_findings_cleanup', PATCH/'scripts/install_dashboard_findings_cleanup.py')
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)


def fixture(name):
    return (FIXTURES/name).read_text(encoding='utf-8')


def make_project(root):
    frontend = root/'frontend'
    (frontend/'src/pages').mkdir(parents=True)
    (frontend/'package.json').write_text('{"name":"security-dashboard"}', encoding='utf-8')
    for n in ('UniversalAnalysis.tsx', 'Dashboard.tsx', 'Findings.tsx'):
        (frontend/'src/pages'/n).write_text(fixture(n), encoding='utf-8')
    (frontend/'src/utils').mkdir(parents=True)
    (frontend/'src/utils/normalizedPdf.ts').write_text('PDF FULL EVIDENCE', encoding='utf-8')
    return frontend


class CleanupTests(unittest.TestCase):
    def test_modern_removes_only_full_findings_panel(self):
        a = fixture('UniversalAnalysis.tsx')
        b = MOD.patch_modern(a)
        self.assertNotIn('<h2>Security findings</h2>', b)
        self.assertNotIn('visibleFindings', b)
        self.assertNotIn('severityFilter', b)
        self.assertNotIn('setSeverityFilter', b)
        for marker in ('<h2>Severity distribution</h2>', 'report.summary.total_findings',
                       'CiscoASAOverview', '<h2>Analysis coverage</h2>', '<h1>{TITLE}</h1>',
                       'Export normalized JSON', 'Parser warnings'):
            self.assertIn(marker, b)
        self.assertEqual(MOD.patch_modern(b), b)

    def test_stage_112_review_additions_survive(self):
        a = fixture('UniversalAnalysis.tsx')
        a = a.replace('<h2>Analysis coverage</h2>',
                      '<ReportValidationSnippet review={report.report_validation_review} />\n'
                      '            <h2>Analysis coverage</h2>')
        out = MOD.patch_modern(a)
        self.assertIn('<ReportValidationSnippet review={report.report_validation_review} />', out)
        self.assertEqual(out.count('ReportValidationSnippet'), 1)
        self.assertNotIn('<h2>Security findings</h2>', out)

    def test_legacy_preserves_kpis_charts_and_navigation_contract(self):
        a = fixture('Dashboard.tsx')
        b = MOD.patch_legacy(a)
        self.assertNotIn('<FindingsOverview', b)
        self.assertNotIn('import FindingsOverview', b)
        self.assertNotIn('className="panel findings-panel"', b)
        for marker in ('<FindingSummary', '<SeverityChart', '<SecurityScore',
                       '<ConfigurationSummary', '<FirewallInfo', 'onViewFindings: () => void'):
            self.assertIn(marker, b)
        self.assertEqual(MOD.patch_legacy(b), b)

    def test_installer_preserves_findings_page_pdf_and_is_idempotent(self):
        with TemporaryDirectory() as tmp:
            root = make_project(Path(tmp))
            findings = (root/'src/pages/Findings.tsx').read_bytes()
            pdf = (root/'src/utils/normalizedPdf.ts').read_bytes()
            first = MOD.install(root)
            self.assertEqual(sorted(str(item).replace('\\', '/') for item in first),
                             ['src/pages/Dashboard.tsx', 'src/pages/UniversalAnalysis.tsx'])
            self.assertEqual(MOD.install(root), [])
            self.assertEqual((root/'src/pages/Findings.tsx').read_bytes(), findings)
            self.assertEqual((root/'src/utils/normalizedPdf.ts').read_bytes(), pdf)
            for n in ('Dashboard.tsx','UniversalAnalysis.tsx'):
                self.assertTrue((root/'src/pages'/(n+MOD.BACKUP_SUFFIX)).exists())

    def test_crlf_and_utf8_bom_preserved(self):
        with TemporaryDirectory() as tmp:
            root = make_project(Path(tmp))
            path = root/'src/pages/UniversalAnalysis.tsx'
            path.write_bytes(b'\xef\xbb\xbf'+fixture('UniversalAnalysis.tsx').replace('\n','\r\n').encode('utf-8'))
            MOD.install(root)
            content = path.read_bytes()
            self.assertTrue(content.startswith(b'\xef\xbb\xbf'))
            self.assertNotIn(b'\n', content.replace(b'\r\n',b''))

    def test_fails_before_writing_if_unrecognized_structure(self):
        with TemporaryDirectory() as tmp:
            root = make_project(Path(tmp))
            modern = root/'src/pages/UniversalAnalysis.tsx'
            legacy = root/'src/pages/Dashboard.tsx'
            before = modern.read_bytes()
            s = legacy.read_text(encoding='utf-8').replace('className="panel findings-panel"', 'className="panel findings-panel" data-test="some-change"').replace('<FindingsOverview', '<DifferentOverview')
            legacy.write_text(s, encoding='utf-8')
            with self.assertRaises(ValueError): MOD.install(root)
            self.assertEqual(modern.read_bytes(), before)
            self.assertFalse((modern.with_name(modern.name+MOD.BACKUP_SUFFIX)).exists())

    def test_invalid_utf8_fails_safely(self):
        with TemporaryDirectory() as tmp:
            root = make_project(Path(tmp))
            path = root/'src/pages/UniversalAnalysis.tsx'
            path.write_bytes(b'\x97 invalid Windows-1252 file')
            legacy = root/'src/pages/Dashboard.tsx'
            backup = legacy.read_bytes()
            with self.assertRaises(UnicodeError): MOD.install(root)
            self.assertEqual(backup, legacy.read_bytes())

    def test_rollback_restores_both_originals(self):
        with TemporaryDirectory() as tmp:
            root = make_project(Path(tmp))
            files = [root /'src/pages'/n for n in ('UniversalAnalysis.tsx','Dashboard.tsx')]
            before = [p.read_bytes() for p in files]
            MOD.install(root)
            for p in files:
                backup = p.with_name(p.name + MOD.BACKUP_SUFFIX)
                p.write_bytes(backup.read_bytes())
            self.assertEqual([p.read_bytes() for p in files], before)


if __name__ == '__main__':
    unittest.main()
