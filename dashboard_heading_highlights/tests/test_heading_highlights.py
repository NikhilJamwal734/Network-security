import importlib.util
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

HERE = Path(__file__).resolve().parent
PACKAGE = HERE.parent
SCRIPT_DIR = PACKAGE / 'scripts'
import sys
sys.path.insert(0, str(SCRIPT_DIR))
import install_heading_highlights as install
import rollback_heading_highlights as rollback
FIX = HERE/'fixtures'


def frontend(root):
    ui = root/'frontend'
    (ui/'src/pages').mkdir(parents=True)
    (ui/'src/utils').mkdir(parents=True)
    (ui/'package.json').write_text('{"name":"analyzer"}', encoding='utf-8')
    for f in ('UniversalAnalysis.tsx', 'Dashboard.tsx', 'Findings.tsx'):
        (ui/'src/pages'/f).write_bytes((FIX/f).read_bytes())
    (ui/'src/utils/normalizedPdf.ts').write_text('PDF unchanged',encoding='utf-8')
    return ui


class DashboardHeadingTests(unittest.TestCase):
    def test_installs_both_imports_one_stylesheet_and_is_idempotent(self):
        with TemporaryDirectory() as td:
            ui = frontend(Path(td))
            original = {x:(ui/x).read_bytes() for x in
                        ['src/pages/Dashboard.tsx','src/pages/UniversalAnalysis.tsx',
                         'src/pages/Findings.tsx','src/utils/normalizedPdf.ts']}
            got = install.install(ui)
            self.assertEqual(got, ['src/pages/UniversalAnalysis.tsx','src/pages/Dashboard.tsx',
                                   'src/pages/DashboardHeadingHighlights.css'])
            for path in ('src/pages/UniversalAnalysis.tsx','src/pages/Dashboard.tsx'):
                after = (ui/path).read_bytes()
                self.assertEqual(after.count(install.IMPORT.encode('utf-8')), 1)
                self.assertEqual(after.replace((install.IMPORT+'\n').encode(),b''),original[path])
                self.assertTrue((ui/path).with_name(Path(path).name+install.BACKUP).exists())
            self.assertEqual((ui/'src/pages/Findings.tsx').read_bytes(),original['src/pages/Findings.tsx'])
            self.assertEqual((ui/'src/utils/normalizedPdf.ts').read_bytes(),original['src/utils/normalizedPdf.ts'])
            self.assertEqual(install.install(ui), [])

    def test_crlf_utf8_bom_and_long_utf8_headings_stay_valid(self):
        with TemporaryDirectory() as td:
            ui = frontend(Path(td))
            path = ui/'src/pages/UniversalAnalysis.tsx'
            orig = (path.read_text('utf8')+'\n// heading — safe').replace('\n','\r\n')
            path.write_bytes(b'\xef\xbb\xbf'+orig.encode('utf8'))
            install.install(ui)
            out=path.read_bytes()
            self.assertTrue(out.startswith(b'\xef\xbb\xbf'))
            self.assertNotIn(b'\n', out.replace(b'\r\n',b''))
            self.assertIn('heading — safe',out.decode('utf-8-sig'))
            rollback.rollback(ui)
            self.assertEqual(path.read_bytes(),b'\xef\xbb\xbf'+orig.encode('utf8'))

    def test_rollback_keeps_other_later_tsx_changes(self):
        with TemporaryDirectory() as td:
            ui = frontend(Path(td))
            install.install(ui)
            path=ui/'src/pages/Dashboard.tsx'
            path.write_text(path.read_text('utf8')+'\n// later custom edit\n',encoding='utf8')
            rollback.rollback(ui)
            self.assertIn('// later custom edit',path.read_text('utf8'))
            self.assertNotIn(install.IMPORT,path.read_text('utf8'))
            self.assertFalse((ui/install.REL_CSS).exists())

    def test_fails_safely_on_unexpected_import(self):
        with TemporaryDirectory() as td:
            ui=frontend(Path(td))
            path=ui/'src/pages/UniversalAnalysis.tsx'
            path.write_text(path.read_text('utf8').replace('import "./UnifiedDashboardExtras.css";',
                           'import "./SomethingUnexpected.css";').replace('import "./UniversalAnalysis.css";',
                           'import "./SomethingElse.css";'),encoding='utf8')
            before = (ui/'src/pages/Dashboard.tsx').read_bytes()
            with self.assertRaises(ValueError):install.install(ui)
            self.assertEqual((ui/'src/pages/Dashboard.tsx').read_bytes(),before)
            self.assertFalse((ui/install.REL_CSS).exists())

    def test_no_changes_on_invalid_utf8(self):
        with TemporaryDirectory() as td:
            ui=frontend(Path(td))
            (ui/'src/pages/Dashboard.tsx').write_bytes(b'\x97not UTF8')
            before=(ui/'src/pages/UniversalAnalysis.tsx').read_bytes()
            with self.assertRaises(UnicodeDecodeError): install.install(ui)
            self.assertEqual((ui/'src/pages/UniversalAnalysis.tsx').read_bytes(),before)

    def test_custom_stylesheet_not_overwritten(self):
        with TemporaryDirectory() as td:
            ui=frontend(Path(td))
            (ui/install.REL_CSS).write_text('custom',encoding='utf8')
            with self.assertRaises(ValueError):install.install(ui)
            self.assertNotIn(install.IMPORT,(ui/'src/pages/Dashboard.tsx').read_text('utf8'))

    def test_css_only_dashboard_selectors(self):
        style=install.CSS.read_text('utf8')
        self.assertIn('.ua-page .rpt112-panel',style)
        self.assertIn('.ua-page .acc111-panel',style)
        self.assertIn('.ua-page .con110-panel',style)
        self.assertIn('.dashboard .panel-header h2',style)
        self.assertNotIn('findings-page',style)
        self.assertNotIn('!important',style)

    def test_fails_on_nonfrontend_root(self):
        with TemporaryDirectory() as td:
            with self.assertRaises(ValueError):install.install(Path(td))

if __name__ == '__main__':
    unittest.main()
