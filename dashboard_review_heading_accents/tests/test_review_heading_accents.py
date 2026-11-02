import importlib.util
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

PACKAGE = Path(__file__).resolve().parents[1]
MODULE = PACKAGE / 'scripts/install_review_heading_accents.py'
ROLLBACK = PACKAGE / 'scripts/rollback_review_heading_accents.py'


def load(path: Path, module_name: str):
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module

installer = load(MODULE, 'review_accent_install')
rollback = load(ROLLBACK, 'review_accent_rollback')


def setup(root: Path, *, bom=False, crlf=False, old_highlights=False):
    (root / 'package.json').write_text('{}', encoding='utf-8')
    folder = root / 'src/pages'
    folder.mkdir(parents=True)
    source = ('import "./UniversalAnalysis.css";\n' +
              ('import "./DashboardHeadingHighlights.css";\n' if old_highlights else '') +
              'export default function UniversalAnalysis() { return null; }\n')
    if crlf:
        source = source.replace('\n', '\r\n')
    (folder / 'UniversalAnalysis.tsx').write_bytes((('\ufeff' if bom else '') + source).encode('utf-8'))
    (folder / 'Findings.tsx').write_text('KEEP FINDINGS', encoding='utf-8')
    (folder / 'normalizedPdf.ts').write_text('KEEP PDF', encoding='utf-8')
    return folder


class ReviewAccentsTests(unittest.TestCase):
    def test_install_changes_only_dashboard_and_css(self):
        with TemporaryDirectory() as temp:
            root=Path(temp); folder=setup(root)
            before={n: (folder / n).read_bytes() for n in ('Findings.tsx','normalizedPdf.ts')}
            changed=installer.install(root)
            self.assertEqual(sorted(changed), ['src/pages/ReviewHeadingAccents.css','src/pages/UniversalAnalysis.tsx'])
            source=(folder/'UniversalAnalysis.tsx').read_text(encoding='utf-8')
            self.assertEqual(source.count(installer.IMPORT), 1)
            self.assertEqual(before,{n: (folder/n).read_bytes() for n in before})
            self.assertEqual(installer.install(root), [])

    def test_requested_heading_ids_are_targeted(self):
        css=installer.SOURCE_CSS.read_text(encoding='utf-8')
        ids=['report-quality-title','vendor-deep-title','rule-correlation-heading','ca-heading','sg6-title','nrr-title','advanced-assessment-heading']
        for section_id in ids:
            with self.subTest(section_id=section_id):
                self.assertIn('#'+section_id,css)
                self.assertIn('.ua-page #'+section_id, css)  # explicit palette selector
        self.assertIn('.advanced-assessment > h3:first-of-type',css)
        self.assertNotIn('.findings-page',css)
        self.assertNotIn('.ed-root',css)

    def test_crlf_bom_and_previous_style_supported(self):
        with TemporaryDirectory() as temp:
            root=Path(temp); folder=setup(root,bom=True,crlf=True,old_highlights=True)
            installer.install(root)
            raw=(folder/'UniversalAnalysis.tsx').read_bytes()
            self.assertTrue(raw.startswith(b'\xef\xbb\xbf'))
            self.assertIn(b'import "./DashboardHeadingHighlights.css";\r\nimport "./ReviewHeadingAccents.css";',raw)
            self.assertEqual(raw.count(b'\n'),raw.count(b'\r\n'))

    def test_rollback_preserves_later_source_changes(self):
        with TemporaryDirectory() as temp:
            root=Path(temp); folder=setup(root)
            original=(folder/'UniversalAnalysis.tsx').read_bytes()
            installer.install(root)
            path=folder/'UniversalAnalysis.tsx'
            # Preserve the existing file's exact newline bytes on Windows and Unix.
            path.write_bytes(path.read_bytes() + b'// later changes\n')
            changed=rollback.rollback(root)
            self.assertEqual(sorted(changed),['src/pages/ReviewHeadingAccents.css','src/pages/UniversalAnalysis.tsx'])
            self.assertNotIn(installer.IMPORT,path.read_text(encoding='utf-8'))
            self.assertIn('// later changes',path.read_text(encoding='utf-8'))
            self.assertTrue(path.read_bytes().startswith(original))
            self.assertEqual(rollback.rollback(root),[])

    def test_unknown_layout_fails_without_writing(self):
        with TemporaryDirectory() as temp:
            root=Path(temp);folder=setup(root)
            p=folder/'UniversalAnalysis.tsx'
            p.write_text('export default function X(){ return null; }',encoding='utf-8')
            before=p.read_bytes()
            with self.assertRaisesRegex(ValueError,'No expected'):
                installer.install(root)
            self.assertEqual(before,p.read_bytes())
            self.assertFalse((folder/'ReviewHeadingAccents.css').exists())

    def test_bad_utf8_fails_closed(self):
        with TemporaryDirectory() as temp:
            root=Path(temp);folder=setup(root)
            p=folder/'UniversalAnalysis.tsx';p.write_bytes(b'\x97')
            with self.assertRaises(UnicodeError): installer.install(root)
            self.assertEqual(p.read_bytes(),b'\x97')
            self.assertFalse((folder/'ReviewHeadingAccents.css').exists())

    def test_custom_existing_css_not_overwritten(self):
        with TemporaryDirectory() as temp:
            root=Path(temp);folder=setup(root)
            css=folder/'ReviewHeadingAccents.css'
            css.write_text('CUSTOM',encoding='utf-8')
            old=(folder/'UniversalAnalysis.tsx').read_bytes()
            with self.assertRaisesRegex(ValueError,'different content'):
                installer.install(root)
            self.assertEqual(old,(folder/'UniversalAnalysis.tsx').read_bytes())
            self.assertEqual('CUSTOM',css.read_text(encoding='utf-8'))

    def test_duplicate_import_is_rejected(self):
        with TemporaryDirectory() as temp:
            root=Path(temp);folder=setup(root)
            p=folder/'UniversalAnalysis.tsx'
            p.write_text(p.read_text(encoding='utf-8')+installer.IMPORT+'\n'+installer.IMPORT+'\n',encoding='utf-8')
            with self.assertRaisesRegex(ValueError,'Duplicate'):
                installer.install(root)


if __name__=='__main__': unittest.main()
