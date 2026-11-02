from __future__ import annotations
import importlib.util
import tempfile
import unittest
from pathlib import Path
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts/apply_pdf_only_ui.py'
SOURCE = Path('/mnt/data')


def load_module():
    spec = importlib.util.spec_from_file_location('pdf_only_ui_installer', SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PatchTests(unittest.TestCase):
    def fixture(self, root: Path):
        z = zipfile.ZipFile(SOURCE / 'API-009.7-All-Platform-Reports-PDF.zip')
        files = {
          'src/App.tsx': z.read('api0097_all_reports_patch/tests/reference_merged_App.tsx').decode(),
          'src/components/NormalizedReportDownloads.tsx': z.read('api0097_all_reports_patch/src/components/NormalizedReportDownloads.tsx').decode(),
          'src/pages/NormalizedReportsPage.tsx': z.read('api0097_all_reports_patch/src/pages/NormalizedReportsPage.tsx').decode(),
          'src/pages/UniversalAnalysis.tsx': (SOURCE/'api0099_frontend_validation/frontend/src/pages/UniversalAnalysis.tsx').read_text(),
          'src/utils/normalizedPdf.ts': (SOURCE/'professional_pdf_patch/frontend_patch/src/utils/normalizedPdf.ts').read_text(),
        }
        for rel, data in files.items():
            p=root/rel;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(data,encoding='utf8')
        (root/'package.json').write_text('{}')
        return files

    def test_all_controls_removed_pdf_left(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            old = self.fixture(root)
            inst = load_module();inst.FRONTEND=root
            output = inst.install()
            self.assertGreaterEqual(len(output),4)
            for rel in old:
                self.assertTrue((root/(rel+'.before_pdf_only_ui.bak')).is_file())
                self.assertEqual((root/(rel+'.before_pdf_only_ui.bak')).read_text(),old[rel])
            app=(root/'src/App.tsx').read_text()
            self.assertNotIn('<JsonReportDownload',app)
            self.assertIn('<PdfReportDownload',app)
            shared=(root/'src/components/NormalizedReportDownloads.tsx').read_text()
            self.assertNotIn('Download JSON',shared)
            self.assertIn('Download PDF',shared)
            self.assertNotIn('downloadNormalizedJson',shared)
            dashboard=(root/'src/pages/UniversalAnalysis.tsx').read_text()
            self.assertNotIn('Export normalized JSON',dashboard)
            self.assertNotIn('function exportReport',dashboard)
            self.assertNotIn('function safeExportName',dashboard)
            pages=(root/'src/pages/NormalizedReportsPage.tsx').read_text()
            self.assertNotIn('Both files contain',pages)
            pdf=(root/'src/utils/normalizedPdf.ts').read_text()
            self.assertIn('pdf.getNumberOfPages()',pdf)
            self.assertNotIn('pdf.internal.getNumberOfPages()',pdf)
            self.assertIn('pdf.setFontSize(12.5);\n    setInk(pdf, COLORS.teal);',pdf)
            self.assertIn('pdf.setFontSize(11.2);',pdf)
            self.assertIn('size: 11.2, spaceAfter: 8',pdf)
            self.assertNotIn('Export JSON for the complete set',pdf)
            self.assertEqual(inst.install(),['Already applied: no further changes needed'])

    def test_fails_without_frontend(self):
        with tempfile.TemporaryDirectory() as tmp:
            inst = load_module();inst.FRONTEND=Path(tmp)
            with self.assertRaisesRegex(ValueError,'package.json'):
                inst.install()

    def test_fails_closed_on_unrecognized_pdf(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);self.fixture(root)
            p=root/'src/utils/normalizedPdf.ts'
            p.write_text('unsupported PDF module')
            inst=load_module();inst.FRONTEND=root
            with self.assertRaisesRegex(ValueError,'not recognized'):
                inst.install()
            self.assertFalse((root/'src/App.tsx.before_pdf_only_ui.bak').exists())

if __name__=='__main__': unittest.main()
