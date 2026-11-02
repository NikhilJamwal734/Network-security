from __future__ import annotations
import importlib.util
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

PKG = Path(__file__).resolve().parents[1]
SCRIPT = PKG / 'scripts' / 'install_f5_ui.py'
FIX = PKG / 'tests' / 'fixtures'
sp = importlib.util.spec_from_file_location('f5_ui_installer', SCRIPT)
assert sp and sp.loader
mod = importlib.util.module_from_spec(sp)
sp.loader.exec_module(mod)


def setup(root: Path, windows=False):
    samples = {
      'frontend/src/pages/UniversalAnalysis.tsx': FIX / 'UniversalAnalysis.baseline.tsx',
      'frontend/src/utils/normalizedPdf.ts': FIX / 'normalizedPdf.baseline.ts',
      'frontend/src/api/universal.ts': FIX / 'universal.baseline.ts',
    }
    for rel, src in samples.items():
        dest = root / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        raw = src.read_bytes()
        if windows and rel.endswith(('.tsx','.ts')):
            raw = b'\xef\xbb\xbf' + raw.replace(b'\r\n',b'\n').replace(b'\n',b'\r\n')
        dest.write_bytes(raw)
    (root/'frontend/package.json').write_text('{}',encoding='utf-8')
    f5=root/'app/f5_phase1_addon/api.py'
    f5.parent.mkdir(parents=True,exist_ok=True)
    f5.write_text('# existing Phase 1 F5 backend\n',encoding='utf-8')
    legacy=root/'app/parsers/f5_bigip_parser.py'
    legacy.parent.mkdir(parents=True,exist_ok=True)
    legacy.write_text('# existing separate F5 parser; preserve me\n', encoding='utf-8')


class F5UIInstallerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        setup(self.root)
        self.original_parser = (self.root/'app/parsers/f5_bigip_parser.py').read_bytes()
    def tearDown(self): self.temp.cleanup()

    def test_dry_run_no_side_effects(self):
        original=(self.root/mod.PAGE).read_bytes()
        results=mod.install(self.root,dry_run=True)
        self.assertEqual(set(results),{mod.PAGE,mod.PDF,mod.NEW_FILE})
        self.assertEqual((self.root/mod.PAGE).read_bytes(),original)
        self.assertFalse((self.root/mod.MANIFEST).exists())

    def test_install_and_idempotence(self):
        results=mod.install(self.root)
        self.assertEqual(len(results),3)
        self.assertEqual(mod.install(self.root),[])
        text=(self.root/mod.PAGE).read_text(encoding="utf-8")
        self.assertIn('setPlatforms(withF5Platform(list))',text)
        self.assertIn('await analyzeF5Phase1(file, controller.signal)',text)
        pdf=(self.root/mod.PDF).read_text(encoding="utf-8")
        self.assertIn('section("F5 BIG-IP Phase 1 - Detailed technical evidence")',pdf)
        self.assertIn('review_observations',pdf)
        self.assertEqual((self.root/'app/parsers/f5_bigip_parser.py').read_bytes(), self.original_parser)
        self.assertFalse((self.root/'app/api/main.py').exists())

    def test_rollback_restores_original(self):
        original={rel:(self.root/rel).read_bytes() for rel in (mod.PAGE,mod.PDF)}
        mod.install(self.root)
        results=mod.rollback(self.root)
        self.assertEqual(set(results),{mod.PAGE,mod.PDF,mod.NEW_FILE})
        for rel,raw in original.items(): self.assertEqual((self.root/rel).read_bytes(),raw)
        self.assertFalse((self.root/mod.NEW_FILE).exists())
        self.assertFalse((self.root/mod.MANIFEST).exists())

    def test_modification_blocks_rollback(self):
        mod.install(self.root)
        with (self.root/mod.PAGE).open('a') as stream: stream.write('\n// customized\n')
        with self.assertRaisesRegex(ValueError,'modified since installation'):mod.rollback(self.root)
        self.assertTrue((self.root/mod.MANIFEST).exists())

    def test_missing_phase1_backend_fails_preflight(self):
        (self.root/mod.MAIN).unlink()
        with self.assertRaisesRegex(ValueError, 'backend'): mod.install(self.root)
        self.assertFalse((self.root/mod.NEW_FILE).exists())

    def test_custom_ui_fails_preflight(self):
        target = self.root/mod.PAGE
        target.write_text('export default function App(){return null}',encoding='utf8')
        before=(self.root/mod.PDF).read_bytes()
        with self.assertRaisesRegex(ValueError,'import'): mod.install(self.root)
        self.assertEqual((self.root/mod.PDF).read_bytes(),before)

    def test_custom_adapter_fails_preflight(self):
        target = self.root/mod.NEW_FILE
        target.parent.mkdir(parents=True,exist_ok=True)
        target.write_text('// custom\n')
        with self.assertRaisesRegex(ValueError,'customized'): mod.install(self.root)

    def test_bom_crlf_preserved(self):
        setup(self.root,windows=True)
        mod.install(self.root)
        for rel in (mod.PAGE,mod.PDF):
            raw=(self.root/rel).read_bytes()
            self.assertTrue(raw.startswith(b'\xef\xbb\xbf'))
            self.assertIn(b'\r\n',raw)
            self.assertNotIn(b'\r\r\n',raw)
        mod.rollback(self.root)
        self.assertEqual((self.root/'app/parsers/f5_bigip_parser.py').read_bytes(),self.original_parser)

    def test_partial_integration_fails_closed(self):
        target=self.root/mod.PAGE
        s=target.read_text(encoding="utf-8")
        target.write_text('import { F5_PLATFORM_ID, withF5Platform, analyzeF5Phase1 } from "../api/f5Phase1";\n'+s, encoding="utf-8")
        with self.assertRaisesRegex(ValueError,'Partially integrated'):mod.install(self.root)

    def test_cli_dry_run(self):
        result=subprocess.run([sys.executable,str(SCRIPT),str(self.root),'--dry-run'],capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('Would update',result.stdout)

if __name__ == '__main__': unittest.main()
