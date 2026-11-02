import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / 'scripts' / 'rename_f5_platform.py'
FIXTURE = ROOT / 'tests' / 'fixtures' / 'f5Phase1.phase3.ts'
SPEC = importlib.util.spec_from_file_location('label_patch', SRC)
patch = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(patch)


class PlatformLabelTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        path = self.root / patch.TARGET
        path.parent.mkdir(parents=True)
        path.write_bytes(FIXTURE.read_bytes())
        self.path = path
        self.original = path.read_bytes()

    def tearDown(self):
        self.temp.cleanup()

    def test_exact_label_and_registry_replacement(self):
        self.assertIn('DRY RUN PASS', patch.install(self.root, True))
        self.assertEqual(self.original, self.path.read_bytes())
        patch.install(self.root)
        src = self.path.read_text('utf-8')
        self.assertEqual(src.count('display_name: "F5 BIG-IP LTM & Advanced WAF"'), 2)
        self.assertIn('items.map((p) => p.platform_id === F5_PLATFORM_ID', src)
        self.assertIn('export const F5_PLATFORM_ID = "f5_bigip";', src)
        self.assertIn('form.append("file", file, file.name)', src)

    def test_preserves_phase3_evidence_adapter(self):
        self.path.write_bytes((FIXTURE.parent / 'f5Phase1.phase3_evidence.ts').read_bytes())
        patch.install(self.root)
        src = self.path.read_text(encoding='utf8')
        self.assertIn('form.append("evidence_json"', src)
        self.assertIn('operatorEvidence?: File | null', src)
        self.assertEqual(src.count('display_name: "F5 BIG-IP LTM & Advanced WAF"'), 2)

    def test_idempotent_and_rollback(self):
        patch.install(self.root)
        self.assertIn('ALREADY INSTALLED', patch.install(self.root))
        self.assertIn('ROLLED BACK', patch.rollback(self.root))
        self.assertEqual(self.path.read_bytes(), self.original)

    def test_crlf_bom_preserved(self):
        self.path.write_bytes(b'\xef\xbb\xbf' + self.original.replace(b'\n', b'\r\n'))
        patch.install(self.root)
        value = self.path.read_bytes()
        self.assertTrue(value.startswith(b'\xef\xbb\xbf'))
        self.assertEqual(value.count(b'\r\n'), value.count(b'\n'))
        patch.rollback(self.root)
        self.assertTrue(self.path.read_bytes().startswith(b'\xef\xbb\xbf'))

    def test_refuses_customized_source(self):
        self.path.write_bytes(self.original.replace(b'F5 BIG-IP (Phases 1 + 2)', b'custom'))
        with self.assertRaisesRegex(ValueError, 'selector label'):
            patch.install(self.root)
        self.assertFalse((self.root / patch.MANIFEST).exists())

    def test_refuses_modified_rollback(self):
        patch.install(self.root)
        self.path.write_bytes(self.path.read_bytes() + b'\n// locally edited\n')
        with self.assertRaisesRegex(ValueError, 'changed after installation'):
            patch.rollback(self.root)

    def test_guard_against_symlink(self):
        other = self.root / 'outside.ts'
        other.write_bytes(self.original)
        self.path.unlink()
        try:
            self.path.symlink_to(other)
        except (OSError, NotImplementedError):
            self.skipTest('Symlinks unavailable')
        with self.assertRaisesRegex(ValueError, 'symlink'):
            patch.install(self.root)
        self.assertEqual(other.read_bytes(), self.original)

    def test_does_not_touch_other_vendor_code(self):
        extra = self.root / 'app' / 'api' / 'main.py'
        extra.parent.mkdir(parents=True)
        extra.write_text('other vendor routes', encoding='utf8')
        patch.install(self.root)
        self.assertEqual(extra.read_text('utf8'), 'other vendor routes')

if __name__ == '__main__':
    unittest.main()
