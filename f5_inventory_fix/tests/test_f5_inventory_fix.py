"""Self-contained tests for F5 inventory request compatibility patch."""
from __future__ import annotations
import importlib.util
from pathlib import Path
import shutil
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts' / 'install_f5_inventory_fix.py'
SPEC = importlib.util.spec_from_file_location('f5_inventory_fix', SCRIPT)
assert SPEC and SPEC.loader
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)

PAGE_SRC = '''import { F5_PLATFORM_ID, withF5Platform, analyzeF5Phase1 } from "../api/f5Phase1";
import { getPlatformDetails } from "../api/platformConfiguration";
function run(file: File, next: any, controller: AbortController) {
      if (next.platform.platform_id !== "cisco_asa") {
    const details = await getPlatformDetails(file, next.platform.platform_id, controller.signal);
    onConfigurationChange(details);
  }
}
'''
INV_SRC = '''import type { NormalizedReport } from "../api/universal";
function Example({report}: {report: NormalizedReport}) {
  const platform = report.platform.platform_id;
  let view: ReactNode;
  if (!present) {
    view = null;
  } else if (section === "Rules" && ids) {
    view = null;
  }
}
'''


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        for rel, data in ((mod.PAGE, PAGE_SRC), (mod.INVENTORY_PAGE, INV_SRC), (mod.F5_ADAPTER, 'export const F5_PLATFORM_ID = "f5_bigip";\n')):
            path = self.root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(data, encoding='utf-8')

    def tearDown(self):
        self.tmp.cleanup()

    def test_install_idempotent_and_no_change_to_f5_backend(self):
        orig = (self.root / mod.F5_ADAPTER).read_bytes()
        self.assertEqual(len(mod.install(self.root)), 2)
        self.assertEqual(mod.install(self.root), [])
        page = (self.root / mod.PAGE).read_text(encoding='utf-8')
        self.assertIn('next.platform.platform_id === F5_PLATFORM_ID', page)
        self.assertIn('else if (next.platform.platform_id !== "cisco_asa")', page)
        self.assertIn('f5_phase1_profile_count: review.total_profiles', page)
        self.assertIn('getPlatformDetails(file, next.platform.platform_id, controller.signal)', page)
        self.assertEqual((self.root / mod.F5_ADAPTER).read_bytes(), orig)

    def test_inventory_reports_not_assessed(self):
        mod.install(self.root)
        text = (self.root / mod.INVENTORY_PAGE).read_text(encoding='utf-8')
        self.assertIn('platform === "f5_bigip"', text)
        self.assertIn('Not assessed by F5 Phase 1', text)
        self.assertIn('SSL / HTTP profiles parsed', text)
        self.assertIn('not a complete device inventory', text)

    def test_rollback_restores_original_bytes(self):
        before = {rel:(self.root / rel).read_bytes() for rel in (mod.PAGE,mod.INVENTORY_PAGE)}
        mod.install(self.root)
        self.assertEqual(set(mod.rollback(self.root)),set(before))
        self.assertEqual({rel:(self.root / rel).read_bytes() for rel in before},before)
        self.assertFalse((self.root/mod.MANIFEST).exists())

    def test_dry_run_no_changes(self):
        self.assertEqual(set(mod.install(self.root,dry_run=True)), {mod.PAGE,mod.INVENTORY_PAGE})
        self.assertFalse((self.root/mod.MANIFEST).exists())

    def test_win_crlf_bom_preserved(self):
        p=self.root/mod.PAGE
        p.write_bytes(b'\xef\xbb\xbf' + PAGE_SRC.replace('\n','\r\n').encode('utf8'))
        mod.install(self.root)
        raw=p.read_bytes()
        self.assertTrue(raw.startswith(b'\xef\xbb\xbf'))
        self.assertNotIn(b'\r\r\n',raw)
        self.assertNotIn(b'\n',raw.replace(b'\r\n',b''))

    def test_custom_edit_blocks_rollback(self):
        mod.install(self.root)
        p=self.root/mod.PAGE
        p.write_bytes(p.read_bytes()+b'\n// user edit\n')
        with self.assertRaisesRegex(ValueError,'File changed after installation'):
            mod.rollback(self.root)

    def test_missing_inventory_file_fails_closed(self):
        (self.root/mod.INVENTORY_PAGE).unlink()
        with self.assertRaisesRegex(ValueError,'Required file missing'):
            mod.install(self.root)
        self.assertNotIn('F5 inventory', (self.root/mod.PAGE).read_text(encoding='utf-8'))

    def test_incompatible_f5_import_fails_closed(self):
        p=self.root/mod.PAGE
        p.write_text(PAGE_SRC.replace(mod.OLD_IMPORT, '/* custom import */'),encoding='utf8')
        original=p.read_bytes()
        with self.assertRaisesRegex(ValueError,'F5 Phase 1 import not found'):
            mod.install(self.root)
        self.assertEqual(p.read_bytes(),original)

    def test_incomplete_integration_does_not_force_changes(self):
        p=self.root/mod.PAGE
        p.write_text(PAGE_SRC.replace(mod.OLD_IMPORT,mod.NEW_IMPORT),encoding='utf8')
        with self.assertRaisesRegex(ValueError,'F5 Phase 1 import not found'):
            mod.install(self.root)

    def test_mixed_line_endings_fails_closed(self):
        p=self.root/mod.PAGE
        p.write_bytes(PAGE_SRC.encode('utf8').replace(b'\n',b'\r\n',1))
        with self.assertRaisesRegex(ValueError,'Mixed or invalid'):
            mod.install(self.root)


if __name__ == '__main__':
    unittest.main()
