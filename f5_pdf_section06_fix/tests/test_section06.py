import importlib.util
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parents[1] / 'scripts' / 'update_heading.py'
spec=importlib.util.spec_from_file_location('f5_sec06',HERE)
fix=importlib.util.module_from_spec(spec)
spec.loader.exec_module(fix)

class Section06Tests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.target=self.root/fix.TARGET
        self.target.parent.mkdir(parents=True, exist_ok=True)
        self.source=b'section("OTHER SECTION");\\r\\n'.replace(b'\\r\\n',b'\r\n')+fix.OLD+b'\r\n// F5 PHASES 1 + 2 COVERAGE LIMITATIONS\r\n'
        self.target.write_bytes(self.source)

    def test_dry_run_no_writes(self):
        self.assertIn('DRY RUN PASS',fix.operation(self.root,dry_run=True))
        self.assertEqual(self.target.read_bytes(),self.source)
        self.assertFalse((self.root/fix.BACKUP).exists())

    def test_install_exact_only(self):
        self.assertIn('INSTALLED',fix.operation(self.root))
        b=self.target.read_bytes()
        self.assertEqual(b.count(fix.NEW),1)
        self.assertEqual(b.count(fix.OLD),0)
        self.assertEqual(b,self.source.replace(fix.OLD,fix.NEW))
        self.assertIn(b'\r\n',b)
        self.assertIn(b'F5 PHASES 1 + 2 COVERAGE LIMITATIONS',b)

    def test_idempotence(self):
        fix.operation(self.root)
        b=self.target.read_bytes()
        self.assertIn('ALREADY INSTALLED',fix.operation(self.root))
        self.assertEqual(b,self.target.read_bytes())

    def test_rollback_round_trip(self):
        fix.operation(self.root)
        self.assertIn('ROLLBACK PASS',fix.operation(self.root,rollback=True))
        self.assertEqual(self.target.read_bytes(),self.source)
        self.assertFalse((self.root/fix.BACKUP).exists())

    def test_rollback_refuses_user_changes(self):
        fix.operation(self.root)
        self.target.write_bytes(self.target.read_bytes()+b'// custom')
        with self.assertRaisesRegex(RuntimeError,'refusing rollback'):
            fix.operation(self.root,rollback=True)

    def test_unknown_refused(self):
        self.target.write_bytes(b'no known F5 heading')
        with self.assertRaisesRegex(RuntimeError,'Unsupported generator'):
            fix.operation(self.root)

    def test_duplicate_anchor_refused(self):
        self.target.write_bytes(self.source+fix.OLD)
        with self.assertRaisesRegex(RuntimeError,'Unsupported generator'):
            fix.operation(self.root)

    def test_backup_cannot_be_overwritten(self):
        b=self.root/fix.BACKUP
        b.parent.mkdir(parents=True,exist_ok=True)
        b.write_bytes(b'user backup')
        with self.assertRaisesRegex(RuntimeError,'Backup already exists'):
            fix.operation(self.root)
        self.assertEqual(self.target.read_bytes(),self.source)

if __name__=='__main__': unittest.main()
