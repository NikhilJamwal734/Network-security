import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / 'audit_logs.py'
spec = importlib.util.spec_from_file_location('audit_logs_standalone', SCRIPT)
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)


class LogIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.logs = self.root / 'logs'
        self.logs.mkdir()
        self.key = self.root / 'anchor' / 'secret.key'
        self.manifest = self.root / 'anchor' / 'first.json'
        (self.logs / 'api_access.log').write_text('{"event":"http_request","status_code":200}\n', encoding='utf-8')
        a.init_key(self.key)

    def test_snapshot_verify(self):
        self.assertEqual(a.snapshot(self.logs, self.manifest, self.key)['status'], 'PASS')
        self.assertEqual(a.verify(self.logs, self.manifest, self.key)['status'], 'PASS')

    def test_modification_is_detected(self):
        a.snapshot(self.logs, self.manifest, self.key)
        (self.logs / 'api_access.log').write_text('{"event":"replaced"}\n', encoding='utf-8')
        result = a.verify(self.logs, self.manifest, self.key)
        self.assertEqual(result['status'], 'FAIL')
        self.assertEqual(result['modified'], ['api_access.log'])

    def test_deleted_file_detected(self):
        a.snapshot(self.logs, self.manifest, self.key)
        (self.logs / 'api_access.log').unlink()
        (self.logs / 'error.log').write_text('{"event":"test"}\n', encoding='utf-8')
        self.assertEqual(a.verify(self.logs, self.manifest, self.key)['missing'], ['api_access.log'])

    def test_added_file_detected(self):
        a.snapshot(self.logs, self.manifest, self.key)
        (self.logs / 'error.log').write_text('{"event":"test"}\n', encoding='utf-8')
        self.assertEqual(a.verify(self.logs, self.manifest, self.key)['new'], ['error.log'])

    def test_manifest_tamper_detected(self):
        a.snapshot(self.logs, self.manifest, self.key)
        d=json.loads(self.manifest.read_text())
        d['payload']['files']['api_access.log']['bytes'] = 1
        self.manifest.write_text(json.dumps(d), encoding='utf-8')
        self.assertEqual(a.verify(self.logs, self.manifest, self.key)['issue'], 'MANIFEST_SIGNATURE_INVALID')

    def test_wrong_key_detected(self):
        a.snapshot(self.logs, self.manifest, self.key)
        self.key.write_bytes(b'x' * 32)
        self.assertEqual(a.verify(self.logs, self.manifest, self.key)['status'], 'FAIL')

    def test_no_overwrite_key(self):
        with self.assertRaises(a.AuditError):
            a.init_key(self.key)

    def test_no_overwrite_manifest(self):
        a.snapshot(self.logs, self.manifest, self.key)
        with self.assertRaises(a.AuditError):
            a.snapshot(self.logs, self.manifest, self.key)

    def test_no_manifest_in_log_dir(self):
        with self.assertRaises(a.AuditError):
            a.snapshot(self.logs, self.logs / 'manifest.json', self.key)

    def test_other_file_ignored(self):
        (self.logs / 'config.txt').write_text('UNTRUSTED', encoding='utf-8')
        result = a.snapshot(self.logs, self.manifest, self.key)
        self.assertEqual(result['managed_files'], 1)
        self.assertNotIn('config.txt', self.manifest.read_text(encoding='utf-8'))

    def test_malformed_jsonl_counted(self):
        (self.logs / 'error.log').write_text('not JSON\n', encoding='utf-8')
        result = a.snapshot(self.logs, self.manifest, self.key)
        self.assertEqual(result['malformed_jsonl_records'], 1)

    def test_large_file_rejected(self):
        with patch.object(a, 'MAX_FILE_BYTES', 4):
            with self.assertRaises(a.AuditError):
                a.snapshot(self.logs, self.manifest, self.key)

    def test_invalid_key_size_rejected(self):
        self.key.write_bytes(b'ab')
        with self.assertRaises(a.AuditError):
            a.snapshot(self.logs, self.manifest, self.key)

    def test_symlink_log_rejected_if_supported(self):
        link = self.logs / 'error.log'
        try:
            link.symlink_to(self.logs / 'api_access.log')
        except (OSError, NotImplementedError):
            self.skipTest('Symlink unavailable on this OS')
        with self.assertRaises(a.AuditError):
            a.snapshot(self.logs, self.manifest, self.key)

    def test_cli_roundtrip(self):
        out = self.root / 'audit-result.json'
        self.assertEqual(a.run_cli(['snapshot', '--logs-dir', str(self.logs), '--manifest', str(self.manifest), '--key-file', str(self.key)]), 0)
        self.assertEqual(a.run_cli(['verify', '--logs-dir', str(self.logs), '--manifest', str(self.manifest), '--key-file', str(self.key), '--out', str(out)]), 0)
        self.assertEqual(json.loads(out.read_text())['status'], 'PASS')


if __name__ == '__main__':
    unittest.main()
