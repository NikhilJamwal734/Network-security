"""Isolated tests for packaged acceptance runner (no EXE required)."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

SOURCE = Path(__file__).resolve().parents[1] / 'check_exe.py'
spec = importlib.util.spec_from_file_location('desktop_acceptance_runner', SOURCE)
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)


class IntegrityTests(unittest.TestCase):
    def test_matching_exe_receipt(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            exe = root / 'FirewallAnalyzer.exe'
            exe.write_bytes(b'EXE-TEST\x00' * 20000)
            receipt = root / 'release_final_build_result.json'
            receipt.write_text(json.dumps({'exe_sha256': hashlib.sha256(exe.read_bytes()).hexdigest(),
                                           'local_exe_smoke': 'PASS'}))
            self.assertEqual(a.integrity_check(exe, receipt)['status'], 'PASS')

    def test_mismatching_exe_receipt(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            exe = root / 'FirewallAnalyzer.exe'
            exe.write_bytes(b'A' * 130_000)
            receipt = root / 'receipt.json'
            receipt.write_text(json.dumps({'exe_sha256': '0' * 64, 'local_exe_smoke': 'PASS'}))
            self.assertEqual(a.integrity_check(exe, receipt)['status'], 'FAIL')

    def test_missing_receipt_incomplete(self):
        with tempfile.TemporaryDirectory() as d:
            exe = Path(d) / 'test.exe'
            exe.write_bytes(b'x' * 130_000)
            self.assertEqual(a.integrity_check(exe, Path(d) / 'no-receipt.json')['status'], 'INCOMPLETE')

    def test_symlink_fixture_rejected_if_supported(self):
        with tempfile.TemporaryDirectory() as d:
            source = Path(d) / 'target.conf'
            source.write_text('hostname synthetic\n')
            link = Path(d) / 'link.conf'
            try:
                link.symlink_to(source)
            except (OSError, NotImplementedError):
                self.skipTest('Symlinks not available')
            with self.assertRaises(ValueError):
                a.safe_sample(link)


class MultipartAndVendorTests(unittest.TestCase):
    def test_multipart_has_evidence_and_close_boundary(self):
        body, mime = a.multipart('test.conf', b'hostname test', b'{"ucs_backups":[]}')
        self.assertIn(b'name="file"', body)
        self.assertIn(b'name="evidence_json"', body)
        self.assertIn(b'hostname test', body)
        self.assertIn(b'--\r\n', body)
        self.assertTrue(mime.startswith('multipart/form-data; boundary='))

    def test_multipart_rejects_unsafe_filename(self):
        with self.assertRaises(ValueError):
            a.multipart('../../secret.conf', b'x')

    def test_is_consistent_strict_counts(self):
        payload = {'platform': {'platform_id': 'cisco_asa'},
                   'findings': [{'code': 'X'}],
                   'summary': {'total_findings': 1},
                   'input_security_review': {'status': 'accepted'}}
        self.assertTrue(a.is_consistent(payload, 'cisco_asa'))
        payload['summary']['total_findings'] = 2
        self.assertFalse(a.is_consistent(payload, 'cisco_asa'))

    def test_vendor_200_expected_platform(self):
        with tempfile.TemporaryDirectory() as d:
            file = Path(d) / 'test.conf'
            file.write_text('hostname sample\n')
            payload = {'platform': {'platform_id': 'fortios'},
                       'findings': [], 'summary': {'total_findings': 0},
                       'input_security_review': {'status': 'accepted'}}
            with mock.patch.object(a, 'fetch', return_value=(200, json.dumps(payload).encode(), 'application/json')):
                result = a.check_vendor('http://127.0.0.1:1234/', 'fortios', file)
                self.assertEqual(result['status'], 'PASS')

    def test_vendor_422_fails(self):
        with tempfile.TemporaryDirectory() as d:
            file = Path(d) / 'test.conf'
            file.write_text('hostname sample\n')
            with mock.patch.object(a, 'fetch', return_value=(422, b'{}', 'application/json')):
                self.assertEqual(a.check_vendor('http://127.0.0.1:1234/', 'fortios', file)['status'], 'FAIL')

    def test_f5_count_and_confidence_check(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            conf = root / 'c.conf'
            ev = root / 'e.json'
            conf.write_bytes(b'ltm virtual sample {}\n')
            ev.write_text('{}')
            sha = hashlib.sha256(conf.read_bytes()).hexdigest()
            base = {'platform': {'platform_id': 'f5_bigip'},
                    'input_security_review': {'status': 'accepted', 'sha256': sha}}
            without = {**base, 'summary': {'total_findings': 3,'total_review_observations': 5},
                       'findings': [{'code': 'F5-001'}]*3, 'review_observations': [{}]*5}
            with_ev = {**base, 'summary': {'total_findings': 4,'total_review_observations': 4},
                       'findings': [{'code': 'F5-001'}]*3 + [{'code':'F5-005','confidence':'operator_supplied_unverified'}],
                       'review_observations': [{'code':'F5-006','confidence':'operator_supplied_unverified'}] + [{}]*3}
            side_effect = [(200, json.dumps(without).encode(), 'application/json'),
                           (200, json.dumps(with_ev).encode(), 'application/json')]
            with mock.patch.object(a,'fetch',side_effect=side_effect):
                self.assertEqual(a.check_f5('http://127.0.0.1:1234/',conf,ev)['status'],'PASS')


class LogsTests(unittest.TestCase):
    def test_log_activity_detected_without_persisting_contents(self):
        with tempfile.TemporaryDirectory() as d:
            logs = Path(d)
            file = logs / 'api_access.log'
            file.write_text(json.dumps({'event': 'http_request', 'timestamp_utc': '2026-11-01T00:00:00+00:00', 'status_code': 200}) + '\n')
            result = a.check_disk_logs(logs, (0, 0))
            self.assertEqual(result['status'], 'PASS')
            self.assertNotIn('2026-11-01T', json.dumps(result))

    def test_log_missing_fails(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(a.check_disk_logs(Path(d), None)['status'], 'FAIL')

    def test_acceptance_output_excludes_secrets(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / 'result.json'
            a.safe_write_result(out, {'counts': {'passed': 1}, 'checks':[a.entry('Log API','PASS','metadata only')]})
            self.assertEqual(json.loads(out.read_text())['checks'][0]['status'], 'PASS')


if __name__ == '__main__':
    unittest.main()

class GateSafetyTests(unittest.TestCase):
    def test_receipt_mismatch_must_not_execute_exe(self):
        import argparse
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            exe = root / 'test.exe'
            exe.write_bytes(b'X' * 130_000)
            receipt = root / 'receipt.json'
            receipt.write_text(json.dumps({'exe_sha256': '0' * 64, 'local_exe_smoke': 'PASS'}))
            args = argparse.Namespace(root=root, exe=exe, receipt=receipt,
                                      out=root / 'result.json', startup_timeout=10)
            with mock.patch.object(a.subprocess, 'Popen', side_effect=AssertionError('Must not launch')):
                result, code = a.run(args)
            self.assertEqual(code, 1)
            self.assertEqual(result['counts']['failed'], 1)
            self.assertEqual(result['manual_ui_acceptance'], 'PENDING')
            self.assertTrue((root / 'result.json').exists())
