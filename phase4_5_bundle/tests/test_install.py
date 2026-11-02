import importlib.util
from pathlib import Path
import tempfile
import unittest

MOD = Path(__file__).resolve().parents[1] / 'scripts/install.py'
spec = importlib.util.spec_from_file_location('install45', MOD)
install = importlib.util.module_from_spec(spec)
spec.loader.exec_module(install)


class InstallerTests(unittest.TestCase):
    def fixture(self, root):
        main = "from app.core.audit_logging import AccessAuditMiddleware\napp.include_router(f5_phase1_addon_router)\napp.add_middleware(AccessAuditMiddleware)\n"
        api = "from app.f5_phase1_addon.checks import analyze\n" + "    report = extend_report(report, objects, decoded_text, evidence_json)\n" + "    return {**report, 'input_security_review': validation}\n"
        adapter = "    ...(isObject(body.input_security_review) ? { input_security_review: body.input_security_review } : {}),\n"
        pdf = "  if (f5Phase1Review) {\n    section(\"F5 BIG-IP Phases 1 + 2 - Detailed technical evidence\");\n  }\nconst f5Phase1Review = null;\n"
        mapping = {install.MAIN:main,install.API:api,install.ADAPTER:adapter,install.PDF:pdf}
        for path, text in mapping.items():
            target = root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text,encoding='utf-8')
        return mapping

    def test_roundtrip_rollback(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            originals = self.fixture(root)
            self.assertEqual(len(install.install(root,dry_run=True)),7)
            self.assertEqual(len(install.install(root)),7)
            self.assertEqual(install.install(root),[])
            self.assertEqual(len(install.rollback(root)),7)
            for path, source in originals.items():
                self.assertEqual((root/path).read_text(),source)
            self.assertFalse((root/install.MANIFEST).exists())

    def test_changed_file_refuses_rollback(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); self.fixture(root)
            install.install(root)
            (root/install.API).write_text('tampered',encoding='utf-8')
            with self.assertRaises(ValueError):
                install.rollback(root)

    def test_unknown_pdf_refuses_preflight(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); self.fixture(root)
            (root/install.PDF).write_text('unexpected',encoding='utf-8')
            with self.assertRaises(ValueError):
                install.install(root,dry_run=True)
            self.assertFalse((root/install.MANIFEST).exists())

    def test_preserve_crlf(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); self.fixture(root)
            p=root/install.API
            p.write_bytes(p.read_bytes().replace(b'\r\n',b'\n').replace(b'\n',b'\r\n'))
            install.install(root)
            raw=p.read_bytes()
            self.assertIn(b'\r\n',raw)
            self.assertNotIn(b'\n',raw.replace(b'\r\n',b''))

if __name__ == '__main__': unittest.main()
