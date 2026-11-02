from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/install_api_010_1.py"
SPEC = importlib.util.spec_from_file_location("api0101_backend_installer", SCRIPT)
installer = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(installer)


class BackendInstallTests(unittest.TestCase):
    def _project(self, root: Path) -> Path:
        p = root / 'project'
        files = {
            'app/api/universal.py': (
                'def foo(\n    platform: str | None = Query(default=None, max_length=64),\n):\n'
                '        report = adapter.analyze(lines)\n'
            ),
            'app/api/main.py': (
                'from app.api.validated import router as validated_router\n'
                'app.include_router(validated_router)\n'
            ),
        }
        for rel, content in files.items():
            file = p / rel
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_text(content, encoding='utf-8')
        return p

    def test_install_idempotent_and_backups(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = self._project(Path(tmp))
            modified = installer.install(p)
            self.assertEqual(len(modified), 5)
            self.assertEqual(installer.install(p), [])
            self.assertIn('deep_review_router', (p / 'app/api/main.py').read_text())
            self.assertIn('_vendor_review: bool = False', (p / 'app/api/universal.py').read_text())
            self.assertIn('review_suricata', (p / 'app/core/vendor_review.py').read_text())
            self.assertTrue((p / 'app/api/main.py.before_api0101.bak').is_file())

    def test_invalid_source_atomic(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = self._project(Path(tmp))
            target = p / 'app/api/main.py'
            target.write_text('totally unrelated', encoding='utf-8')
            prior = (p / 'app/api/universal.py').read_bytes()
            with self.assertRaises(ValueError):
                installer.install(p)
            self.assertEqual((p / 'app/api/universal.py').read_bytes(), prior)
            self.assertFalse((p / 'app/api/deep_review.py').exists())


if __name__ == '__main__':
    unittest.main()
