from __future__ import annotations
import importlib.util
from pathlib import Path
import tempfile
import unittest

INSTALLER = Path(__file__).resolve().parents[1] / 'scripts/install_api_010_3.py'
spec = importlib.util.spec_from_file_location('api0103_installer', INSTALLER)
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.project = Path(self.tmp.name) / 'config analyzer'
        (self.project / 'app/api').mkdir(parents=True)
        (self.project / 'app/core').mkdir(parents=True)
        (self.project / 'tests').mkdir()
        self.main = self.project / 'app/api/main.py'
        self.main.write_text('from fastapi import FastAPI\n'
          'from app.api.precision_review import router as precision_review_router\n'
          'app = FastAPI()\napp.include_router(precision_review_router)\n')
        for f in ('app/api/precision_review.py', 'app/core/precision_review.py',
                  'app/core/precision_enhancements.py'):
            (self.project / f).write_text('# Installed API-010.2.1\n')

    def test_installs_once_backups_existing_and_registers_route(self):
        updates = installer.install(self.project)
        self.assertEqual(len(updates), 4)
        self.assertEqual(installer.install(self.project), [])
        contents = self.main.read_text()
        self.assertEqual(contents.count('app.include_router(rule_correlation_router)'), 1)
        self.assertEqual(contents.count('from app.api.rule_correlation import router'), 1)
        self.assertTrue((self.project / 'app/api/main.py.before_api0103.bak').exists())

    def test_fails_fast_missing_predecessor(self):
        (self.project / 'app/api/precision_review.py').unlink()
        initial = self.main.read_text()
        with self.assertRaisesRegex(ValueError, 'prerequisite missing'):
            installer.install(self.project)
        self.assertEqual(self.main.read_text(), initial)

    def test_fails_fast_unrecognized_main(self):
        self.main.write_text('app = FastAPI()\n')
        with self.assertRaisesRegex(ValueError, 'Unknown'):
            installer.install(self.project)
        self.assertFalse((self.project / 'app/core/rule_correlation.py').exists())

    def test_installer_handles_windows_project_root_with_spaces(self):
        results = installer.install(self.project)
        self.assertIn('app/core/rule_correlation.py', [p.replace('\\','/') for p in results])


if __name__ == '__main__':
    unittest.main()
