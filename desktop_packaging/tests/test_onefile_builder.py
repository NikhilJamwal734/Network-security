"""Tests for the safe onefile build planner. No executable is built in tests."""
from pathlib import Path
from tempfile import TemporaryDirectory
import importlib.util
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "build_onefile.py"
spec = importlib.util.spec_from_file_location("onefile_builder", SCRIPT)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def setup_root(root: Path, launcher_text=None):
    (root / "app/api").mkdir(parents=True)
    (root / "app/api/main.py").write_text("app = None\n", encoding="utf-8")
    (root / "frontend/dist").mkdir(parents=True)
    (root / "frontend/dist/index.html").write_text("<html></html>", encoding="utf-8")
    (root / "desktop_packaging").mkdir(parents=True)
    if launcher_text is None:
        launcher_text = 'import sys\nroot = sys._MEIPASS\ndef resolve_api_origin(*a): pass\n'
    (root / "desktop_packaging/desktop_launcher.py").write_text(launcher_text, encoding="utf-8")


class OnefileBuildTests(unittest.TestCase):
    def test_single_exe_command_and_bundled_assets(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            setup_root(root)
            result = mod.plan(root, "python.exe")
            self.assertIn("--onefile", result)
            self.assertNotIn("--onedir", result)
            self.assertEqual(result[result.index("--distpath") + 1], str(root / "desktop_release_single"))
            self.assertEqual(result[result.index("--add-data") + 1], f"{root / 'frontend/dist'}:frontend/dist")
            self.assertIn(str(root / "desktop_packaging/desktop_launcher.py"), result)

    def test_no_secrets_or_source_trees_in_datas(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            setup_root(root)
            args = mod.plan(root, "py")
            data_args = [args[i+1] for i,item in enumerate(args) if item == "--add-data"]
            self.assertEqual(len(data_args), 1)
            self.assertNotIn("node_modules", data_args[0])
            self.assertNotIn("reports", data_args[0])

    def test_missing_compiled_frontend_fails(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            setup_root(root)
            (root / "frontend/dist/index.html").unlink()
            with self.assertRaisesRegex(FileNotFoundError, "npm --prefix frontend run build"):
                mod.plan(root, "py")

    def test_unpatched_launcher_fails(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            setup_root(root, launcher_text='import sys\nroot = sys._MEIPASS\n')
            with self.assertRaisesRegex(ValueError, "localhost API port fix"):
                mod.plan(root, "py")

    def test_bom_launcher_accepted(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            setup_root(root)
            path = root / "desktop_packaging/desktop_launcher.py"
            path.write_bytes(b"\xef\xbb\xbf" + path.read_bytes())
            self.assertIn("--onefile", mod.plan(root, "py"))


if __name__ == "__main__":
    unittest.main()
