from __future__ import annotations
import ast
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

BASE = Path(__file__).resolve().parents[1]


class BuildContractTests(unittest.TestCase):
    def test_files_are_valid_python(self):
        for name in ("desktop_launcher.py", "build_exe.py"):
            ast.parse((BASE / name).read_text(encoding="utf-8"))

    def test_build_guards_missing_api_and_frontend(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("build_kit", BASE / "build_exe.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.assertRaises(FileNotFoundError):
                module.plan(root, "python")
            (root / "app/api").mkdir(parents=True)
            (root / "app/api/main.py").write_text("app = 1", encoding="utf-8")
            with self.assertRaises(FileNotFoundError):
                module.plan(root, "python")
            (root / "frontend/dist").mkdir(parents=True)
            (root / "frontend/dist/index.html").write_text("<html/>", encoding="utf-8")
            (root / "desktop_packaging").mkdir()
            (root / "desktop_packaging/desktop_launcher.py").write_text("# launcher\n", encoding="utf-8")
            args = module.plan(root, "python")
            self.assertIn("--onedir", args)
            self.assertIn("--add-data", args)
            self.assertNotIn("--onefile", args)
            data_arg = args[args.index("--add-data") + 1]
            src, dst = data_arg.rsplit(":", 1)
            self.assertEqual(Path(src), (root / "frontend" / "dist").resolve())
            self.assertEqual(dst, "frontend/dist")
            self.assertTrue(Path(src).is_absolute())

    def test_launcher_routes_api_and_static_separately(self):
        code = (BASE / "desktop_launcher.py").read_text(encoding="utf-8")
        self.assertIn('from app.api.main import app as backend_app', code)
        self.assertIn('path.startswith("/api/")', code)
        self.assertIn('listener.bind(("127.0.0.1", 0))', code)
        self.assertIn('is_relative_to(root)', code)


if __name__ == "__main__":
    unittest.main()
