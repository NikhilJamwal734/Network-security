from __future__ import annotations
from importlib.util import module_from_spec, spec_from_file_location
import os
from pathlib import Path
import shutil
import tempfile
import unittest
import sys
from types import ModuleType
from unittest.mock import patch
from fastapi import FastAPI


HERE = Path(__file__).resolve().parents[1]


def load(name, filename):
    spec = spec_from_file_location(name, HERE / filename)
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


build = load("build_complete_exe", "build_complete_exe.py")
# The packaging kit does not ship the user's analyzer source. Import the
# launcher using a disposable FastAPI stub, leaving the real project untouched.
_fake_app = ModuleType("app")
_fake_app.__path__ = []
_fake_api = ModuleType("app.api")
_fake_api.__path__ = []
_fake_main = ModuleType("app.api.main")
_fake_main.app = FastAPI()
with patch.dict(sys.modules, {"app": _fake_app, "app.api": _fake_api,
                              "app.api.main": _fake_main}):
    launcher = load("desktop_launcher_complete", "desktop_launcher_complete.py")


class BuildTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        for name, content in {
            "app/api/main.py": "from fastapi import FastAPI\napp = FastAPI()\n",
            "frontend/package.json": '{"scripts":{"build":"vite build"}}',
            "frontend/index.html": "<html></html>",
            "frontend/dist/index.html": "<html></html>",
            "frontend/vite.config.ts": 'export default {}',
            "desktop_packaging/desktop_launcher_complete.py": '# launcher',
        }.items():
            p = self.root / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content, encoding="utf-8")

    def test_layout_works_without_logs(self):
        f = build.validate_project(self.root)
        self.assertFalse(f["logs_html"])
        self.assertFalse(f["logging"])

    def test_log_html_requires_entrypoint(self):
        (self.root / "frontend/logs.html").write_text("hello")
        with self.assertRaisesRegex(ValueError, "Incomplete standalone"):
            build.validate_project(self.root)

    def test_log_api_requires_registration(self):
        (self.root / "frontend/logs.html").write_text("hello")
        (self.root / "frontend/src/logs-main.tsx").parent.mkdir(exist_ok=True)
        (self.root / "frontend/src/logs-main.tsx").write_text("// entry")
        (self.root / "app/api/log_viewer.py").write_text("# api")
        with self.assertRaisesRegex(ValueError, "not wired"):
            build.validate_project(self.root)

    def test_temp_config_keeps_original_unchanged(self):
        original = (self.root / "frontend/vite.config.ts").read_bytes()
        (self.root / "frontend/logs.html").write_text("hello")
        with build.temporary_multipage_config(self.root):
            tmp = self.root / "frontend/.firewall-desktop-vite.config.mts"
            self.assertTrue(tmp.is_file())
            self.assertIn('logs: resolve', tmp.read_text())
        self.assertFalse(tmp.exists())
        self.assertEqual(original, (self.root / "frontend/vite.config.ts").read_bytes())

    def test_temp_config_cleans_after_exception(self):
        (self.root / "frontend/logs.html").write_text("hello")
        with self.assertRaisesRegex(RuntimeError, "example"):
            with build.temporary_multipage_config(self.root):
                raise RuntimeError("example")
        self.assertFalse((self.root / "frontend/.firewall-desktop-vite.config.mts").exists())

    def test_packager_includes_compiled_assets(self):
        cmd = build.build_command(self.root, "python", onefile=True)
        self.assertIn("--onefile", cmd)
        self.assertIn("--collect-submodules", cmd)
        self.assertIn("app", cmd)
        self.assertTrue(any("frontend/dist" in x for x in cmd))
        self.assertNotIn(".venv-win", " ".join(cmd))
        self.assertNotIn("logs/", " ".join(cmd))

    def test_packager_refuses_missing_compiled_logs_page(self):
        (self.root / "frontend/logs.html").write_text("hello")
        with self.assertRaisesRegex(FileNotFoundError, "Logs page"):
            build.build_command(self.root, "python")

    def test_onedir_build_plan(self):
        cmd = build.build_command(self.root, "python", onefile=False)
        self.assertIn("--onedir", cmd)
        self.assertNotIn("--onefile", cmd)


class LauncherTests(unittest.TestCase):
    def test_rewrites_only_dev_origins(self):
        original = (b"fetch('http://127.0.0.1:8000/api/report')\n"
                    b"fetch('http://localhost:8000/api/v1/logs')\n"
                    b"external=https://docs.example.com/v1")
        result = launcher.replace_development_api_origin(original, 44555)
        self.assertIn(b"http://127.0.0.1:44555/api/report", result)
        self.assertIn(b"http://127.0.0.1:44555/api/v1/logs", result)
        self.assertIn(b"https://docs.example.com/v1", result)
        self.assertNotIn(b":8000", result)

    def test_invalid_port(self):
        with self.assertRaises(ValueError):
            launcher.replace_development_api_origin(b"http://127.0.0.1:8000", 0)

    def test_asset_path_traversal(self):
        self.assertIsNone(launcher._asset_path("../app/core/audit_logging.py"))
        self.assertIsNone(launcher._asset_path(r"\\server\share"))

    def test_assets_and_spa(self):
        with tempfile.TemporaryDirectory() as tmp:
            import unittest.mock
            root = Path(tmp)
            (root / "index.html").write_text("INDEX")
            (root / "logs.html").write_text("LOGS")
            (root / "assets").mkdir()
            (root / "assets/app.js").write_text("JS")
            with unittest.mock.patch.object(launcher, "DIST", root):
                self.assertEqual(launcher._asset_path("/"), root / "index.html")
                self.assertEqual(launcher._asset_path("/logs.html"), root / "logs.html")
                self.assertEqual(launcher._asset_path("/assets/app.js"), root / "assets/app.js")
                self.assertEqual(launcher._asset_path("/dashboard"), root / "index.html")
                self.assertIsNone(launcher._asset_path("/assets/missing.js"))

    def test_served_json_logs_and_origin_replacement(self):
        import asyncio
        import httpx
        import unittest.mock
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "index.html").write_text('<script src="http://127.0.0.1:8000/api/report"></script>')
            (root / "logs.html").write_text('<h1>JSON logs</h1>')
            async def check():
                async with httpx.AsyncClient(
                    transport=httpx.ASGITransport(app=launcher.application),
                    base_url="http://127.0.0.1:44555"
                ) as client:
                    main = await client.get("/")
                    logs = await client.get("/logs.html")
                    missing = await client.get("/absent.js")
                    denied = await client.get("/", headers={"host": "example.com"})
                    self.assertEqual(main.status_code, 200)
                    self.assertIn("http://127.0.0.1:44555/api/report", main.text)
                    self.assertEqual(logs.status_code, 200)
                    self.assertIn("JSON logs", logs.text)
                    self.assertEqual(missing.status_code, 404)
                    self.assertEqual(denied.status_code, 400)
            with unittest.mock.patch.object(launcher, "DIST", root):
                asyncio.run(check())

    def test_api_forwarding(self):
        self.assertTrue(launcher._is_backend_path("/api/v1/logs"))
        self.assertTrue(launcher._is_backend_path("/api/report"))
        self.assertTrue(launcher._is_backend_path("/docs"))
        self.assertFalse(launcher._is_backend_path("/logs.html"))


if __name__ == "__main__":
    unittest.main()
