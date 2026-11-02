"""Run: .venv-win\\Scripts\\python.exe -m unittest discover -s desktop_packaging/tests -p test_desktop_port_fix.py -v"""
from __future__ import annotations
import asyncio
import importlib.util
import sys
import tempfile
import types
import unittest
from pathlib import Path
from starlette.requests import Request
from fastapi import HTTPException

LAUNCHER = Path(__file__).resolve().parents[1] / "desktop_launcher.py"


def load_launcher():
    # Unit test the shipped launcher without requiring the entire analyzer tree.
    previous = {name: sys.modules.get(name) for name in ("app", "app.api", "app.api.main")}
    for name in ("app", "app.api"):
        pkg = types.ModuleType(name)
        pkg.__path__ = []
        sys.modules[name] = pkg
    main = types.ModuleType("app.api.main")
    async def backend_app(scope, receive, send):
        return None
    main.app = backend_app
    sys.modules["app.api.main"] = main
    try:
        spec = importlib.util.spec_from_file_location("desktop_launcher_test", LAUNCHER)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        for name, value in previous.items():
            if value is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = value


class DesktopPortTests(unittest.TestCase):
    def setUp(self):
        self.mod = load_launcher()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.mod.DIST = Path(self.tmp.name)
        (self.mod.DIST / "assets").mkdir()

    def req(self, path, *, port=49281):
        return Request({
            "type": "http", "method": "GET", "path": "/" + path,
            "path_params": {"path": path}, "root_path": "",
            "server": ("127.0.0.1", port), "headers": [], "query_string": b"",
        })

    def test_rewrites_both_absolute_development_origins(self):
        asset = self.mod.DIST / "assets" / "app.js"
        original = b'fetch("http://127.0.0.1:8000/api/v1/platforms"); fetch("http://localhost:8000/api/health")'
        asset.write_bytes(original)
        response = asyncio.run(self.mod.frontend_page(self.req("assets/app.js", port=49330)))
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"http://127.0.0.1:49330/api/v1/platforms", response.body)
        self.assertIn(b"http://127.0.0.1:49330/api/health", response.body)
        self.assertNotIn(b"8000", response.body)
        self.assertEqual(asset.read_bytes(), original)
        self.assertEqual(response.headers["cache-control"], "no-store")

    def test_history_route_serves_index_with_current_origin(self):
        (self.mod.DIST / "index.html").write_text(
            '<html><script>const api="http://127.0.0.1:8000";</script></html>', encoding="utf8")
        response = asyncio.run(self.mod.frontend_page(self.req("dashboard",port=42001)))
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"http://127.0.0.1:42001", response.body)

    def test_non_api_assets_remain_unchanged(self):
        asset = self.mod.DIST / "assets" / "styles.css"
        asset.write_text("body { color: red; }", encoding="utf8")
        response = asyncio.run(self.mod.frontend_page(self.req("assets/styles.css")))
        from fastapi.responses import FileResponse
        self.assertIsInstance(response, FileResponse)

    def test_failed_assets_return_404_not_html(self):
        (self.mod.DIST / "index.html").write_text("homepage",encoding="utf8")
        with self.assertRaises(HTTPException) as ctx:
            asyncio.run(self.mod.frontend_page(self.req("assets/missing.js")))
        self.assertEqual(ctx.exception.status_code, 404)

    def test_no_rewrite_without_valid_server_metadata(self):
        path = self.mod.DIST / "assets" / "app.js"
        path.write_bytes(b'"http://127.0.0.1:8000"')
        request = self.req("assets/app.js")
        request.scope.pop("server")
        response = asyncio.run(self.mod.frontend_page(request))
        from fastapi.responses import FileResponse
        self.assertIsInstance(response, FileResponse)

    def test_invalid_ports_fail_safely(self):
        with self.assertRaises(ValueError):
            self.mod.resolve_api_origin(b"hello", 0)
        with self.assertRaises(ValueError):
            self.mod.resolve_api_origin(b"hello", 65536)


if __name__ == "__main__":
    unittest.main()
