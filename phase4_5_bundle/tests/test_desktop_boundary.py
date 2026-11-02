"""Isolated request-boundary tests; no real uploads saved."""
import importlib.util
from pathlib import Path
import unittest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

MODULE = Path(__file__).resolve().parents[1] / 'app/security/desktop_boundary.py'
spec = importlib.util.spec_from_file_location('phase45_boundary', MODULE)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class BoundaryTests(unittest.TestCase):
    def setUp(self):
        app = FastAPI()
        @app.get('/api/health')
        def health(): return {'status': 'ok'}
        @app.post('/api/upload')
        async def upload(request: Request):
            payload = await request.body()
            return {'status': 'ok', 'bytes': len(payload)}
        app.add_middleware(mod.DesktopBoundaryMiddleware, max_bytes=64*1024)
        self.client = TestClient(app)

    def test_health(self):
        r = self.client.get('/api/health')
        self.assertEqual(r.status_code, 200)

    def test_local_vite_origin_allowed(self):
        r = self.client.post('/api/upload', content=b'test', headers={'Origin':'http://localhost:5173'})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()['bytes'], 4)

    def test_reject_foreign_origin(self):
        self.assertEqual(self.client.post('/api/upload', content=b'test',headers={'Origin':'https://attacker.test'}).status_code,403)

    def test_reject_untrusted_host(self):
        self.assertEqual(self.client.get('/api/health', headers={'Host': 'attacker.test'}).status_code,400)
        self.assertEqual(self.client.get('/api/health', headers={'Host': '127.0.0.1#attacker'}).status_code,400)

    def test_reject_oversized_body(self):
        self.assertEqual(self.client.post('/api/upload',content=b'A'*70_000).status_code,413)

    def test_no_header_echo(self):
        r = self.client.get('/api/health',headers={'Host':'secret.example'})
        self.assertNotIn('secret.example',r.text)

    def test_loopback_helpers(self):
        for host in ('localhost','127.0.0.1','::1','[::1]','testserver'):
            self.assertTrue(mod.loopback(host))
        for host in ('example.com','192.168.1.10','8.8.8.8',''):
            self.assertFalse(mod.loopback(host))

    def test_reject_origin_without_port(self):
        self.assertFalse(mod.allowed_origin('https://example.com'))
        self.assertFalse(mod.allowed_origin('http://127.0.0.1:1234/evil'))
        self.assertTrue(mod.allowed_origin('http://127.0.0.1:58921'))

if __name__ == '__main__': unittest.main()
