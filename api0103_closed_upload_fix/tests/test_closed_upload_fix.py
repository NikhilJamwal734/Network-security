"""Check that the actual API endpoint survives prior analysis closing the upload."""
import asyncio
from io import BytesIO
from pathlib import Path
import importlib.util
import sys
import types
import unittest
from unittest.mock import patch
from fastapi import FastAPI, UploadFile
from fastapi.testclient import TestClient

PKG = Path(__file__).resolve().parents[1]
INSTALLER = PKG / 'scripts' / 'fix_closed_upload.py'
ORIGINAL_FIXTURE = PKG / 'tests' / 'fixtures' / 'original_rule_correlation.py.txt'

def load_script():
    spec = importlib.util.spec_from_file_location('api0103_upload_installer', INSTALLER)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m

def load_endpoint(source):
    # Only the small pure correlation function is stubbed; the endpoint's UploadFile
    # lifecycle, FastAPI multipart handling, and re-reading behavior are real.
    app_pkg = types.ModuleType('app'); app_pkg.__path__ = []
    api_pkg = types.ModuleType('app.api'); api_pkg.__path__ = []
    core_pkg = types.ModuleType('app.core'); core_pkg.__path__ = []
    correlation_stub = types.ModuleType('app.core.rule_correlation')
    correlation_stub.correlate_rules = lambda platform, text, source_truncated=False: {'platform_id': platform, 'snippet': text, 'truncated': source_truncated}
    with patch.dict(sys.modules, {'app':app_pkg,'app.api':api_pkg,'app.core':core_pkg,'app.core.rule_correlation': correlation_stub}):
        spec=importlib.util.spec_from_loader('app.api.rule_correlation', loader=None)
        m=types.ModuleType('app.api.rule_correlation')
        m.__spec__=spec
        sys.modules['app.api.rule_correlation'] = m
        try:
            exec(compile(source,'app/api/rule_correlation.py','exec'), m.__dict__)
        finally:
            sys.modules.pop('app.api.rule_correlation',None)
    return m

class ClosedUploadTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original=ORIGINAL_FIXTURE.read_text(encoding='utf-8')
        cls.installer=load_script()

    def test_patch_idempotent(self):
        updated=self.installer.patch_source(self.original)
        self.assertEqual(self.installer.patch_source(updated), updated)

    def test_old_endpoint_fails_when_upstream_closes_upload(self):
        m=load_endpoint(self.original)
        async def fake_previous(*,file,platform):
            await file.read()
            await file.close()
            return {'platform':{'platform_id': platform}}
        m._run_precision=fake_previous
        upload=UploadFile(file=BytesIO(b'alert tcp any any -> any any (sid:1;)\n'),filename='test.rules')
        with self.assertRaises(ValueError):
            asyncio.run(m.analyze_rule_correlation(file=upload,platform='snort'))

    def test_fixed_endpoint_succeeds_even_when_upstream_closes_upload(self):
        m=load_endpoint(self.installer.patch_source(self.original))
        async def fake_previous(*,file,platform):
            data=await file.read()
            self.assertEqual(data,b'alert tcp any any -> any any (sid:1;)\n')
            await file.close()
            return {'platform': {'platform_id': platform}, 'findings': [], 'summary': {'total_findings': 0}}
        m._run_precision=fake_previous
        upload=UploadFile(file=BytesIO(b'alert tcp any any -> any any (sid:1;)\n'),filename='test.rules')
        result=asyncio.run(m.analyze_rule_correlation(file=upload,platform='snort'))
        self.assertEqual(result['findings'],[])
        self.assertIn('alert tcp',result['rule_correlation']['snippet'])

    def test_fastapi_post_succeeds_and_preserves_fields(self):
        m=load_endpoint(self.installer.patch_source(self.original))
        async def fake_previous(*,file,platform):
            data=await file.read()
            self.assertEqual(data,b'access-list A extended permit ip any any\n')
            await file.close()
            return {'platform': {'platform_id': platform}, 'findings': [], 'assessment': {'review_score': {'value': 80}}}
        m._run_precision=fake_previous
        app=FastAPI();app.include_router(m.router)
        with TestClient(app) as client:
            r=client.post('/api/v1/analyze/rule-correlation?platform=cisco_asa',files={'file':('a.txt',b'access-list A extended permit ip any any\n','text/plain')})
        self.assertEqual(r.status_code,200,r.text)
        self.assertEqual(r.json()['assessment']['review_score']['value'],80)
        self.assertIn('access-list',r.json()['rule_correlation']['snippet'])

    def test_bounded_sample_read_preserves_truncated_flag(self):
        m=load_endpoint(self.installer.patch_source(self.original))
        m._MAX_CORRELATION_BYTES=6
        async def fake_previous(*,file,platform):
            await file.read()
            await file.close()
            return {'platform':{'platform_id': platform}}
        m._run_precision=fake_previous
        upload=UploadFile(file=BytesIO(b'0123456789'),filename='a.txt')
        res=asyncio.run(m.analyze_rule_correlation(file=upload,platform='cisco_asa'))
        self.assertEqual(res['rule_correlation']['snippet'],'012345')
        self.assertTrue(res['rule_correlation']['truncated'])

if __name__=='__main__':unittest.main()
