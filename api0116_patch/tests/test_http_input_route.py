from __future__ import annotations
import importlib.util
import sys
import types
from pathlib import Path
import httpx
import pytest
from fastapi import FastAPI, HTTPException

ROOT=Path(__file__).resolve().parents[1]


def load(path, name):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[name]=module
    spec.loader.exec_module(module)
    return module


def setup(monkeypatch):
    for name in ('app','app.core','app.api'):
        mod=types.ModuleType(name)
        mod.__path__=[]
        monkeypatch.setitem(sys.modules,name,mod)
    core=load(ROOT/'app/core/input_hardening.py','app.core.input_hardening')
    monkeypatch.setitem(sys.modules,'app.core.input_hardening',core)
    calls=[]
    upstream=types.ModuleType('app.api.pipeline_validation')
    async def analyze_pipeline_validation(*,file,platform):
        payload=await file.read()
        calls.append((payload,platform))
        if payload.startswith(b'upstream-error'):
            raise HTTPException(status_code=422,detail='Existing parser rejected input.')
        return {'platform': {'platform_id':platform or 'suricata'},'findings': [], 'summary': {'total_findings':0}}
    upstream.analyze_pipeline_validation=analyze_pipeline_validation
    monkeypatch.setitem(sys.modules,'app.api.pipeline_validation',upstream)
    route=load(ROOT/'app/api/hardened_analysis.py','app.api.hardened_analysis')
    app=FastAPI()
    app.include_router(route.router)
    return app,calls


@pytest.mark.asyncio
async def test_route_accepts_and_delegates_exact_original_bytes_once(monkeypatch):
    app,calls=setup(monkeypatch)
    raw=b'\xef\xbb\xbfconfig firewall policy\r\n edit 1\r\n'
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://local') as client:
        response=await client.post('/api/v1/analyze/hardened?platform=fortios', files={'file':('fw.conf',raw,'application/octet-stream')})
    assert response.status_code==200, response.text
    assert calls==[(raw,'fortios')]
    data=response.json()
    assert data['input_security_review']['summary']['checks_passed']==6
    assert data['findings']==[]


@pytest.mark.asyncio
@pytest.mark.parametrize('name,raw,status',[
    ('bad.conf',b'PK\x03\x04archive',422),
    ('bad.conf',b'a'* (8*1024*1024+1),413),
    ('bad.conf',b'\xff',422),
    ('../bad.conf',b'hello',422),
    ('empty.conf',b'',422),
], ids=[
    'binary-archive',
    'oversized-upload-413',
    'invalid-utf8',
    'path-like-filename',
    'empty-upload',
])
async def test_route_rejects_before_upstream(monkeypatch,name,raw,status):
    app,calls=setup(monkeypatch)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://local') as client:
        response=await client.post('/api/v1/analyze/hardened',files={'file':(name,raw,'text/plain')})
    assert response.status_code==status
    assert calls==[]
    assert 'input_security_review' not in response.text


@pytest.mark.asyncio
async def test_route_propagates_existing_analyzer_errors(monkeypatch):
    app,calls=setup(monkeypatch)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://local') as client:
        response=await client.post('/api/v1/analyze/hardened',files={'file':('f.conf',b'upstream-error\n','text/plain')})
    assert response.status_code==422
    assert len(calls)==1
    assert 'input_security_review' not in response.text
