"""In-process HTTP contract test; exercises the real API-011.4 route and upload.

The 11.3 chain is stubbed here to isolate API-011.4's delegation behavior.
The separate localhost smoke tool exercises the deployed complete chain.
"""
from __future__ import annotations
import importlib.util
import sys
import types
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI, HTTPException

ROOT=Path(__file__).resolve().parents[1]


def module_from(path, name):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def setup_router(monkeypatch):
    for package in ('app','app.core','app.api'):
        mod=types.ModuleType(package)
        mod.__path__=[]
        monkeypatch.setitem(sys.modules,package,mod)
    core=module_from(ROOT/'app/core/pipeline_validation.py','app.core.pipeline_validation')
    monkeypatch.setitem(sys.modules,'app.core.pipeline_validation',core)
    upstream=types.ModuleType('app.api.pdf_export_readiness')
    calls=[]

    async def analyze_pdf_readiness(*,file,platform):
        content=await file.read()
        calls.append((content,platform))
        if not content: raise HTTPException(status_code=400,detail='empty input rejected upstream')
        name=platform or 'cisco_asa'
        report={'platform':{'platform_id':name},'summary':{'total_findings':0},'findings':[]}
        for key in ('consolidation_review','correlation_accuracy_review','report_validation_review','pdf_export_review'):
            report[key]={'platform_id':name,'status':'complete','summary':{'warnings':0}}
        return report

    upstream.analyze_pdf_readiness=analyze_pdf_readiness
    monkeypatch.setitem(sys.modules,'app.api.pdf_export_readiness',upstream)
    route=module_from(ROOT/'app/api/pipeline_validation.py','app.api.pipeline_validation')
    app=FastAPI()
    app.include_router(route.router)
    return app,calls


@pytest.mark.asyncio
async def test_actual_multipart_route_calls_upstream_once(monkeypatch):
    app,calls=setup_router(monkeypatch)
    transport=httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport,base_url='http://test') as client:
        response=await client.post('/api/v1/analyze/pipeline-validation?platform=snort',
                                   files={'file':('snort.lua', b'ips = { }','text/plain')})
    assert response.status_code==200
    data=response.json()
    assert calls==[(b'ips = { }','snort')]
    assert data['platform']['platform_id']=='snort'
    assert data['pdf_export_review']['platform_id']=='snort'
    assert data['pipeline_validation_review']['summary']['manual_required']==1
    assert data['pipeline_validation_review']['summary']['blockers']==0


@pytest.mark.asyncio
async def test_upstream_upload_failure_propagates_without_false_success(monkeypatch):
    app,calls=setup_router(monkeypatch)
    transport=httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport,base_url='http://test') as client:
        response=await client.post('/api/v1/analyze/pipeline-validation',
                                   files={'file':('empty.conf',b'','text/plain')})
    assert response.status_code==400
    assert calls==[(b'',None)]
    assert 'pipeline_validation_review' not in response.text
