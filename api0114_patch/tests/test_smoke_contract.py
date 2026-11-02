from __future__ import annotations
import importlib.util
from pathlib import Path
import pytest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('smoke114',ROOT/'scripts/smoke_test_api_011_4.py')
smoke=importlib.util.module_from_spec(spec); assert spec and spec.loader;spec.loader.exec_module(smoke)


def example():
    platform='snort'
    d={'platform':{'platform_id':platform},'findings':[],
       **{key:{'status':'limited'} for key in ('consolidation_review','correlation_accuracy_review','report_validation_review','pdf_export_review')}}
    d['pipeline_validation_review']={'platform_id':platform,'status':'limited',
                                     'summary':{'checks':2,'passed':1,'warnings':0,'blockers':0,'manual_required':1},
                                     'stages':[{},{}]}
    return d


def test_smoke_checks_counts_and_expected_keys():
    assert smoke.check_report(example())['manual_pdf_verification_required']


def test_smoke_rejects_missing_review():
    x=example();del x['correlation_accuracy_review']
    with pytest.raises(ValueError,match='Missing'):smoke.check_report(x)


def test_smoke_rejects_incorrect_check_count():
    x=example();x['pipeline_validation_review']['summary']['checks']=3
    with pytest.raises(ValueError,match='counters'):smoke.check_report(x)


def test_smoke_refuses_non_local_server(tmp_path):
    p=tmp_path/'ok.conf';p.write_text('hello',encoding='utf-8')
    with pytest.raises(ValueError,match='localhost'):smoke.upload('https://example.com',p,None)
