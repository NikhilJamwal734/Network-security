from __future__ import annotations
import importlib.util
from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory
import pytest

FILE=Path(__file__).resolve().parents[1]/'app/core/pdf_export_readiness.py'
spec=importlib.util.spec_from_file_location('export113',FILE)
assert spec and spec.loader
mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)


def base():
    return {'schema_version':'1.0','platform':{'platform_id':'suricata'},
        'summary':{'total_findings':1},'findings':[{'code':'FW1'}],
        'coverage':{'domains':[],'limitations':[]},
        'consolidation_review':{'status':'reviewed_subset','summary':{}},
        'correlation_accuracy_review':{'status':'reviewed_subset','summary':{}},
        'report_validation_review':{'status':'consistent_subset','summary':{}},
        'security_score':42}


def test_nominal_preflight_preserves_upstream():
    r=base(); untouched=deepcopy(r)
    result=mod.assess_pdf_readiness(r)
    assert result['status']=='preflight_pass'
    assert result['summary']['checks']==9
    assert result['summary']['warnings']==0
    assert r==untouched


def test_missing_core_sections_block_export_preflight():
    r=base(); del r['findings']; r['coverage']=None
    result=mod.assess_pdf_readiness(r)
    assert result['status']=='blocked'
    assert result['summary']['blockers']==2
    assert result['observations'][0]['kind']=='findings_shape'


def test_warnings_do_not_change_existing_findings():
    r=base();r['findings']=[{'code':str(i)} for i in range(304)]
    before=deepcopy(r)
    result=mod.assess_pdf_readiness(r)
    assert result['status']=='limited'
    assert result['summary']['warnings']>=2
    assert any(x['kind']=='findings_truncation' for x in result['observations'])
    assert r==before


def test_missing_review_warning_not_all_clear():
    r=base();del r['report_validation_review']
    result=mod.assess_pdf_readiness(r)
    assert result['status']=='limited'
    assert any(x['kind']=='report_validation_review' for x in result['observations'])


@pytest.mark.parametrize('p', ['invalid','paloalto',None])
def test_invalid_platform_rejected(p):
    r=base();r['platform']['platform_id']=p
    with pytest.raises(ValueError):mod.assess_pdf_readiness(r)


def test_invalid_report_rejected():
    with pytest.raises(ValueError):mod.assess_pdf_readiness([])


def test_observations_bounded_and_no_original_config_leaked():
    r=base();r['findings']=[{'text':'SECRET-CONFIG'}]*500
    result=mod.assess_pdf_readiness(r)
    assert len(result['observations'])<=mod.MAX_EVIDENCE
    assert 'SECRET-CONFIG' not in repr(result)
