from __future__ import annotations
import importlib.util
from pathlib import Path
import copy
import pytest

ROOT=Path(__file__).resolve().parents[1]
mod_path=ROOT/'app/core/pipeline_validation.py'
spec=importlib.util.spec_from_file_location('pipeline114',mod_path)
mod=importlib.util.module_from_spec(spec); assert spec and spec.loader; spec.loader.exec_module(mod)


def report(platform='cisco_asa'):
    return {
        'platform':{'platform_id':platform}, 'findings':[{'code':'FW-001'}],
        'summary':{'total_findings':1},
        **{name:{'platform_id':platform,'status':'complete','summary':{'warnings':0}}
           for name in ('consolidation_review','correlation_accuracy_review','report_validation_review','pdf_export_review')},
    }


@pytest.mark.parametrize('p', ['cisco_asa','fortios','snort','suricata'])
def test_platforms_have_bounded_checks_and_manual_warning(p):
    original=report(p); old=copy.deepcopy(original)
    result=mod.inspect_pipeline(original)
    assert result['platform_id']==p
    assert result['status']=='server_checks_passed'
    assert result['summary']=={'checks':9, 'passed':8, 'warnings':0, 'blockers':0, 'manual_required':1}
    assert result['stages'][-1]['result']=='manual_required'
    assert original==old


def test_missing_review_is_blocker():
    obj=report(); del obj['pdf_export_review']
    result=mod.inspect_pipeline(obj)
    assert result['status']=='blocked'
    assert result['summary']['blockers']==1


def test_wrong_review_platform_blocks():
    obj=report();obj['consolidation_review']['platform_id']='snort'
    assert mod.inspect_pipeline(obj)['summary']['blockers']==1


def test_limited_review_adds_warning():
    obj=report();obj['pdf_export_review']['status']='limited'
    assert mod.inspect_pipeline(obj)['status']=='limited'


def test_inconsistent_findings_block():
    obj=report();obj['summary']['total_findings']=2
    assert mod.inspect_pipeline(obj)['summary']['blockers']==1


def test_malformed_findings_block():
    obj=report();obj['findings']=['not a dict']
    assert mod.inspect_pipeline(obj)['summary']['blockers']>=1


def test_nonint_summary_is_warning():
    obj=report();obj['summary']['total_findings']=True
    assert mod.inspect_pipeline(obj)['summary']['warnings']==1


def test_invalid_report_or_platform_rejected():
    with pytest.raises(ValueError):mod.inspect_pipeline([])
    with pytest.raises(ValueError):mod.inspect_pipeline({'platform':{'platform_id':'unknown'}})
