"""Direct unit checks of the static, read-only report contract preflight."""
from __future__ import annotations
import importlib.util
from pathlib import Path
from copy import deepcopy
import pytest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT/'app/core/report_validation.py'
if not SOURCE.is_file(): SOURCE = ROOT/'api0112_patch/app/core/report_validation.py'
spec = importlib.util.spec_from_file_location('validation112_core', SOURCE)
assert spec and spec.loader
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def report(platform='suricata'):
    return {
        'platform': {'platform_id':platform}, 'summary': {'total_findings':1},
        'score':77,
        'findings':[{'code':'SEC-001','line_number':10,'severity':'HIGH','title':'Example'}],
        'consolidation_review': {
            'platform_id':platform,'status':'reviewed_subset',
            'summary':{'sections_present':1,'candidate_links':1,'incomplete':False},
            'sections':[{'availability':'returned'}], 'issues':[],
            'links':[{'reference':'LINK-001'}],
        },
        'correlation_accuracy_review': {
            'platform_id':platform,'status':'reviewed_subset',
            'summary':{'links_checked':1,'plausible_links':1,'unsupported_links':0,
                       'uncertain_links':0,'incomplete':False},
            'decisions':[{'reference':'ACCL-001'}], 'quality_observations':[],
        },
    }


@pytest.mark.parametrize('platform',['cisco_asa','fortios','snort','suricata'])
def test_platform_and_original_not_modified(platform):
    data = report(platform)
    before = deepcopy(data)
    output = mod.validate_report_contract(data)
    assert data == before
    assert output['platform_id'] == platform
    assert output['status'] == 'consistent_subset'
    assert output['summary']['discrepancies'] == 0
    assert len(output['checks']) <= mod.MAX_CHECKS


def test_counter_mismatch_is_inconsistent_and_does_not_modify_score():
    data = report()
    data['summary']['total_findings'] = 123
    output = mod.validate_report_contract(data)
    assert output['status'] == 'inconsistent'
    assert any(x['check'] == 'finding_total' and x['result'] == 'discrepancy' for x in output['checks'])
    assert data['score'] == 77


def test_upstream_cross_review_counter_drift():
    data = report('fortios')
    data['consolidation_review']['summary']['candidate_links'] = 4
    assert mod.validate_report_contract(data)['summary']['discrepancies'] > 0
    data = report()
    data['correlation_accuracy_review']['summary']['unsupported_links'] = 7
    assert mod.validate_report_contract(data)['summary']['discrepancies'] > 0


def test_omitted_items_are_warnings_not_false_clean_pass():
    data = report()
    data['correlation_accuracy_review']['status'] = 'limited'
    data['correlation_accuracy_review']['summary']['incomplete'] = True
    data['correlation_accuracy_review']['summary']['items_omitted'] = 3
    output = mod.validate_report_contract(data)
    assert output['status'] == 'limited'
    assert output['summary']['warnings'] >= 1
    assert output['summary']['incomplete'] is True


def test_invalid_review_and_missing_dependency_detected():
    data = report()
    del data['correlation_accuracy_review']
    assert mod.validate_report_contract(data)['status'] == 'inconsistent'
    data = report()
    data['consolidation_review']['links'] = 'invalid'
    assert mod.validate_report_contract(data)['status'] == 'inconsistent'


def test_unknown_platform_rejected():
    with pytest.raises(ValueError): mod.validate_report_contract({'platform':{'platform_id':'fake'}})


def test_capped_output_reports_omissions():
    data = report()
    data['findings'] = [{} for _ in range(mod.MAX_FINDINGS + 2)]
    data['summary']['total_findings'] = len(data['findings'])
    x = mod.validate_report_contract(data)
    assert x['status'] == 'limited'
    assert x['summary']['items_omitted'] >= 2
    assert len(x['checks']) <= mod.MAX_CHECKS


def test_no_sensitive_configuration_values_copied():
    data = report()
    data['findings'][0]['description'] = 'secret-marker-should-never-be-copied'
    assert 'secret-marker' not in str(mod.validate_report_contract(data))


def test_rendering_explicitly_not_verified():
    data = report()
    text = ' '.join(mod.validate_report_contract(data)['limitations'])
    assert 'NOT verified' in text
