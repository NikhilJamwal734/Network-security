"""No provider/network access; predictable static report fixtures."""
from __future__ import annotations
import asyncio
from copy import deepcopy
from io import BytesIO

import pytest
from app.core.consolidation import consolidate_report, MAX_EXAMINED


def fixture(platform='cisco_asa'):
    report = {
        'platform': {'platform_id': platform},
        'score': 91,
        'summary': {'total_findings': 2},
        'findings': [
            {'code': 'FW-123', 'title': 'Broad entry', 'line_number': 5, 'severity': 'HIGH'},
            {'code': 'FW-234', 'title': 'Old entry', 'line_number': 3, 'severity': 'LOW'},
        ],
    }
    if platform in ('cisco_asa', 'fortios'):
        report['object_resolution'] = {'status': 'reviewed_subset', 'platform_id': platform, 'summary': {},
             'evidence': [{'kind': 'FW-123', 'title': 'Broad entry', 'line_number': 5, 'reference': 'OBJ-1'}]}
        report['nat_route_reachability'] = {'status': 'reviewed_subset', 'platform_id': platform,
            'summary': {'incomplete': False}, 'evidence': [{'kind': 'route_declared', 'title': 'Route', 'line_number': 10}]}
    else:
        report['ids_deep_review'] = {'status': 'reviewed_subset', 'platform_id': platform,
            'summary': {'evidence_items': 1, 'incomplete': False},
            'evidence': [{'reference': 'IDS-001', 'kind': 'broad_home_net_selector', 'line_number': 8,
                          'title': 'HOME_NET permits any address'}]}
    return report


@pytest.mark.parametrize('platform', ['cisco_asa','fortios','snort','suricata'])
def test_supported_platforms_preserve_input_and_provenance(platform):
    original = fixture(platform)
    snapshot = deepcopy(original)
    review = consolidate_report(original)
    assert original == snapshot
    assert review['platform_id'] == platform
    assert review['summary']['sections_present'] >= 2
    assert review['summary']['advisory_items_examined'] >= 2
    assert review['limitations']
    assert len(review['sections']) == 6


def test_link_only_across_distinct_sources_same_line_kind_title():
    r = fixture('cisco_asa')
    output = consolidate_report(r)
    assert output['summary']['candidate_links'] == 1
    link = output['links'][0]
    assert link['source_line'] == 5
    assert len(link['related']) == 2
    assert {x['section'] for x in link['related']} == {'normalized_findings', 'object_resolution'}
    # Matching line alone or kind alone is insufficient.
    r['object_resolution']['evidence'][0]['title'] = 'Unrelated observation'
    assert consolidate_report(r)['links'] == []


def test_no_links_for_same_section_repeated_entries():
    r = fixture('snort')
    r['ids_deep_review']['evidence'] *= 2
    r['ids_deep_review']['summary']['evidence_items'] = 2
    output = consolidate_report(r)
    assert output['links'] == []


def test_context_mismatch_is_metadata_only():
    r = fixture()
    r['object_resolution']['platform_id'] = 'fortios'
    output = consolidate_report(r)
    assert output['issues'][0]['kind'] == 'platform_context_mismatch'
    assert output['issues'][0]['confidence'] == 'report_metadata_only'


def test_count_mismatch_is_reported_not_rewritten():
    r = fixture('suricata')
    r['ids_deep_review']['summary']['evidence_items'] = 99
    result = consolidate_report(r)
    assert any(x['kind'] == 'reported_count_mismatch' for x in result['issues'])
    assert r['ids_deep_review']['summary']['evidence_items'] == 99


def test_incomplete_and_missing_are_not_clean_pass():
    r = fixture('fortios')
    r['nat_route_reachability']['status'] = 'limited'
    r['nat_route_reachability']['summary']['incomplete'] = True
    r['nat_route_reachability']['summary']['items_omitted'] = 5
    result = consolidate_report(r)
    assert result['status'] == 'limited'
    assert result['summary']['items_omitted'] == 5
    assert result['summary']['sections_unavailable'] > 0  # unreturned service IPv6 etc.


def test_invalid_context_and_shape_explicitly_handled():
    with pytest.raises(ValueError):
        consolidate_report({'platform': {'platform_id': 'mystery'}})
    r = fixture('snort')
    r['ids_deep_review'] = []
    x = consolidate_report(r)
    assert x['status'] == 'limited'
    assert any(i['kind'] == 'invalid_review_shape' for i in x['issues'])


def test_large_inputs_bound_scan_without_losing_original_findings():
    r = fixture('cisco_asa')
    r['findings'] = [{'title': 'x', 'code': 'X', 'line_number': i} for i in range(12000)]
    r['object_resolution']['evidence'] = [{'title': 'x', 'kind': 'X', 'line_number': i} for i in range(10000)]
    before = len(r['findings'])
    x = consolidate_report(r)
    assert x['summary']['advisory_items_examined'] <= MAX_EXAMINED
    assert x['summary']['incomplete'] is True
    assert x['summary']['items_omitted'] > 0
    assert len(r['findings']) == before


def test_api_preserves_all_previous_keys_when_upstream_closes_upload(monkeypatch):
    from starlette.datastructures import UploadFile
    from app.api import consolidation
    previous = fixture('snort')
    async def upstream(*, file, platform):
        await file.close()
        return previous
    monkeypatch.setattr(consolidation, '_previous_analysis', upstream)
    output = asyncio.run(consolidation.analyze_consolidated(
        file=UploadFile(BytesIO(b'snort config'), filename='snort.conf'), platform='snort'))
    for key, value in previous.items():
        assert output[key] is value
    assert output['consolidation_review']['platform_id'] == 'snort'
