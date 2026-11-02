"""Static regression tests for advisory link accuracy without re-scoring findings."""
from __future__ import annotations
import asyncio
from copy import deepcopy
from io import BytesIO
import pytest
from app.core.correlation_accuracy import review_correlation_accuracy, MAX_FINDINGS, MAX_LINKS


def base(platform='cisco_asa'):
    evidence_section = 'ids_deep_review' if platform in ('snort', 'suricata') else 'object_resolution'
    report = {
        'platform': {'platform_id': platform}, 'score': 73,
        'findings': [{'line_number': 7, 'code': 'FW-100', 'title': 'Broad rule', 'severity': 'HIGH', 'rule_id': 4}],
        evidence_section: {'status': 'reviewed_subset', 'platform_id': platform, 'summary': {'incomplete': False},
                           'evidence': [{'line_number': 7, 'kind': 'FW-100', 'title': 'Broad rule', 'reference': 'E-1'}]},
        'consolidation_review': {'status': 'reviewed_subset', 'platform_id': platform, 'summary': {'incomplete': False},
            'links': [{'reference': 'LINK-001', 'source_line': 7, 'signal': 'fw-100', 'title': 'broad rule',
                       'related': [
                           {'section': 'normalized_findings', 'locator': '0', 'source_line': 7},
                           {'section': evidence_section, 'locator': 'evidence[0]', 'source_line': 7},
                       ]}]},
    }
    return report


@pytest.mark.parametrize('platform', ['cisco_asa', 'fortios', 'snort', 'suricata'])
def test_supported_platforms_and_read_only(platform):
    r = base(platform)
    original = deepcopy(r)
    x = review_correlation_accuracy(r)
    assert r == original
    assert x['summary']['links_checked'] == 1
    assert x['summary']['plausible_links'] == 1
    assert x['summary']['unsupported_links'] == 0
    assert x['decisions'][0]['confidence'] == 'static_report_metadata_only'
    assert x['scope'] == 'single_upload_advisory_link_validation'


def test_same_line_but_different_kind_or_title_is_rejected():
    r = base()
    r['object_resolution']['evidence'][0]['title'] = 'Different rule'
    x = review_correlation_accuracy(r)
    assert x['summary']['unsupported_links'] == 1
    assert x['summary']['plausible_links'] == 0


def test_different_source_line_and_tampered_link_are_rejected():
    r = base()
    r['object_resolution']['evidence'][0]['line_number'] = 8
    assert review_correlation_accuracy(r)['summary']['unsupported_links'] == 1
    r = base()
    r['consolidation_review']['links'][0]['title'] = 'made up'
    assert review_correlation_accuracy(r)['summary']['unsupported_links'] == 1


def test_unknown_source_or_cross_platform_section_rejected():
    r = base()
    r['consolidation_review']['links'][0]['related'][1]['section'] = 'ids_deep_review'
    assert review_correlation_accuracy(r)['summary']['unsupported_links'] == 1
    r['consolidation_review']['links'][0]['related'][1]['section'] = '../../something'
    assert review_correlation_accuracy(r)['summary']['unsupported_links'] == 1


def test_same_section_does_not_establish_cross_review_link():
    r = base()
    r['consolidation_review']['links'][0]['related'][1]['section'] = 'normalized_findings'
    r['consolidation_review']['links'][0]['related'][1]['locator'] = '0'
    assert review_correlation_accuracy(r)['summary']['unsupported_links'] == 1


def test_incomplete_source_or_section_is_uncertain_not_clean():
    r = base()
    r['consolidation_review']['status'] = 'limited'
    assert review_correlation_accuracy(r)['summary']['uncertain_links'] == 1
    r = base()
    r['object_resolution']['summary']['incomplete'] = True
    assert review_correlation_accuracy(r)['summary']['uncertain_links'] == 1


def test_potential_duplicate_metadata_does_not_remove_findings():
    r = base()
    r['findings'].append(dict(r['findings'][0]))
    x = review_correlation_accuracy(r)
    assert x['summary']['finding_metadata_pairs'] == 1
    assert x['quality_observations'][0]['kind'] == 'possible_repeated_finding_metadata'
    assert len(r['findings']) == 2


def test_conflicting_severities_not_reclassified():
    r = base()
    r['findings'].append({**r['findings'][0], 'severity': 'LOW'})
    x = review_correlation_accuracy(r)
    assert x['summary']['severity_conflicts'] == 1
    assert x['quality_observations'][0]['kind'] == 'severity_disagreement'
    assert r['findings'][0]['severity'] == 'HIGH'
    assert r['findings'][1]['severity'] == 'LOW'


def test_no_line_is_coverage_note_not_false_positive():
    r = base()
    r['findings'].append({'code': 'GENERIC', 'title': 'Global setting'})
    x = review_correlation_accuracy(r)
    assert x['summary']['findings_without_line'] == 1
    assert x['summary']['unsupported_links'] == 0


def test_bad_shape_or_context_fails_without_claims():
    with pytest.raises(ValueError):
        review_correlation_accuracy({'platform': {'platform_id': 'other'}, 'consolidation_review': {}})
    with pytest.raises(ValueError):
        review_correlation_accuracy({'platform': {'platform_id': 'snort'}})
    r = base()
    r['consolidation_review']['platform_id'] = 'suricata'
    with pytest.raises(ValueError):
        review_correlation_accuracy(r)


def test_large_collections_bounded():
    r = base()
    r['findings'] = [r['findings'][0]] * (MAX_FINDINGS + 12)
    r['consolidation_review']['links'] = [r['consolidation_review']['links'][0]] * (MAX_LINKS + 5)
    x = review_correlation_accuracy(r)
    assert x['summary']['links_checked'] == MAX_LINKS
    assert len(x['decisions']) <= 80
    assert len(x['quality_observations']) <= 80
    assert x['summary']['items_omitted'] >= 17
    assert x['status'] == 'limited'


def test_missing_findings_does_not_signal_clean_pass():
    r = base()
    del r['findings']
    x = review_correlation_accuracy(r)
    assert x['summary']['incomplete'] is True
    assert x['summary']['unsupported_links'] == 1


def test_api_does_not_reread_closed_upload(monkeypatch):
    from starlette.datastructures import UploadFile
    from app.api import correlation_accuracy
    r = base('snort')
    async def upstream(*, file, platform):
        await file.close()
        return r
    monkeypatch.setattr(correlation_accuracy, '_previous_analysis', upstream)
    x = asyncio.run(correlation_accuracy.analyze_correlation_accuracy(
        file=UploadFile(BytesIO(b'hello'), filename='snort.conf'), platform='snort'))
    for key, value in r.items():
        assert x[key] is value
    assert x['correlation_accuracy_review']['summary']['links_checked'] == 1
