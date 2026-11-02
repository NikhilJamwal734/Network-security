"""API-010.4: evidence semantics, source boundaries and API preservation."""
import asyncio
from io import BytesIO
from pathlib import Path
import pytest
from fastapi import UploadFile

from app.core.correlation_assurance import verify_correlations
from app.core.rule_correlation import correlate_rules


def check(platform, source, **kw):
    prior = correlate_rules(platform, source)
    return verify_correlations(platform, source, prior, **kw)


def asa_pair(sequence1, sequence2):
    source = (f'access-list WEB line {sequence1} extended deny ip any any\n'
              f'access-list WEB line {sequence2} extended permit tcp any any eq 443\n')
    return check('cisco_asa', source)


def test_asa_reversed_explicit_order_is_not_trusted():
    report = asa_pair(20, 5)
    assert report['summary']['ordering_contradictions'] == 1
    assert report['items'][0]['status'] == 'ordering_contradicted'
    assert report['items'][0]['evidence_present'] is True
    assert 'not justified' in report['items'][0]['explanation']


def test_asa_forward_explicit_order_remains_conditional():
    item, = asa_pair(5, 20)['items']
    assert item['status'] == 'order_supported_candidate'
    assert 'conditional' in item['explanation']


def test_asa_without_explicit_order_abstains():
    source = 'access-list WEB extended deny ip any any\naccess-list WEB extended permit tcp any any eq 443\n'
    assert check('cisco_asa', source)['items'][0]['status'] == 'order_unverified'


def test_asa_mixed_explicit_order_abstains():
    source = 'access-list WEB line 1 extended deny ip any any\naccess-list WEB extended permit tcp any any eq 443\n'
    assert check('cisco_asa', source)['items'][0]['status'] == 'order_unverified'


def _policy(number, action='accept'):
    return (f'edit {number}\nset srcintf "lan"\nset dstintf "wan1"\n'
            f'set srcaddr "all"\nset dstaddr "all"\nset service "HTTP"\n'
            f'set schedule "always"\nset action {action}\nnext\n')


def test_fortios_objects_remain_unresolved():
    source = 'config firewall policy\n' + _policy(1) + _policy(2) + 'end\n'
    item, = check('fortios', source)['items']
    assert item['status'] == 'object_resolution_required'
    assert item['evidence_present']


@pytest.mark.parametrize('platform', ['snort', 'suricata'])
def test_ids_equal_headers_are_not_assumed_equal_rules(platform):
    source = ('alert tcp any any -> any any (sid:1001; content:"alpha";)\n'
              'alert tcp any any -> any any (sid:1002; content:"beta";)\n')
    item, = check(platform, source)['items']
    assert item['status'] == 'ids_options_unverified'
    assert item['evidence_present']


def test_unsupported_platform_rejected():
    with pytest.raises(ValueError):
        verify_correlations('paloalto', '', {'pairs': []})


def test_invalid_line_references_not_treated_as_verified():
    item = {'correlation_id': 'RC-001', 'evidence': {'line_number': 900, 'related_line_number': 1}}
    result = verify_correlations('cisco_asa', 'access-list WEB extended permit ip any any\n', {'pairs': [item]})
    assert result['summary']['evidence_unavailable'] == 1
    assert result['items'][0]['status'] == 'evidence_unavailable'


def test_commented_ids_line_not_valid_evidence():
    item = {'correlation_id': 'RC-001', 'evidence': {'line_number': 2, 'related_line_number': 1}}
    src = '# alert tcp any any -> any any (sid:1;)\nalert tcp any any -> any any (sid:2;)\n'
    result = verify_correlations('snort', src, {'pairs': [item]})
    assert result['summary']['evidence_present'] == 0


def test_boolean_not_accepted_as_line_number():
    item = {'evidence': {'related_line_number': True, 'line_number': 1}}
    result = verify_correlations('cisco_asa', 'access-list A extended deny ip any any\n', {'pairs': [item]})
    assert result['summary']['evidence_unavailable'] == 1


def test_report_preservation():
    src = 'access-list WEB line 2 extended deny ip any any\naccess-list WEB line 4 extended permit ip any any\n'
    prev = correlate_rules('cisco_asa', src)
    before = repr(prev)
    verify_correlations('cisco_asa', src, prev)
    assert repr(prev) == before


def test_no_pairs_all_platforms():
    for platform in ('cisco_asa', 'fortios', 'snort', 'suricata'):
        report = check(platform, '# empty\n')
        assert not report['items']
        assert report['summary']['pairs_reviewed'] == 0


def test_incomplete_sample_status():
    result = check('cisco_asa', 'access-list A extended deny ip any any\n', source_truncated=True)
    assert result['status'] == 'limited'
    assert result['summary']['truncated']


def test_pair_output_cap():
    src = 'access-list A extended permit ip any any\n'
    pair = {'evidence': {'related_line_number': 1, 'line_number': 1}}
    report = verify_correlations('cisco_asa', src, {'pairs': [pair] * 100})
    assert len(report['items']) == 70
    assert report['summary']['truncated']


def test_endpoint_handles_prior_upload_close(monkeypatch):
    from app.api import correlation_assurance as endpoint
    old = {'platform': {'platform_id': 'cisco_asa'}, 'summary': {'total_findings': 0},
           'rule_correlation': correlate_rules('cisco_asa',
               'access-list WEB line 10 extended deny ip any any\n'
               'access-list WEB line 2 extended permit ip any any\n')}
    async def fake_previous(*, file, platform):
        assert platform == 'cisco_asa'
        assert (await file.read()).startswith(b'access-list WEB')
        await file.close()
        return old
    monkeypatch.setattr(endpoint, '_previous_analysis', fake_previous)
    source = UploadFile(file=BytesIO(b'access-list WEB line 10 extended deny ip any any\n'
                                      b'access-list WEB line 2 extended permit ip any any\n'), filename='asa.txt')
    response = asyncio.run(endpoint.analyze_correlation_assurance(file=source, platform='cisco_asa'))
    assert response['rule_correlation'] == old['rule_correlation']
    assert response['summary'] == old['summary']
    assert response['correlation_assurance']['summary']['ordering_contradictions'] == 1


def test_endpoint_sample_capped(monkeypatch):
    from app.api import correlation_assurance as endpoint
    previous = {'platform': {'platform_id': 'snort'}, 'rule_correlation': {'pairs': []}}
    async def fake_previous(*, file, platform):
        await file.close()
        return previous
    monkeypatch.setattr(endpoint, '_previous_analysis', fake_previous)
    monkeypatch.setattr(endpoint, 'MAX_SAMPLE_BYTES', 20)
    source = UploadFile(file=BytesIO(b'alert tcp any any -> any any (sid:1;)\n'), filename='a.rules')
    report = asyncio.run(endpoint.analyze_correlation_assurance(file=source, platform='snort'))
    assert report['correlation_assurance']['status'] == 'limited'


def test_existing_route_not_called_twice(monkeypatch):
    from app.api import correlation_assurance as endpoint
    calls = []
    async def fake_previous(*, file, platform):
        calls.append(platform)
        await file.close()
        return {'platform': {'platform_id': 'fortios'}, 'rule_correlation': {'pairs': []}}
    monkeypatch.setattr(endpoint, '_previous_analysis', fake_previous)
    source = UploadFile(file=BytesIO(b'config firewall policy\nend\n'), filename='f.conf')
    asyncio.run(endpoint.analyze_correlation_assurance(file=source, platform='fortios'))
    assert calls == ['fortios']
