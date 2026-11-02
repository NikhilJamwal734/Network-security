"""API-010.3: exact evidence, non-overclaiming, boundedness, API preservation."""
from __future__ import annotations
import asyncio
from io import BytesIO
from pathlib import Path
import sys
import pytest
from fastapi import UploadFile

from app.core.rule_correlation import correlate_rules


def pairs(platform, text):
    return correlate_rules(platform, text)['pairs']


def test_empty_per_platform():
    for platform in ('cisco_asa', 'fortios', 'snort', 'suricata'):
        report = correlate_rules(platform, '# Empty config\n')
        assert not report['pairs']
        assert report['summary']['eligible_rules'] == 0
        assert report['scope'] == 'static_rule_correlation_advisory'


def test_asa_shadowing_evidence_with_host_and_any():
    report = correlate_rules('cisco_asa', '''access-list OUT extended deny tcp any any eq 443
access-list OUT extended permit tcp host 10.0.0.2 any eq 443
''')
    result, = report['pairs']
    assert result['kind'] == 'shadowed_candidate'
    assert result['evidence']['related_line_number'] == 1
    assert result['evidence']['line_number'] == 2
    assert result['scope'] == 'ASA ACL OUT'
    assert result['confidence'] == 'conditional'


def test_asa_redundant_and_same_acl_only():
    content = '''access-list A extended permit ip any any
access-list A extended permit tcp host 192.0.2.1 any eq 443
access-list B extended deny tcp any any eq 443
'''
    items = pairs('cisco_asa', content)
    assert len(items) == 1
    assert items[0]['kind'] == 'redundant_candidate'


def test_asa_action_conflict_with_partial_overlap():
    items = pairs('cisco_asa', '''access-list A extended permit tcp 10.0.0.0 255.255.255.0 any eq 80
access-list A extended deny tcp 10.0.0.128 255.255.255.128 any eq 80
''')
    assert items and items[0]['kind'] == 'shadowed_candidate'
    partial = pairs('cisco_asa', '''access-list A extended permit tcp 10.0.0.0 255.255.255.128 any eq 80
access-list A extended deny tcp 10.0.0.64 255.255.255.192 any eq 80
''')
    assert partial[0]['kind'] == 'shadowed_candidate'
    partial = pairs('cisco_asa', '''access-list A extended permit tcp 10.0.0.0 255.255.255.128 any eq 80
access-list A extended deny tcp 10.0.0.0 255.255.255.0 any eq 80
''')
    assert partial[0]['kind'] == 'action_conflict_candidate'


def test_asa_different_protocol_or_port_or_acl_no_pairs():
    text = '''access-list A extended deny tcp any any eq 80
access-list A extended permit udp any any eq 80
access-list B extended permit tcp any any eq 80
access-list A extended permit tcp any any eq 443
'''
    assert pairs('cisco_asa', text) == []


def test_asa_unknown_object_does_not_correlate():
    config = '''access-list A extended permit tcp object-group ADMIN_NET any eq 443
access-list A extended deny tcp any any eq 443
'''
    assert pairs('cisco_asa', config) == []
    assert correlate_rules('cisco_asa', config)['summary']['rules_not_correlated'] == 1


def test_asa_inactive_time_range_abstains():
    config = '''access-list A extended deny ip any any inactive
access-list A extended permit tcp any any eq 443
'''
    assert pairs('cisco_asa', config) == []


def test_asa_log_suffix_can_be_correlated():
    assert pairs('cisco_asa', '''access-list A extended permit ip any any log
access-list A extended deny tcp any any eq 443
''')


def test_asa_order_explicit_is_conditional():
    result = pairs('cisco_asa', '''access-list A line 10 extended deny ip any any
access-list A line 2 extended permit tcp any any eq 443
''')
    assert result and result[0]['confidence'] == 'conditional'
    assert 'ordering' in result[0]['detail'].lower()


def _policy(number: int, *, action='accept', service='HTTPS', status='enable', src='internal'):
    return f'''edit {number}
set srcintf "{src}"
set dstintf "wan1"
set srcaddr "all"
set dstaddr "all"
set service "{service}"
set schedule "always"
set action {action}
set status {status}
next
'''


def test_fortios_identical_policy_selectors_opposing_actions():
    text = 'config firewall policy\n' + _policy(1) + _policy(2, action='deny') + 'end\n'
    report = correlate_rules('fortios', text)
    found, = report['pairs']
    assert found['kind'] == 'action_conflict_candidate'
    assert (found['evidence']['related_rule_id'], found['evidence']['rule_id']) == ('1', '2')


def test_fortios_redundancy_and_disabled_exclusion():
    text = 'config firewall policy\n' + _policy(1) + _policy(2) + 'end\n'
    assert pairs('fortios', text)[0]['kind'] == 'redundant_candidate'
    text = 'config firewall policy\n' + _policy(1, status='disable') + _policy(2) + 'end\n'
    assert pairs('fortios', text) == []


def test_fortios_reference_selector_mismatch_no_false_positive():
    text = 'config firewall policy\n' + _policy(1) + _policy(2, service='DNS') + 'end\n'
    assert pairs('fortios', text) == []


def test_fortios_repeated_edits_are_not_conflated():
    text = 'config firewall policy\n' + _policy(1) + _policy(1, action='deny') + _policy(2) + 'end\n'
    assert pairs('fortios', text) == []


def test_snort_header_overlap_not_rule_equivalence():
    text = '''alert tcp any any -> any any (msg:"A"; sid:1001; content:"ABC";)
alert tcp any any -> any any (msg:"B"; sid:1002; content:"XYZ";)
'''
    found, = pairs('snort', text)
    assert found['kind'] == 'header_overlap'
    assert found['confidence'] == 'informational'
    assert 'options' in found['detail']


def test_snort_actions_may_interact_not_proven_conflict():
    text = '''pass tcp any any -> any any (sid:1001;)
alert tcp any any -> any any (sid:1002;)
'''
    found, = pairs('snort', text)
    assert found['kind'] == 'action_interaction_candidate'
    assert 'ordering' in found['detail']


def test_snort_different_direction_no_match():
    text = '''alert tcp any any -> any any (sid:1001;)
alert tcp any any <> any any (sid:1002;)
'''
    assert pairs('snort', text) == []


def test_suricata_commented_rules_do_not_correlate():
    text = '''# alert tcp any any -> any any (sid:1000;)
alert tcp any any -> any any (sid:1001;)
'''
    assert pairs('suricata', text) == []


def test_suricata_rule_header_overlap_with_distinct_ids():
    text = '''alert udp any any -> any 53 (sid:1001;)
drop udp any any -> any 53 (sid:1002;)
'''
    found, = pairs('suricata', text)
    assert found['kind'] == 'action_interaction_candidate'
    assert found['evidence']['line_number'] == 2


def test_suricata_yaml_comments_are_not_alerts():
    lines = '# alert tcp any any -> any any (sid:500;)\n# drop udp any any -> any any (sid:501;)\nrule-files:\n - test.rules\n'
    assert pairs('suricata', lines) == []


def test_duplicate_id_is_not_reported_as_extra_header_overlap():
    rules = '''alert tcp any any -> any any (sid:1;)
alert tcp any any -> any any (sid:1;)
'''
    assert pairs('snort', rules) == []
    assert pairs('suricata', rules) == []


def test_limit_results_and_report_truncation():
    lines = '\n'.join(f'alert tcp any any -> any any (sid:{i + 1};)' for i in range(300))
    report = correlate_rules('snort', lines)
    assert report['summary']['eligible_rules'] == 250
    assert len(report['pairs']) <= 70
    assert report['summary']['truncated'] is True


def test_no_mutation_of_source_data():
    text = 'access-list A extended permit ip any any\n' * 2
    report = correlate_rules('cisco_asa', text)
    assert report['summary']['candidate_pairs'] == 1
    assert text.count('access-list') == 2


def test_unknown_platform_is_rejected():
    with pytest.raises(ValueError):
        correlate_rules('juniper', '')


def test_opt_in_route_preserves_prior_response_without_full_app(monkeypatch):
    from app.api import rule_correlation as endpoint
    old = {'platform': {'platform_id': 'cisco_asa'}, 'summary': {'total_findings': 2},
           'findings': [{'finding_id': 'F-1'}], 'assessment': {'review_score': {'value': 80}},
           'quality': {'status': 'limited_coverage'}}
    async def fake_analyze(*, file, platform):
        assert platform == 'cisco_asa'
        return old
    monkeypatch.setattr(endpoint, '_run_precision', fake_analyze)
    source = UploadFile(file=BytesIO(b'access-list OUT extended permit ip any any\n'), filename='a.txt')
    result = asyncio.run(endpoint.analyze_rule_correlation(file=source, platform='cisco_asa'))
    for field in old:
        assert result[field] == old[field]
    assert result['rule_correlation']['platform_id'] == 'cisco_asa'
    assert 'rule_correlation' not in old


def test_bounded_source_read_reports_truncation(monkeypatch):
    from app.api import rule_correlation as endpoint
    old = {'platform': {'platform_id': 'suricata'}}
    async def fake_analyze(*, file, platform):
        return old
    monkeypatch.setattr(endpoint, '_run_precision', fake_analyze)
    monkeypatch.setattr(endpoint, '_MAX_CORRELATION_BYTES', 20)
    data = b'alert tcp any any -> any any (sid:1;)\n' * 3
    source = UploadFile(file=BytesIO(data), filename='a.rules')
    result = asyncio.run(endpoint.analyze_rule_correlation(file=source, platform='suricata'))
    assert result['rule_correlation']['summary']['truncated'] is True


def test_invalid_utf8_rejected_not_lossily_replaced(monkeypatch):
    from app.api import rule_correlation as endpoint
    async def fake_analyze(*, file, platform):
        return {'platform': {'platform_id': 'snort'}}
    monkeypatch.setattr(endpoint, '_run_precision', fake_analyze)
    source = UploadFile(file=BytesIO(b'\xffbad'), filename='bad')
    with pytest.raises(UnicodeDecodeError):
        asyncio.run(endpoint.analyze_rule_correlation(file=source, platform='snort'))


@pytest.mark.parametrize('platform,filename,body', [
    ('cisco_asa', 'acl.txt', b'access-list A extended permit ip any any\naccess-list A extended deny ip any any\n'),
    ('fortios', 'fortigate.conf', b'config firewall policy\nedit 1\nset action accept\nnext\nend\n'),
    ('snort', 'local.rules', b'alert tcp any any -> any any (sid:1001;)\n'),
    ('suricata', 'suricata.rules', b'alert tcp any any -> any any (sid:1001;)\n'),
])
def test_multipart_endpoint_preserves_existing_fields(monkeypatch, platform, filename, body):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from app.api import rule_correlation as endpoint
    previous = {'platform': {'platform_id': platform}, 'summary': {'total_findings': 0},
                'coverage': {'domains': []}, 'findings': [], 'assessment': {'status': 'provisional'}}
    async def fake_prior(*, file, platform):
        return previous
    monkeypatch.setattr(endpoint, '_run_precision', fake_prior)
    app = FastAPI()
    app.include_router(endpoint.router)
    with TestClient(app) as client:
        response = client.post(f'/api/v1/analyze/rule-correlation?platform={platform}',
                               files={'file': (filename, body, 'text/plain')})
    assert response.status_code == 200, response.text
    result = response.json()
    for key, value in previous.items():
        assert result[key] == value
    assert result['rule_correlation']['platform_id'] == platform
    assert 'rule_correlation' not in previous


def test_multibyte_boundary_does_not_generate_500(monkeypatch):
    from app.api import rule_correlation as endpoint
    async def fake_analyze(*, file, platform):
        return {'platform': {'platform_id': 'snort'}}
    monkeypatch.setattr(endpoint, '_run_precision', fake_analyze)
    monkeypatch.setattr(endpoint, '_MAX_CORRELATION_BYTES', 6)
    source = UploadFile(file=BytesIO(b'hello\xc3\xa9 abc'), filename='ok.rules')
    report = asyncio.run(endpoint.analyze_rule_correlation(file=source, platform='snort'))
    assert report['rule_correlation']['summary']['truncated'] is True
