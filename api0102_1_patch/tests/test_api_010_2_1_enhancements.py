"""API-010.2.1: context-sensitive accuracy, legacy contract preservation."""
import pytest

from app.core.precision_enhancements import augment_precision_review
from app.core.precision_review import refine_vendor_review
from app.core.vendor_review import review_cisco_asa, review_fortios, review_snort, review_suricata
from app.parsers.firewalls.fortios import FortiOSParser
from app.parsers.ids.snort import SnortParser
from app.parsers.ids.suricata import SuricataParser


def analyze(platform, *lines):
    lines = list(lines)
    if platform == 'cisco_asa':
        original = review_cisco_asa(lines)
    elif platform == 'fortios':
        original = review_fortios(FortiOSParser().parse(lines))
    elif platform == 'snort':
        original = review_snort(SnortParser().parse(lines))
    else:
        original = review_suricata(SuricataParser().parse(lines))
    return refine_vendor_review(platform, lines, original)


def findings(result, code):
    return [c for c in result['checks'] if c['code'] == code]


@pytest.mark.parametrize('platform', ['cisco_asa', 'fortios', 'snort', 'suricata'])
def test_empty_config_no_new_findings(platform):
    report = analyze(platform, '# comment')
    assert report['checks'] == []
    assert report['precision']['enhanced_version'] == '1.1'


def test_asa_sshv1_last_effective_selection():
    finding = findings(analyze('cisco_asa', 'ssh version 1'), 'ASA-PREC2-001')
    assert len(finding) == 1 and finding[0]['line_number'] == 1
    assert not findings(analyze('cisco_asa', 'ssh version 1', 'ssh version 2'), 'ASA-PREC2-001')
    assert not findings(analyze('cisco_asa', '# ssh version 1'), 'ASA-PREC2-001')
    assert not findings(analyze('cisco_asa', 'ssh version 1', 'no ssh version 1'), 'ASA-PREC2-001')


def test_asa_http_selector_needs_explicit_server_enablement():
    broad = 'http 0.0.0.0 0.0.0.0 outside'
    assert not findings(analyze('cisco_asa', broad), 'ASA-PREC2-002')
    item = findings(analyze('cisco_asa', broad, 'http server enable'), 'ASA-PREC2-002')
    assert len(item) == 1 and item[0]['line_number'] == 1
    assert 'not evidence of cleartext' in item[0]['detail']
    assert not findings(analyze('cisco_asa', broad, 'http server enable', 'no http server enable'), 'ASA-PREC2-002')
    assert not findings(analyze('cisco_asa', broad, 'no http 0.0.0.0 0.0.0.0 outside', 'http server enable'), 'ASA-PREC2-002')


def test_asa_selectors_are_interface_specific():
    report = analyze('cisco_asa', 'http 0.0.0.0 0.0.0.0 outside',
                     'no http 0.0.0.0 0.0.0.0 inside', 'http server enable')
    assert len(findings(report, 'ASA-PREC2-002')) == 1


def test_fortios_explicit_utm_disabled_on_accept_policy():
    report = analyze('fortios', 'config firewall policy', 'edit 10', 'set action accept',
                     'set utm-status disable', 'next', 'end')
    item = findings(report, 'FORTIOS-PREC2-001')
    assert len(item) == 1 and item[0]['rule_id'] == '10'
    assert item[0]['severity'] == 'LOW'


@pytest.mark.parametrize('extras', [
    ('set status disable',), ('set action deny',), ('set utm-status enable',),
])
def test_fortios_utm_no_overclaim(extras):
    report = analyze('fortios', 'config firewall policy', 'edit 10', 'set action accept',
                     'set utm-status disable', *extras, 'next', 'end')
    assert findings(report, 'FORTIOS-PREC2-001') == []


def test_fortios_duplicate_edits_do_not_claim_effective_utm():
    report = analyze('fortios', 'config firewall policy', 'edit 10', 'set action accept',
                     'set utm-status disable', 'next', 'edit 10', 'set utm-status enable',
                     'next', 'end')
    assert not findings(report, 'FORTIOS-PREC2-001')


def test_snort_gid_sid_pair_distinguishes_generators():
    report = analyze('snort',
        'alert tcp any any -> any any (gid:1; sid:101;)',
        'alert tcp any any -> any any (gid:2; sid:101;)')
    assert not findings(report, 'SNORT-PREC-001')
    assert report['precision']['suppressed_preliminary_checks'] >= 1


def test_snort_duplicate_gid_sid_cites_both_lines():
    report = analyze('snort',
        'alert tcp any any -> any any (gid:2; sid:101;)',
        'alert udp any any -> any any (gid:2; sid:101;)')
    entry = findings(report, 'SNORT-PREC-001')
    assert len(entry) == 1
    assert entry[0]['rule_id'] == '2:101'
    assert entry[0]['line_number'] == 2
    assert 'source lines: 1, 2' in entry[0]['detail']


def test_snort_default_generator_matches_explicit_one():
    report = analyze('snort',
        'alert tcp any any -> any any (sid:101;)',
        'alert udp any any -> any any (gid:1; sid:101;)')
    assert len(findings(report, 'SNORT-PREC-001')) == 1


def test_snort_quoted_gid_message_does_not_change_generator():
    report = analyze('snort',
        'alert tcp any any -> any any (msg:"quoted; gid:2; example"; sid:101;)',
        'alert udp any any -> any any (gid:2; sid:101;)')
    assert not findings(report, 'SNORT-PREC-001')


def test_snort_malformed_gid_is_not_guessed():
    report = analyze('snort',
        'alert tcp any any -> any any (gid:invalid; sid:101;)',
        'alert udp any any -> any any (sid:101;)')
    assert findings(report, 'SNORT-PREC-001') == []


def test_suricata_duplicate_evidence_and_other_gid():
    report = analyze('suricata',
        'alert tcp any any -> any any (gid:1; sid:202; rev:1;)',
        'alert udp any any -> any any (gid:1; sid:202; rev:2;)',
        'alert tcp any any -> any any (gid:2; sid:202; rev:1;)')
    item = findings(report, 'SURICATA-PREC-001')
    assert len(item) == 1 and item[0]['rule_id'] == '1:202'
    assert 'source lines: 1, 2' in item[0]['detail']


def test_zero_score_impact_and_nonmutation():
    original = dict(checks=[{'code': 'test', 'line_number': 1, 'rule_id': None}],
                    precision=dict(status='context_refined', suppressed_preliminary_checks=0,
                                   additional_evidence_checks=0), limitations=[],
                    suppressed_checks=0, interpretation='No score changes')
    refined = augment_precision_review('cisco_asa', ['ssh version 1'], original)
    assert len(original['checks']) == 1
    assert 'enhanced_version' not in original['precision']
    assert len(refined['checks']) == 2
    assert 'score' in refined['interpretation']


@pytest.mark.parametrize('platform,filename,payload', [
    ('cisco_asa', 'asa.txt', b'ssh version 1\n'),
    ('fortios', 'f.conf', b'config firewall policy\nedit 1\nset action accept\nset utm-status disable\nnext\nend\n'),
    ('snort', 's.rules', b'alert tcp any any -> any any (gid:2; sid:1;)\nalert tcp any any -> any any (gid:2; sid:1;)\n'),
    ('suricata', 'u.rules', b'alert tcp any any -> any any (sid:1;)\nalert tcp any any -> any any (sid:1;)\n'),
])
def test_endpoint_preserves_old_report_fields(platform, filename, payload):
    from fastapi.testclient import TestClient
    from app.api.main import app
    paths = {route.path for route in app.routes}
    if '/api/v1/analyze/deep-review' not in paths or '/api/v1/analyze/precision-review' not in paths:
        pytest.skip('Compatibility-only parser workspace lacks the complete FastAPI routers')
    with TestClient(app) as client:
        old = client.post(f'/api/v1/analyze/deep-review?platform={platform}',
                          files={'file': (filename, payload, 'text/plain')})
        new = client.post(f'/api/v1/analyze/precision-review?platform={platform}',
                          files={'file': (filename, payload, 'text/plain')})
    assert old.status_code == new.status_code == 200, (old.text, new.text)
    previous, enhanced = old.json(), new.json()
    for field in ('summary', 'findings', 'assessment', 'quality', 'coverage'):
        assert previous[field] == enhanced[field]
    assert 'precision' not in previous['vendor_review']
    assert enhanced['vendor_review']['precision']['enhanced_version'] == '1.1'
