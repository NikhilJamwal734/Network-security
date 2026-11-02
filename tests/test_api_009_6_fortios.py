"""API-009.6 focused FortiOS parser, checks, safe routing and normalized API."""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.api.main import app
from app.analyzer.fortios import analyze_fortios_configuration
from app.core.adapters.fortios import FortiOSAdapter
from app.core.catalog import create_default_registry
from app.core.detection import (
    DetectionStatus, PlatformDetectionError, detect_platform, select_platform,
)
from app.core.fortios_normalization import normalize_fortios_report
from app.parsers.firewalls.fortios import FortiOSParser

REGISTRY = create_default_registry()
POLICY = '''config firewall policy
    edit 100
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set service "ALL"
        set logtraffic disable
    next
end'''
ASA = 'hostname ASA\nobject network APP\n host 192.0.2.10\n'
SNORT = 'preprocessor stream5_global: track_tcp yes\n'
SURICATA = 'rule-files:\n  - local.rules\n'
RULE = 'alert tcp any any -> any 443 (msg:"x"; sid:1234;)'


def parsed(text=POLICY):
    return FortiOSParser().parse(text.splitlines())


def codes(text=POLICY):
    return {x['code'] for x in analyze_fortios_configuration(parsed(text))}


def upload(content=POLICY, *, platform=None, name='device.conf', endpoint='/api/v1/analyze/universal'):
    body = content.encode('utf-8') if isinstance(content, str) else content
    params = {'platform': platform} if platform is not None else None
    with TestClient(app) as client:
        return client.post(endpoint, params=params, files={
            'file': (name, body, 'application/octet-stream')
        })


def test_registry_has_four_platforms():
    assert [x.platform_id for x in REGISTRY.list_platforms()] == [
        'cisco_asa', 'fortios', 'snort', 'suricata'
    ]


def test_fortios_metadata():
    info = REGISTRY.get('fortios').descriptor
    assert info.family.value == 'firewall'
    assert info.extensions == ('.conf', '.cfg', '.txt')


def test_parser_policy_fields_and_id():
    policy = parsed().policies[0]
    assert (policy.identifier, policy.line_number) == ('100', 2)
    assert policy.get('service') == ('ALL',)


def test_parser_case_insensitive_commands():
    c = parsed('CONFIG firewall policy\n EDIT 42\n SET action accept\n NEXT\n END')
    assert c.policies[0].get('action') == ('accept',)


def test_parser_multiple_policies():
    c = parsed(POLICY.replace('    next\nend', '    next\n    edit 101\n     set action deny\n    next\nend'))
    assert [p.identifier for p in c.policies] == ['100', '101']


def test_parser_quoted_policy_name():
    c = parsed('config firewall policy\n edit 2\n set name "Office policy"\n next\nend')
    assert c.policies[0].get('name') == ('Office policy',)


def test_parser_multiple_quoted_values():
    c = parsed('config firewall policy\n edit 2\n set srcaddr "LAN-1" "LAN 2"\n next\nend')
    assert c.policies[0].get('srcaddr') == ('LAN-1', 'LAN 2')


def test_parser_set_then_unset():
    c = parsed('config firewall policy\n edit 2\n set service ALL\n unset service\n next\nend')
    assert not c.policies[0].is_set('service')


def test_parser_repeated_set_uses_last_visible_value():
    c = parsed('config firewall policy\n edit 2\n set action deny\n set action accept\n next\nend')
    assert c.policies[0].get('action') == ('accept',)


def test_parser_addresses():
    c = parsed('config firewall address\n edit "LAN"\n set subnet 192.0.2.0 255.255.255.0\n next\nend')
    assert len(c.addresses) == 1 and c.addresses[0].get('subnet') == ('192.0.2.0', '255.255.255.0')


def test_parser_custom_services():
    c = parsed('config firewall service custom\n edit "APP"\n set tcp-portrange 8080\n next\nend')
    assert c.services[0].get('tcp-portrange') == ('8080',)


def test_parser_interfaces():
    c = parsed('config system interface\n edit "port2"\n set allowaccess ping https ssh\n next\nend')
    assert c.interfaces[0].get('allowaccess') == ('ping', 'https', 'ssh')


def test_parser_ignores_comments():
    c = parsed('# config firewall policy\n! comment\n// comment\n' + POLICY)
    assert len(c.policies) == 1


def test_parser_ignores_unknown_top_level_commands():
    c = parsed('execute reboot\n get system status\n' + POLICY)
    assert len(c.policies) == 1


def test_parser_does_not_capture_secrets_or_unknown_keys():
    c = parsed('config system interface\n edit "port1"\n set password "SECRET"\n set allowaccess ssh\n next\nend')
    assert 'SECRET' not in str(c)
    assert not c.interfaces[0].is_set('password')


def test_parser_rejects_unterminated_edit_identifier():
    c = parsed('config firewall policy\n edit "broken\nend')
    assert not c.policies and c.malformed_lines


def test_parser_skips_unterminated_set_value():
    c = parsed('config firewall policy\n edit 2\n set service "broken\n next\nend')
    assert c.policies[0].get('service') == ()
    assert c.malformed_lines


def test_parser_recovers_from_missing_next():
    c = parsed('config firewall policy\n edit 2\n set action deny\n end')
    assert len(c.policies) == 1 and c.malformed_lines


def test_parser_detects_unclosed_end():
    c = parsed('config firewall policy\n edit 2\n set action accept')
    assert len(c.policies) == 1 and c.malformed_lines


def test_parser_warns_extra_end():
    c = parsed('end\n' + POLICY)
    assert 1 in c.malformed_lines


def test_parser_nested_section_not_mistaken_for_top_level():
    c = parsed('config vdom\n edit "root"\n config firewall policy\n edit 1\n set action accept\n next\n end\n next\nend')
    assert not c.policies


def test_parser_depth_bounded():
    c = parsed(('config dummy\n' * 40) + ('end\n' * 40))
    assert c.malformed_lines


def test_parser_does_not_open_path_references(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError('Never open referenced paths')
    monkeypatch.setattr(Path, 'open', forbidden)
    c = parsed('config firewall address\n edit "/etc/shadow"\n set fqdn "example.test"\n next\nend')
    assert c.addresses[0].identifier == '/etc/shadow'


def test_broad_accept_policy_high():
    assert 'FORTIOS-001' in codes()


def test_broad_service_only_medium():
    text = POLICY.replace('set dstaddr "all"', 'set dstaddr "SERVER"')
    assert 'FORTIOS-002' in codes(text) and 'FORTIOS-001' not in codes(text)


def test_explicit_logtraffic_disable_medium():
    assert 'FORTIOS-003' in codes()


def test_missing_logtraffic_not_assumed_disabled():
    assert 'FORTIOS-003' not in codes(POLICY.replace('set logtraffic disable', ''))


def test_disabled_policy_info_and_not_broad_high():
    text = POLICY.replace('set action accept', 'set status disable\n        set action accept')
    assert 'FORTIOS-004' in codes(text) and 'FORTIOS-001' not in codes(text)


def test_any_to_any_interface_medium():
    text = POLICY.replace('"port1"', '"any"').replace('"port2"', '"any"')
    assert 'FORTIOS-005' in codes(text)


def test_utms_disabled_is_informational():
    assert 'FORTIOS-006' in codes(POLICY.replace('set logtraffic disable', 'set utm-status disable'))


@pytest.mark.parametrize('protocol', ['http', 'telnet', 'http telnet'], ids=['http', 'telnet', 'both'])
def test_insecure_interface_management(protocol):
    text = f'config system interface\n edit "wan1"\n set allowaccess ping {protocol}\n next\nend'
    assert 'FORTIOS-007' in codes(text)


def test_secure_interface_management_not_flagged():
    text = 'config system interface\n edit "wan1"\n set allowaccess ping https ssh\n next\nend'
    assert 'FORTIOS-007' not in codes(text)


def test_broad_address_object_low():
    text = 'config firewall address\n edit ALLNET\n set subnet 0.0.0.0 0.0.0.0\n next\nend'
    assert 'FORTIOS-008' in codes(text)


def test_address_object_specific_not_flagged():
    text = 'config firewall address\n edit LAN\n set subnet 192.0.2.0 255.255.255.0\n next\nend'
    assert 'FORTIOS-008' not in codes(text)


def test_no_visible_firewall_policies_only_info():
    finding = next(f for f in analyze_fortios_configuration(parsed('config system interface\nend')) if f['code'] == 'FORTIOS-009')
    assert finding['severity'] == 'INFO'


def test_malformed_lines_are_signaled_without_flooding():
    text = ('end\n' * 30) + POLICY
    assert sum(f['code'] == 'FORTIOS-010' for f in analyze_fortios_configuration(parsed(text))) == 1


def test_adapter_summary_matches_findings():
    report = FortiOSAdapter().analyze(POLICY.splitlines())
    assert report['summary']['total_findings'] == len(report['findings'])
    assert report['summary']['firewall_policies'] == 1


def test_adapter_does_not_invent_a_score():
    report = FortiOSAdapter().analyze(POLICY.splitlines())
    assert report['summary']['security_score'] is None
    assert report['summary']['risk_level'] is None


def test_adapter_only_serializes_safe_fields():
    src = 'config system interface\n edit port1\n set password MySecretPassword\n next\nend'
    report = FortiOSAdapter().analyze(src.splitlines())
    assert 'MySecretPassword' not in str(report)


def test_adapter_malformed_count():
    report = FortiOSAdapter().analyze('end\n'.splitlines())
    assert report['summary']['malformed_lines'] == 1


def test_detection_auto_fortios():
    result = detect_platform(POLICY.splitlines(), REGISTRY)
    assert (result.status, result.platform_id) == (DetectionStatus.SUPPORTED, 'fortios')


def test_explicit_fortios_selection():
    choice = select_platform(POLICY.splitlines(), REGISTRY, 'fortios')
    assert (choice.platform_id, choice.method) == ('fortios', 'explicit')


@pytest.mark.parametrize('text,expected', [
    (ASA, 'cisco_asa'), (SNORT, 'snort'), (SURICATA, 'suricata'),
], ids=['asa', 'snort', 'suricata'])
def test_existing_detection_stable(text, expected):
    assert detect_platform(text.splitlines(), REGISTRY).platform_id == expected


@pytest.mark.parametrize('other', [ASA, SNORT, SURICATA], ids=['asa', 'snort', 'suricata'])
def test_mixed_config_is_ambiguous(other):
    detected = detect_platform((POLICY + '\n' + other).splitlines(), REGISTRY)
    assert detected.status is DetectionStatus.AMBIGUOUS


@pytest.mark.parametrize('other', [ASA, SNORT, SURICATA], ids=['asa', 'snort', 'suricata'])
def test_wrong_selection_is_rejected(other):
    with pytest.raises(PlatformDetectionError) as e:
        select_platform(other.splitlines(), REGISTRY, 'fortios')
    assert e.value.code == 'platform_mismatch'


def test_explicit_cisco_rejects_fortios():
    with pytest.raises(PlatformDetectionError) as e:
        select_platform(POLICY.splitlines(), REGISTRY, 'cisco_asa')
    assert e.value.code == 'platform_mismatch'


def test_unrecognized_fortios_without_marker_is_unknown():
    result = detect_platform(['edit 1', 'set action accept', 'next'], REGISTRY)
    assert result.status is DetectionStatus.UNKNOWN


def test_api_platforms_lists_four():
    with TestClient(app) as client:
        response = client.get('/api/v1/platforms')
    assert response.status_code == 200
    assert {x['platform_id'] for x in response.json()['platforms']} == {
        'cisco_asa', 'fortios', 'snort', 'suricata'
    }


def test_api_automatic_fortios_upload():
    response = upload()
    assert response.status_code == 200, response.text
    assert response.json()['platform_detection'] == {'platform_id': 'fortios', 'method': 'automatic'}


def test_api_explicit_fortios_upload():
    response = upload(platform='fortios', name='backup.cfg')
    assert response.status_code == 200, response.text
    assert response.json()['summary']['firewall_policies'] == 1


def test_api_normalized_fortios():
    response = upload(endpoint='/api/v1/analyze/normalized')
    assert response.status_code == 200, response.text
    data = response.json()
    assert data['platform']['platform_id'] == 'fortios'
    assert data['platform']['family'] == 'firewall'
    assert data['summary']['security_score'] is None
    assert data['summary']['total_findings'] == len(data['findings'])


def test_api_normalized_coverage_is_honest():
    response = upload(endpoint='/api/v1/analyze/normalized')
    domains = {x['domain']: x['status'] for x in response.json()['coverage']['domains']}
    assert domains['effective_policy_order_and_default_values'] == 'not_assessed'


def test_api_legacy_asa_endpoint_not_repurposed():
    response = upload(endpoint='/api/v1/analyze')
    assert response.status_code == 422


def test_api_fortios_as_snort_fails():
    response = upload(platform='snort')
    assert response.status_code == 422
    assert response.json()['detail']['code'] == 'platform_mismatch'


def test_api_fortios_as_suricata_fails():
    response = upload(platform='suricata')
    assert response.status_code == 422
    assert response.json()['detail']['code'] == 'platform_mismatch'


def test_api_fortios_wrong_extension():
    response = upload(platform='fortios', name='firewall.yaml')
    assert response.status_code == 400


def test_api_oversize_upload_rejected():
    content = b'A' * (2 * 1024 * 1024 + 1)
    response = upload(content=content)
    assert response.status_code == 413


def test_api_unsupported_platform_rejected():
    response = upload(platform='palo_alto')
    assert response.status_code == 400
    assert response.json()['detail']['code'] == 'unsupported_platform'


def test_api_malicious_configuration_text_not_executed(monkeypatch):
    import subprocess
    def forbidden(*args, **kwargs):
        raise AssertionError('Uploaded input must not be executed')
    monkeypatch.setattr(subprocess, 'run', forbidden)
    malicious = POLICY + '\nset name "$(whoami); __import__(os)"\n'
    response = upload(content=malicious)
    assert response.status_code == 200, response.text


def test_normalization_rejects_wrong_vendor():
    report = FortiOSAdapter().analyze(POLICY.splitlines())
    with pytest.raises(ValueError):
        normalize_fortios_report(report, REGISTRY.get('cisco_asa').descriptor)


def test_normalization_rejects_wrong_summary():
    report = FortiOSAdapter().analyze(POLICY.splitlines())
    report['summary']['total_findings'] = 999
    with pytest.raises(ValueError):
        normalize_fortios_report(report, REGISTRY.get('fortios').descriptor)


def test_normalization_rejects_missing_findings():
    report = FortiOSAdapter().analyze(POLICY.splitlines())
    report.pop('findings')
    with pytest.raises(ValueError):
        normalize_fortios_report(report, REGISTRY.get('fortios').descriptor)


def test_normalization_no_secret_exposure():
    report = FortiOSAdapter().analyze(POLICY.splitlines())
    normalized = normalize_fortios_report(report, REGISTRY.get('fortios').descriptor)
    assert all(x['evidence']['rule_id'] == '100' or x['evidence']['rule_id'] is None
               for x in normalized.to_dict()['findings'])


def test_sample_fortios_parses():
    sample = Path(__file__).resolve().parents[1] / 'configs/fortios_sample.conf'
    assert len(FortiOSParser().parse(sample.read_text(encoding='utf-8').splitlines()).policies) == 2
