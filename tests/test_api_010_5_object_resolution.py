"""Unit and endpoint tests for bounded API-010.5 resolution."""
import asyncio
from io import BytesIO
from copy import deepcopy
import pytest
from fastapi import UploadFile

from app.core.object_resolution import resolve_and_compare


def asa(text): return resolve_and_compare('cisco_asa', text)
def fortios(text): return resolve_and_compare('fortios', text)


def test_asa_object_and_literal_ace_overlap():
    src = ('object network TRUSTED\n host 10.0.0.5\n'
           'access-list WEB line 2 extended permit tcp any any eq 443\n'
           'access-list WEB line 5 extended deny tcp object TRUSTED any eq 443\n')
    result = asa(src)
    assert result['summary']['definitions_resolved'] == 1
    assert result['summary']['candidate_pairs'] == 1
    item, = result['pairs']
    assert item['kind'] == 'shadowing_candidate'
    assert item['order_status'] == 'explicit_sequence_supports_order'
    assert item['evidence']['related_line_number'] == 3
    assert item['evidence']['line_number'] == 4
    assert item['resolved_object_references'] == ['TRUSTED']


def test_asa_subnet_mask_and_partial_overlap():
    source = ('object network A\n subnet 10.0.0.0 255.255.255.0\n'
              'object network B\n subnet 10.0.0.128 255.255.255.128\n'
              'access-list TEST extended permit ip object A any\n'
              'access-list TEST extended permit ip object B any\n')
    report = asa(source)
    assert report['summary']['definitions_resolved'] == 2
    assert report['pairs'][0]['kind'] == 'redundancy_candidate'
    assert report['pairs'][0]['order_status'] == 'unverified'


def test_asa_duplicate_object_name_abstains():
    src = ('object network X\n host 10.0.0.1\nobject network X\n host 10.0.0.2\n'
           'access-list A extended deny ip object X any\n')
    result = asa(src)
    assert result['summary']['definitions_unresolved'] == 1
    assert result['summary']['rules_with_resolved_selectors'] == 0


@pytest.mark.parametrize('body', [' range 10.0.0.1 10.0.0.5', ' fqdn www.example.com',
                                   ' subnet 10.0.0.0 255.0.255.0', ' host 999.999.999.999'])
def test_asa_unsupported_object_abstains(body):
    report = asa(f'object network X\n{body}\naccess-list A extended deny ip object X any\n')
    assert report['summary']['candidate_pairs'] == 0
    assert report['summary']['rules_not_resolved'] == 1


def test_asa_does_not_compare_different_acl_bindings():
    source = ('object network X\n host 10.0.0.1\n'
              'access-list A extended permit ip any any\n'
              'access-list B extended deny ip object X any\n')
    assert asa(source)['summary']['candidate_pairs'] == 0


def test_asa_inline_modifiers_abstain():
    source = ('object network X\n host 10.0.0.1\n'
              'access-list A extended permit ip any any\n'
              'access-list A extended deny ip object X any inactive\n')
    assert asa(source)['summary']['candidate_pairs'] == 0


FORTI = '''config firewall address
edit "LAN"
set subnet 10.0.0.0 255.255.255.0
next
edit "HOST"
set subnet 10.0.0.5 255.255.255.255
next
end
config firewall addrgrp
edit "LAN_GROUP"
set member "LAN"
next
end
config firewall service custom
edit "TCP443"
set tcp-portrange 443
next
end
config firewall policy
edit 1
set srcintf "port1"
set dstintf "port2"
set srcaddr "LAN_GROUP"
set dstaddr "all"
set service "TCP443"
set schedule "always"
set action accept
next
edit 2
set srcintf "port1"
set dstintf "port2"
set srcaddr "HOST"
set dstaddr "all"
set service "TCP443"
set schedule "always"
set action deny
next
end
'''


def test_fortios_object_group_and_custom_service():
    report = fortios(FORTI)
    assert report['summary']['definitions_resolved'] == 4
    assert report['summary']['rules_with_resolved_selectors'] == 2
    assert report['summary']['candidate_pairs'] == 1
    pair, = report['pairs']
    assert pair['kind'] == 'opposite_action_containment'
    assert pair['order_status'] == 'unverified'
    assert set(pair['resolved_object_references']) == {'LAN_GROUP', 'LAN', 'HOST', 'TCP443'}


def test_fortios_unsupported_builtin_service_abstains():
    source = FORTI.replace('set service "TCP443"', 'set service "HTTP"')
    report = fortios(source)
    assert report['summary']['rules_with_resolved_selectors'] == 0
    assert report['summary']['candidate_pairs'] == 0


def test_fortios_group_cycle_does_not_recurse():
    src = ('config firewall addrgrp\nedit A\nset member B\nnext\n'
           'edit B\nset member A\nnext\nend\n')
    report = fortios(src)
    assert report['summary']['definitions_unresolved'] == 2


def test_fortios_vdom_abstains():
    report = fortios('config vdom\nedit root\n' + FORTI + '\nnext\nend\n')
    assert not report['pairs']
    assert 'VDOM' in report['limitations'][0]
    assert report['status'] == 'not_assessed'


def test_fortios_disabled_policy_abstains():
    src = FORTI.replace('edit 2\n', 'edit 2\nset status disable\n')
    assert fortios(src)['summary']['candidate_pairs'] == 0


def test_fortios_negated_policy_abstains():
    src = FORTI.replace('edit 2\n', 'edit 2\nset srcaddr-negate enable\n')
    assert fortios(src)['summary']['candidate_pairs'] == 0


def test_fortios_interface_scope_abstains():
    src = FORTI.replace('edit 2\nset srcintf "port1"', 'edit 2\nset srcintf "port99"')
    assert fortios(src)['summary']['candidate_pairs'] == 0


def test_fortios_duplicate_object_definition_unresolved():
    extra = 'config firewall address\nedit "LAN"\nset subnet 10.1.0.0 255.255.0.0\nnext\nend\n'
    result = fortios(FORTI + extra)
    assert any(x['name'] == 'LAN' and x['status'] == 'unresolved' for x in result['objects'])
    assert result['summary']['candidate_pairs'] == 0


def test_ids_abstain():
    for platform in ('snort', 'suricata'):
        result = resolve_and_compare(platform, 'var HOME_NET any\nalert tcp any any -> any any (sid:1;)')
        assert result['summary']['candidate_pairs'] == 0
        assert result['scope'] == 'bounded_static_ipv4_object_resolution'
        assert result['limitations'][0].startswith(platform.capitalize())


def test_prior_report_not_mutated():
    before = {'summary': {'total_findings': 9}, 'correlation_assurance': {'items': [1]}}
    snapshot = deepcopy(before)
    _ = asa('')
    assert before == snapshot


def test_abstains_when_truncated():
    report = resolve_and_compare('cisco_asa', 'object network A\n host 10.0.0.1', source_truncated=True)
    assert report['status'] == 'limited'
    assert report['summary']['truncated'] is True


def test_endpoint_capture_before_file_is_closed(monkeypatch):
    from app.api import object_resolution as endpoint
    sample = ('object network X\n host 10.0.0.1\n'
              'access-list A extended permit ip any any\n'
              'access-list A extended deny ip object X any\n').encode()
    original = {'platform': {'platform_id': 'cisco_asa'}, 'summary': {'total_findings': 3},
                'correlation_assurance': {'items': [{'a': 'b'}]}}
    async def prior(*, file, platform):
        assert await file.read() == sample
        await file.close()
        return original
    monkeypatch.setattr(endpoint, '_previous_analysis', prior)
    response = asyncio.run(endpoint.analyze_object_resolution(
        file=UploadFile(file=BytesIO(sample), filename='asa.conf'), platform='cisco_asa'))
    assert response['summary'] == original['summary']
    assert response['correlation_assurance'] == original['correlation_assurance']
    assert response['object_resolution']['summary']['candidate_pairs'] == 1


def test_endpoint_called_once(monkeypatch):
    from app.api import object_resolution as endpoint
    calls = []
    async def prior(*, file, platform):
        calls.append(1)
        await file.close()
        return {'platform': {'platform_id': 'snort'}, 'findings': []}
    monkeypatch.setattr(endpoint, '_previous_analysis', prior)
    asyncio.run(endpoint.analyze_object_resolution(file=UploadFile(file=BytesIO(b'')), platform='snort'))
    assert len(calls) == 1


def test_unsupported_platform():
    with pytest.raises(ValueError):
        resolve_and_compare('routeros', '')
