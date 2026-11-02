"""API-010.7 bounded vendor-specific evidence regression suite."""
import asyncio
from copy import deepcopy
from io import BytesIO
from fastapi import UploadFile
import pytest
from app.core.service_ipv6 import review_service_ipv6

ASA = ('object network V6HOST\n host 2001:db8::42\n'
       'access-list WAN line 10 extended permit tcp any6 any6 eq 443\n'
       'access-list WAN line 20 extended deny tcp object V6HOST any6 eq 443\n')
FORTI = '''config firewall address6
 edit "dept v6"
 set ip6 2001:db8:1::/64
 next
end
config firewall service custom
 edit TCP443
 set tcp-portrange 443
 next
end
config firewall service group
 edit OUTBOUND
 set member TCP443
 next
end
config firewall policy6
 edit 10
 set action accept
 set srcintf lan
 set dstintf wan
 set schedule always
 set srcaddr6 "dept v6"
 set dstaddr6 all6
 set service OUTBOUND
 next
 edit 20
 set action deny
 set srcintf lan
 set dstintf wan
 set schedule always
 set srcaddr6 "dept v6"
 set dstaddr6 all6
 set service OUTBOUND
 next
end
'''


def test_asa_named_ipv6_and_line_evidence():
    r = review_service_ipv6('cisco_asa', ASA)
    assert r['summary']['correlation_candidates'] == 1
    p, = r['pairs']
    assert p['ip_version'] == 6
    assert p['related_line_number'] == 3 and p['line_number'] == 4
    assert p['kind'] == 'opposite_action_containment'
    assert 'V6HOST' in p['resolved_objects']


def test_asa_unsupported_ipv4_does_not_fake_ipv6():
    src = ('object network X\n host 10.0.0.4\n'
           'access-list OUT extended permit tcp object X any6 eq 443\n')
    r = review_service_ipv6('cisco_asa', src)
    assert r['summary']['definitions_unresolved'] == 1
    assert not r['pairs']


def test_asa_unrecognized_options_are_excluded():
    src = ('access-list A extended permit tcp any6 any6 eq 443 log\n'
           'access-list A extended deny tcp any6 any6 eq 443\n')
    assert review_service_ipv6('cisco_asa', src)['summary']['rules_eligible'] == 1


def test_asa_diff_acl_cannot_correlate():
    src = ('access-list A extended permit tcp any6 any6 eq 443\n'
           'access-list B extended deny tcp any6 any6 eq 443\n')
    assert review_service_ipv6('cisco_asa', src)['pairs'] == []


def test_forti_service_group_and_ipv6_compare():
    r = review_service_ipv6('fortios', FORTI)
    assert r['summary']['definitions_resolved'] == 3
    assert r['summary']['correlation_candidates'] == 1
    assert r['pairs'][0]['related_rule_id'] == '10'
    assert r['pairs'][0]['rule_id'] == '20'
    assert 'OUTBOUND' in r['pairs'][0]['resolved_objects']


def test_forti_nested_services():
    src = '''config firewall service custom
edit SSL
set tcp-portrange 443
next
end
config firewall service group
edit G1
set member SSL
next
edit G2
set member G1
next
end
'''
    r = review_service_ipv6('fortios', src)
    assert r['summary']['definitions_resolved'] == 3


def test_forti_service_cycle_abstains():
    src = '''config firewall service group
edit A
set member B
next
edit B
set member A
next
end
'''
    r = review_service_ipv6('fortios', src)
    assert r['summary']['definitions_unresolved'] == 2


def test_forti_missing_builtin_does_not_guess():
    src = '''config firewall service group
edit G
set member HTTP
next
end
'''
    r = review_service_ipv6('fortios', src)
    assert r['summary']['definitions_unresolved'] == 1
    assert not r['pairs']


def test_forti_separate_interface_avoids_false_candidate():
    s = FORTI.replace('edit 20\n set action deny\n set srcintf lan', 'edit 20\n set action deny\n set srcintf dmz')
    r = review_service_ipv6('fortios', s)
    assert r['summary']['rules_eligible'] == 2 and not r['pairs']


def test_forti_different_family_avoids_mixed_compare():
    src = FORTI + '''config firewall address
edit V4
set subnet 10.0.0.0 255.0.0.0
next
end
'''
    assert review_service_ipv6('fortios', src)['summary']['correlation_candidates'] == 1


def test_forti_duplicate_definition_is_unresolved():
    src = '''config firewall service custom
edit DUP
set tcp-portrange 443
next
edit DUP
set tcp-portrange 8443
next
end
'''
    r = review_service_ipv6('fortios', src)
    assert r['summary']['definitions_unresolved'] == 1


def test_forti_comment_rule_ignored():
    src = '# config firewall service group\n# edit G\n# set member M\n'
    assert review_service_ipv6('fortios', src)['summary']['definitions_seen'] == 0


def test_forti_vdom_not_assessed():
    r = review_service_ipv6('fortios', 'config vdom\nedit root\nend\n')
    assert r['summary']['incomplete'] and not r['pairs']


def test_truncated_report_does_not_claim_full_coverage():
    r = review_service_ipv6('fortios', FORTI, source_truncated=True)
    assert r['summary']['incomplete'] and r['status'] == 'limited'

@pytest.mark.parametrize('platform', ['snort', 'suricata'])
def test_ids_explicitly_not_assessed(platform):
    r = review_service_ipv6(platform, 'var HOME_NET any\n')
    assert r['status'] == 'not_assessed' and not r['pairs']


def test_does_not_modify_supplied_analysis_dict():
    r = {'platform': {'platform_id': 'fortios'}, 'summary': {'security_score': 87}}
    old = deepcopy(r)
    review_service_ipv6('fortios', FORTI)
    assert r == old


def test_bad_platform():
    with pytest.raises(ValueError):
        review_service_ipv6('other', '')


def test_endpoint_reads_before_prior_closes_file(monkeypatch):
    from app.api import service_ipv6
    payload = ASA.encode()
    old = {'platform': {'platform_id': 'cisco_asa'}, 'summary': {'total_findings': 7}}
    async def prior(*, file, platform):
        assert await file.read() == payload
        await file.close()
        return old
    monkeypatch.setattr(service_ipv6, '_previous_analysis', prior)
    result = asyncio.run(service_ipv6.analyze_service_ipv6(
        file=UploadFile(filename='a.txt', file=BytesIO(payload)), platform='cisco_asa'))
    assert result['summary'] == old['summary']
    assert result['service_ipv6']['summary']['correlation_candidates'] == 1
    assert 'service_ipv6' not in old


def test_partial_utf8_binary_is_never_interpreted_as_full(monkeypatch):
    from app.api import service_ipv6
    async def prior(*, file, platform):
        await file.close()
        return {'platform': {'platform_id': 'fortios'}, 'findings': []}
    monkeypatch.setattr(service_ipv6, '_previous_analysis', prior)
    result = asyncio.run(service_ipv6.analyze_service_ipv6(
        file=UploadFile(filename='binary.conf', file=BytesIO(b'\xff\xfe')), platform='fortios'))
    assert result['service_ipv6']['summary']['incomplete']


def test_forti_ipv4_policy_can_use_custom_service_group():
    src = '''config firewall address
edit S
set subnet 10.0.0.0 255.0.0.0
next
edit D
set subnet 192.0.2.0 255.255.255.0
next
end
config firewall service custom
edit SSL
set tcp-portrange 443
next
end
config firewall service group
edit G
set member SSL
next
end
config firewall policy
edit 1
set action accept
set srcintf lan
set dstintf wan
set schedule always
set srcaddr S
set dstaddr D
set service G
next
edit 2
set action deny
set srcintf lan
set dstintf wan
set schedule always
set srcaddr S
set dstaddr D
set service G
next
end
'''
    r = review_service_ipv6('fortios', src)
    assert r['summary']['rules_eligible'] == 2
    assert r['pairs'][0]['ip_version'] == 4
    assert 'G' in r['pairs'][0]['resolved_objects']


def test_forti_ipv6_address_negation_excluded():
    src = FORTI.replace('set srcaddr6 "dept v6"\n set dstaddr6 all6\n set service OUTBOUND',
                        'set srcaddr6 "dept v6"\n set srcaddr6-negate enable\n set dstaddr6 all6\n set service OUTBOUND', 1)
    r = review_service_ipv6('fortios', src)
    assert r['summary']['rules_eligible'] == 1
    assert r['pairs'] == []


def test_forti_multi_service_members_respect_udp_tcp_protocol():
    src = '''config firewall service custom
edit TCP
set tcp-portrange 443
next
edit UDP
set udp-portrange 53
next
end
config firewall service group
edit G
set member TCP UDP
next
end
'''
    r = review_service_ipv6('fortios', src)
    assert r['summary']['definitions_resolved'] == 3


def test_same_action_selector_overlap_is_not_called_a_verified_conflict():
    src = ('access-list A extended permit tcp any6 any6 eq 443\n'
           'access-list A extended permit tcp host 2001:db8::5 any6 eq 443\n')
    r = review_service_ipv6('cisco_asa', src)
    assert r['pairs'][0]['kind'] == 'same_action_containment'
    assert r['pairs'][0]['confidence'] == 'resolved_selectors_conditional'
