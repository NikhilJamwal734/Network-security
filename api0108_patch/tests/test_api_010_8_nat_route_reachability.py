"""API-010.8 regression tests: bounded/no-claim NAT/route analysis."""
from __future__ import annotations
from copy import deepcopy
from io import BytesIO
import asyncio
import pytest
from fastapi import UploadFile
from app.core.nat_route_reachability import review_nat_route_reachability

ASA = '''object network WEB
 host 10.0.0.10
 nat (inside,outside) static 203.0.113.10
route outside 0.0.0.0 0.0.0.0 203.0.113.1 1
access-group WAN_ACL in interface outside
access-list WAN_ACL extended permit tcp any host 203.0.113.10 eq 443
'''
FORTI = '''config router static
 edit 1
  set dst 10.0.0.0 255.255.255.0
  set gateway 10.0.0.1
  set device "port2"
 next
end
config firewall vip
 edit "HTTPS-VIP"
  set extip 203.0.113.10
  set mappedip 10.0.0.10
  set extintf "port1"
 next
end
config firewall policy
 edit 7
  set srcintf "port1"
  set dstintf "port2"
  set dstaddr "HTTPS-VIP"
  set action accept
  set nat enable
  set service "HTTPS"
 next
end
'''


def test_asa_static_nat_route_match_candidate_only():
    r = review_nat_route_reachability('cisco_asa', ASA)
    s = r['summary']
    assert (s['routes_resolved'], s['nat_resolved'], s['policies_eligible']) == (1, 1, 1)
    assert r['status'] == 'reviewed_subset'
    assert r['evidence'][0]['kind'] == 'configured_static_nat_candidate'
    matched = [e for e in r['evidence'] if e['kind'] == 'route_policy_candidate']
    assert len(matched) == 1 and matched[0]['ingress_interface'] == 'outside'
    assert matched[0]['route_line_number'] == 4
    assert all(e['confidence'] == 'configured_candidate_only' for e in r['evidence'])


def test_asa_without_access_group_binding_does_not_claim_active_policy():
    r = review_nat_route_reachability('cisco_asa', ASA.replace('access-group WAN_ACL in interface outside\n', ''))
    assert not any(e['kind'] == 'route_policy_candidate' for e in r['evidence'])
    assert r['summary']['incomplete']


def test_asa_unsupported_port_nats_never_assumed():
    text = ASA.replace('static 203.0.113.10', 'static 203.0.113.10 service tcp 443 443')
    r = review_nat_route_reachability('cisco_asa', text)
    assert r['summary']['nat_resolved'] == 0
    assert not any(e['kind'] == 'configured_static_nat_candidate' for e in r['evidence'])


def test_asa_duplicate_objects_are_not_resolved():
    duplicate = 'object network WEB\n host 10.0.0.11\n' + ASA
    r = review_nat_route_reachability('cisco_asa', duplicate)
    assert r['summary']['policies_eligible'] == 1  # rule references literal host
    assert r['summary']['nat_seen'] == 1
    assert r['summary']['nat_resolved'] == 0
    assert not any(e['kind'] == 'configured_static_nat_candidate' for e in r['evidence'])


def test_forti_vip_dnat_and_egress_conditional():
    r = review_nat_route_reachability('fortios', FORTI)
    assert r['summary']['nat_resolved'] == 1
    assert r['summary']['routes_resolved'] == 1
    assert any(e['kind'] == 'policy_snat_indicator' for e in r['evidence'])
    candidates = [e for e in r['evidence'] if e['kind'] == 'route_policy_candidate']
    assert len(candidates) == 1
    assert candidates[0]['mapped_destination'] == '10.0.0.10/32'
    assert 'SNAT is configured' in candidates[0]['explanation']


def test_forti_egress_difference_is_hypothesis_not_confirmed_issue():
    r = review_nat_route_reachability('fortios', FORTI.replace('set dstintf "port2"', 'set dstintf "port3"'))
    mismatches = [e for e in r['evidence'] if e['kind'] == 'potential_egress_discrepancy']
    assert len(mismatches) == 1
    assert 'dynamic/PBR routing may explain' in mismatches[0]['explanation']


def test_no_route_does_not_claim_unreachable():
    r = review_nat_route_reachability('fortios', FORTI.replace('config router static', 'config router policy'))
    assert not any(e['kind'] in ('route_policy_candidate', 'potential_egress_discrepancy') for e in r['evidence'])
    assert any('NOT proof' in line for line in r['limitations'])


def test_split_route_abstains_from_single_egress_claim():
    text = '''config router static
edit 1
set dst 0.0.0.0 0.0.0.0
set device wan
set gateway 192.0.2.1
next
edit 2
set dst 10.0.1.0 255.255.255.0
set device internal
set gateway 192.0.2.2
next
end
config firewall address
edit LAN
set subnet 10.0.0.0 255.255.0.0
next
end
config firewall policy
edit 3
set srcintf lan
set dstintf wan
set dstaddr LAN
next
end
'''
    r = review_nat_route_reachability('fortios', text)
    assert not any('route' in e['kind'] for e in r['evidence'])


def test_forti_duplicate_vip_unresolved():
    double = FORTI.replace('next\nend\nconfig firewall policy', 'next\nedit "HTTPS-VIP"\nset extip 203.0.113.11\nset mappedip 10.0.0.11\nset extintf port1\nnext\nend\nconfig firewall policy')
    r = review_nat_route_reachability('fortios', double)
    assert r['summary']['nat_resolved'] == 0
    assert r['summary']['policies_eligible'] == 0


def test_forti_vdom_abstains():
    r = review_nat_route_reachability('fortios', 'config vdom\nedit root\nend\n' + FORTI)
    assert r['status'] == 'limited' and not r['evidence']
    assert any('VDOM' in x for x in r['limitations'])


def test_unsupported_forti_vip_port_forwarding_abstains():
    src = FORTI.replace('set extip 203.0.113.10', 'set portforward enable\n  set extip 203.0.113.10')
    r = review_nat_route_reachability('fortios', src)
    assert r['summary']['nat_resolved'] == 0



def test_forti_negated_destination_abstains():
    r = review_nat_route_reachability('fortios', FORTI.replace('set dstaddr "HTTPS-VIP"',
                                                                 'set dstaddr "HTTPS-VIP"\n  set dstaddr-negate enable'))
    assert r['summary']['policies_eligible'] == 0
    assert not any(e['kind'].startswith('route_policy') for e in r['evidence'])


def test_forti_vip_wrong_ingress_abstains():
    r = review_nat_route_reachability('fortios', FORTI.replace('set srcintf "port1"', 'set srcintf "port9"'))
    assert not any(e['kind'] in ('route_policy_candidate', 'potential_egress_discrepancy') for e in r['evidence'])


def test_different_route_family_not_joined():
    r = review_nat_route_reachability('cisco_asa', 'ipv6 route outside 2001:db8::/32 2001:db8::1\naccess-group A in interface outside\naccess-list A extended permit ip any host 198.51.100.1\n')
    assert r['summary']['routes_resolved'] == 1
    assert not r['evidence']


def test_strict_limits_suppress_hypotheses():
    r = review_nat_route_reachability('fortios', FORTI, source_truncated=True)
    assert r['status'] == 'limited' and not r['evidence']
    r = review_nat_route_reachability('fortios', FORTI + '\n' * 40_001)
    assert r['status'] == 'limited' and not r['evidence']


@pytest.mark.parametrize('platform', ['snort', 'suricata'])
def test_ids_previous_engine_untouched(platform):
    r = review_nat_route_reachability(platform, 'alert tcp any any -> any any (sid:1;)')
    assert r['status'] == 'not_assessed' and not r['evidence']


def test_scores_and_normalized_report_not_affected():
    report = {'summary': {'security_score': 18, 'critical_findings': 3}}
    old = deepcopy(report)
    review_nat_route_reachability('cisco_asa', ASA)
    assert report == old


def test_bad_platform_rejected():
    with pytest.raises(ValueError):
        review_nat_route_reachability('unknown', '')


def test_endpoint_snapshots_before_upstream_closes(monkeypatch):
    from app.api import nat_route_reachability
    payload = ASA.encode()
    previous = {'platform': {'platform_id': 'cisco_asa'}, 'service_ipv6': {'status': 'reviewed_subset'}, 'summary': {'security_score': 12}}

    async def fake_previous(*, file, platform):
        assert await file.read() == payload
        await file.close()
        return previous

    monkeypatch.setattr(nat_route_reachability, '_previous_analysis', fake_previous)
    out = asyncio.run(nat_route_reachability.analyze_nat_route_reachability(
        file=UploadFile(filename='asa.cfg', file=BytesIO(payload)), platform='cisco_asa'))
    assert out['summary'] == previous['summary']
    assert out['service_ipv6'] == previous['service_ipv6']
    assert out['nat_route_reachability']['summary']['routes_resolved'] == 1
    assert 'nat_route_reachability' not in previous
