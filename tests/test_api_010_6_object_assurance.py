"""API-010.6 object-reference accuracy tests; no real network/device access."""
from __future__ import annotations
import asyncio
from io import BytesIO
from copy import deepcopy
import pytest
from fastapi import UploadFile
from app.core.object_assurance import review_dependencies


def asa(s, **kw): return review_dependencies('cisco_asa', s, **kw)
def forti(s, **kw): return review_dependencies('fortios', s, **kw)


def test_asa_missing_reference_has_exact_line():
    r = asa('object network GOOD\n host 10.0.0.1\naccess-list A extended permit ip object MISSING any\n')
    assert r['summary']['missing_in_upload'] == 1
    o, = r['observations']
    assert o['object_name'] == 'MISSING' and o['line_number'] == 3
    assert o['kind'] == 'not_defined_in_upload'


def test_asa_defined_object_not_flagged():
    r = asa('object network GOOD\n host 10.0.0.1\naccess-list A extended permit ip object GOOD any\n')
    assert r['summary']['references_checked'] == 1
    assert not r['observations']


def test_asa_acl_service_object_not_mislabeled_network():
    # "object HTTPS" after both addresses is a service selector, not a network address.
    r = asa('access-list ACL extended permit tcp any any object HTTPS\n')
    assert not r['observations']


def test_asa_ports_do_not_mask_dst_object():
    r = asa('access-list A extended permit tcp any eq 8080 object MISS eq 443\n')
    assert r['summary']['missing_in_upload'] == 1


def test_asa_duplicate_object_line_paired():
    r = asa('object network X\n host 10.0.0.1\nobject network X\n host 10.0.0.2\n')
    assert r['summary']['repeated_definitions'] == 1
    o, = r['observations']
    assert o['line_number'] == 3 and o['related_line_numbers'] == [1]


def test_asa_comments_do_not_trigger():
    r = asa('# object network X\n! access-list A extended deny ip object MISS any\n')
    assert not r['observations']


def test_truncated_source_marks_absence_as_incomplete():
    r = asa('access-list A extended deny ip object OTHER any\n', source_truncated=True)
    assert r['summary']['incomplete']
    assert r['observations'][0]['kind'] == 'not_visible_in_excerpt'


def test_fortios_missing_group_member():
    src = 'config firewall addrgrp\nedit G\nset member MISSING\nnext\nend\n'
    r = forti(src)
    assert r['summary']['missing_in_upload'] == 1
    assert r['observations'][0]['line_number'] == 3


def test_fortios_group_cycle_one_observation():
    src = ('config firewall addrgrp\nedit A\nset member B\nnext\n'
           'edit B\nset member A\nnext\nend\n')
    r = forti(src)
    assert r['summary']['cycles'] == 1
    assert len([o for o in r['observations'] if o['kind'] == 'dependency_cycle']) == 1


def test_fortios_finite_group_chain_not_cycle():
    src = ('config firewall address\nedit H\nset subnet 10.0.0.0 255.0.0.0\nnext\nend\n'
           'config firewall addrgrp\nedit A\nset member H\nnext\nend\n')
    assert forti(src)['summary']['cycles'] == 0
    assert forti(src)['summary']['missing_in_upload'] == 0


def test_fortios_repeat_definition_is_advisory():
    src = ('config firewall address\nedit A\nnext\nend\n'
           'config firewall address\nedit A\nnext\nend\n')
    assert forti(src)['summary']['repeated_definitions'] == 1


def test_fortios_builtin_service_not_called_missing():
    src = 'config firewall policy\nedit 1\nset service HTTP\nnext\nend\n'
    obs = forti(src)['observations']
    assert len(obs) == 1
    assert obs[0]['kind'] == 'service_definition_not_visible'
    assert 'may be a FortiOS built-in' in obs[0]['explanation']
    assert forti(src)['summary']['missing_in_upload'] == 0


def test_fortios_quoted_names_with_spaces():
    src = ('config firewall address\nedit "Dept A"\nset subnet 10.1.0.0 255.255.0.0\nnext\nend\n'
           'config firewall policy\nedit 1\nset srcaddr "Dept A"\nnext\nend\n')
    r = forti(src)
    assert r['summary']['missing_in_upload'] == 0
    assert r['summary']['references_checked'] == 1


def test_fortios_vdom_refuses_unsafe_scope():
    src = 'config vdom\nedit root\nconfig firewall policy\nedit 1\nset srcaddr MISS\n'
    r = forti(src)
    assert r['status'] == 'not_assessed' and not r['observations']


@pytest.mark.parametrize('platform', ['snort', 'suricata'])
def test_ids_not_assessed(platform):
    r = review_dependencies(platform, 'var HOME_NET 10.0.0.0/8\n')
    assert r['status'] == 'not_assessed' and not r['observations']


def test_unsupported_platform():
    with pytest.raises(ValueError):
        review_dependencies('juniper', '')


def test_existing_report_remains_unchanged():
    original = {'summary': {'total_findings': 5}, 'object_resolution': {'summary': {'truncated': False}}}
    copy = deepcopy(original)
    _ = asa('object network X\n host 10.1.1.1\n', object_resolution=original['object_resolution'])
    assert original == copy


def test_inherited_truncation_is_respected():
    r = asa('access-list A extended deny ip object NOPE any\n',
            object_resolution={'summary': {'truncated': True}})
    assert r['observations'][0]['kind'] == 'not_visible_in_excerpt'


def test_diagnostic_cap():
    src = ''.join(f'access-list A extended deny ip object M{i} any\n' for i in range(140))
    r = asa(src)
    assert len(r['observations']) == 100
    assert r['summary']['observations_omitted'] == 40


def test_endpoint_reads_before_prior_closes_file(monkeypatch):
    from app.api import object_assurance as endpoint
    sample = b'access-list A extended deny ip object BAD any\n'
    old = {'platform': {'platform_id': 'cisco_asa'}, 'summary': {'total_findings': 2},
           'object_resolution': {'summary': {'truncated': False}}}
    async def prior(*, file, platform):
        assert await file.read() == sample
        await file.close()
        return old
    monkeypatch.setattr(endpoint, '_previous_analysis', prior)
    result = asyncio.run(endpoint.analyze_object_assurance(
        file=UploadFile(file=BytesIO(sample), filename='asa.conf'), platform='cisco_asa'))
    assert result['summary'] == old['summary']
    assert result['object_resolution'] == old['object_resolution']
    assert result['object_assurance']['summary']['missing_in_upload'] == 1


def test_api_does_not_call_prior_twice(monkeypatch):
    from app.api import object_assurance as endpoint
    calls = []
    async def prior(*, file, platform):
        calls.append(True)
        await file.close()
        return {'platform': {'platform_id': 'snort'}, 'object_resolution': {}}
    monkeypatch.setattr(endpoint, '_previous_analysis', prior)
    asyncio.run(endpoint.analyze_object_assurance(file=UploadFile(file=BytesIO(b'alert tcp any any -> any any (sid:1;)')),
                                                platform='snort'))
    assert len(calls) == 1
