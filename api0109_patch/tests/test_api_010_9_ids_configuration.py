from __future__ import annotations
from io import BytesIO
import pytest
from app.core.ids_configuration import review_ids_configuration, MAX_ITEMS


def test_firewalls_are_not_applicable():
    for platform in ('cisco_asa', 'fortios'):
        result = review_ids_configuration(platform, 'ipvar HOME_NET any')
        assert result['status'] == 'not_applicable'
        assert not result['evidence']
        assert not result['summary']['incomplete']


def test_snort_duplicate_gid_sid_true_positive():
    config = '''# alert tcp any any -> any 80 (sid:17;) 
ipvar HOME_NET any
include $RULE_PATH/local.rules
output alert_fast: stdout
alert tcp any any -> any 80 (msg:"one"; sid:17; rev:1;)
alert udp any any -> any 53 (msg:"two"; gid:1; sid:17; rev:2;)
alert udp any any -> any 53 (msg:"distinct"; gid:2; sid:17; rev:1;)
'''
    r = review_ids_configuration('snort', config)
    assert r['summary']['rules_inspected'] == 3
    assert r['summary']['duplicate_rule_ids'] == 1
    assert r['summary']['external_references'] == 1
    assert r['summary']['outputs_declared'] == 1
    assert r['summary']['outputs_explicitly_enabled'] == 0
    dup = next(x for x in r['evidence'] if x['kind'] == 'duplicate_inline_rule_identifier')
    assert dup['line_number'] == 6
    assert '5 and 6' in dup['observation']
    assert not r['summary']['incomplete']
    assert not any('risk_level' in x for x in r['evidence'])


def test_snort_only_explicit_inline_rules_and_does_not_assume_missing_rules():
    r = review_ids_configuration('snort', '''# include hidden.conf
-- output alert_fast
include $RULE_PATH/local.rules
var EXTERNAL_NET any
alert tcp any any -> any 80 (msg:"no sid"; rev:1;)
''')
    assert r['summary']['rules_inspected'] == 0
    assert r['summary']['external_references'] == 1
    assert r['summary']['outputs_explicitly_enabled'] == 0
    assert r['status'] == 'limited'
    assert not any(x['kind'] == 'no_explicit_rule_file_entries' for x in r['evidence'])


def test_suricata_disabled_output_and_line_evidence():
    config = '''vars:
  address-groups:
    HOME_NET: any
outputs:
  - eve-log:
      enabled: no
  - fast:
      enabled: yes
rule-files:
  - suricata.rules
af-packet:
  - interface: ens33
    copy-mode: ips
'''
    r = review_ids_configuration('suricata', config)
    assert r['summary']['outputs_explicitly_enabled'] == 1
    assert r['summary']['outputs_explicitly_disabled'] == 1
    assert r['summary']['interfaces_declared'] == 1
    assert r['summary']['external_references'] == 1
    assert {x['kind'] for x in r['evidence']} >= {
        'broad_home_net_selector', 'explicit_alert_output_disabled',
        'external_rule_files_unverified', 'inline_pair_dependency',
    }
    eve = next(x for x in r['evidence'] if x['kind'] == 'explicit_alert_output_disabled')
    assert eve['line_number'] == 6
    assert 'other outputs' in eve['implication'].lower()


def test_suricata_explicit_empty_rules_not_claiming_no_rules_loaded():
    r = review_ids_configuration('suricata', 'rule-files: []\noutputs: []\n')
    assert [x['kind'] for x in r['evidence']] == ['no_explicit_rule_file_entries']
    assert 'might still' in r['evidence'][0]['implication'].lower()


@pytest.mark.parametrize('conf', [
    'outputs:\n - eve-log: { enabled: true }\n - eve-log: { enabled: false }\nvars: {a: 1, a: 2}\n',
    'vars: &evil {a: 1}\noutputs: *evil\n',
    '!!python/object/apply:os.system ["false"]\n',
    'bad: [unfinished\n',
])
def test_unsafe_or_ambiguous_yaml_abstains(conf):
    r = review_ids_configuration('suricata', conf)
    assert r['status'] == 'limited'
    assert not r['evidence']
    assert r['summary']['incomplete']


def test_suricata_does_not_infer_disabled_when_enabled_unspecified():
    r = review_ids_configuration('suricata', 'outputs:\n - eve-log:\n     filename: eve.json\n')
    assert r['summary']['outputs_explicitly_enabled'] == 0
    assert r['summary']['outputs_explicitly_disabled'] == 0
    assert not r['evidence']


def test_truncation_and_line_cap_and_output_cap():
    r = review_ids_configuration('snort', '\n'.join('output alert_fast: stdout' for _ in range(90)), source_truncated=True)
    assert r['status'] == 'limited' and r['summary']['incomplete']
    assert r['summary']['outputs_declared'] == 90
    assert r['summary']['evidence_items'] == MAX_ITEMS
    assert r['summary']['items_omitted'] == 10
    r2 = review_ids_configuration('snort', '\n'.join('include file.conf' for _ in range(40001)))
    assert r2['summary']['incomplete']
    assert r2['summary']['items_omitted'] >= 1



def test_lua_multiline_comment_does_not_generate_duplicate_ids():
    config = ('alert tcp any any -> any 80 (sid:42;)\n'
              '--[[\n'
              'alert tcp any any -> any 80 (sid:42;)\n'
              ']]\n'
              'alert tcp any any -> any 80 (sid:43;)\n')
    r = review_ids_configuration('snort', config)
    assert r['summary']['rules_inspected'] == 2
    assert r['summary']['duplicate_rule_ids'] == 0


def test_invalid_platform_rejected():
    with pytest.raises(ValueError):
        review_ids_configuration('random_vendor', 'something')


@pytest.mark.asyncio
async def test_api_snapshots_upload_before_upstream_closes_it(monkeypatch):
    from starlette.datastructures import UploadFile
    from app.api import ids_configuration as mod
    up = UploadFile(BytesIO(b'ipvar HOME_NET any\n'), filename='snort.conf')

    async def previous(*, file, platform):
        await file.close()
        return {'platform': {'platform_id': 'snort'}, 'nat_route_reachability': {'preserved': True},
                'score': 123, 'findings': [{'code': 'existing'}]}

    monkeypatch.setattr(mod, '_previous_analysis', previous)
    ret = await mod.analyze_ids_configuration(file=up, platform='snort')
    assert ret['score'] == 123
    assert ret['findings'] == [{'code': 'existing'}]
    assert ret['nat_route_reachability'] == {'preserved': True}
    assert ret['ids_deep_review']['evidence'][0]['kind'] == 'broad_home_net_selector'


@pytest.mark.asyncio
async def test_api_invalid_encoding_marked_limited(monkeypatch):
    from starlette.datastructures import UploadFile
    from app.api import ids_configuration as mod
    up = UploadFile(BytesIO(b'\xffinvalid'), filename='snort.conf')

    async def previous(*, file, platform):
        return {'platform': {'platform_id': 'snort'}}

    monkeypatch.setattr(mod, '_previous_analysis', previous)
    ret = await mod.analyze_ids_configuration(file=up, platform='snort')
    assert ret['ids_deep_review']['status'] == 'limited'
    assert not ret['ids_deep_review']['evidence']
