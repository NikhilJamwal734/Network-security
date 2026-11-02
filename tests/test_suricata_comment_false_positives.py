"""Regression coverage for Suricata YAML documentation false positives.

These tests contain only the minimum comment strings needed to reproduce the
seven PDF alerts; the user's full configuration is intentionally not bundled.
"""

import pytest

from app.analyzer.suricata import analyze_suricata_configuration
from app.core.adapters.suricata import SuricataAdapter
from app.parsers.ids.suricata import SuricataParser

COMMENTS_FROM_PDF = (
    (191, '# Log the current state of the flow record.'),
    (194, '# Log the metadata field from the rule in a structured'),
    (197, '# Log the raw rule text.'),
    (547, '# Log TCP data after stream normalization'),
    (560, '# Log HTTP body data after normalization, de-chunking and unzipping.'),
    (1049, '# Log the scheme of URLs that are extracted'),
    (1851, '# Log the rules that made it past the prefilter stage, per packet'),
)

RULE = 'alert tcp any any -> $HOME_NET 80 (msg:"test"; sid:23001; rev:1;)'


@pytest.mark.parametrize('line_number,comment', COMMENTS_FROM_PDF, ids=[
    'pdf-line-191', 'pdf-line-194', 'pdf-line-197', 'pdf-line-547',
    'pdf-line-560', 'pdf-line-1049', 'pdf-line-1851',
])
def test_pdf_yaml_comments_are_not_malformed_rules(line_number, comment):
    parsed = SuricataParser().parse([' ' * (line_number % 7) + comment])
    assert not parsed.malformed_rule_lines
    assert not parsed.rules
    assert 'SURICATA-008' not in {
        finding['code'] for finding in analyze_suricata_configuration(parsed)
    }


def test_all_seven_findings_eliminated_at_original_line_numbers():
    lines = [''] * 1851
    for line_number, comment in COMMENTS_FROM_PDF:
        lines[line_number - 1] = '    ' + comment
    parsed = SuricataParser().parse(lines)
    assert parsed.malformed_rule_lines == ()
    assert parsed.rules == ()
    assert not any('rule-like lines could not be parsed' in msg for msg in parsed.warnings)
    assert not any(f['code'] == 'SURICATA-008' for f in analyze_suricata_configuration(parsed))


def test_valid_commented_rule_still_recognized_as_disabled():
    parsed = SuricataParser().parse(['   # ' + RULE])
    assert len(parsed.rules) == 1
    assert parsed.rules[0].enabled is False
    assert parsed.rules[0].sid == 23001
    assert 'SURICATA-004' in {
        f['code'] for f in analyze_suricata_configuration(parsed)
    }


def test_commented_malformed_rule_is_not_active_security_finding():
    parsed = SuricataParser().parse(['# alert tcp broken header (sid:1;)'])
    assert not parsed.rules
    assert parsed.malformed_rule_lines == ()
    assert 'SURICATA-008' not in {
        f['code'] for f in analyze_suricata_configuration(parsed)
    }


def test_active_malformed_rule_is_still_reported():
    parsed = SuricataParser().parse(['alert tcp broken header (sid:1;)'])
    assert parsed.malformed_rule_lines == (1,)
    assert 'SURICATA-008' in {
        f['code'] for f in analyze_suricata_configuration(parsed)
    }


def test_active_rule_validity_unchanged():
    parsed = SuricataParser().parse([RULE])
    assert len(parsed.rules) == 1
    assert parsed.rules[0].enabled is True
    assert parsed.malformed_rule_lines == ()


def test_yaml_comments_do_not_hide_genuine_active_rule_error():
    parsed = SuricataParser().parse([
        '# Log TCP data after stream normalization',
        'alert tcp broken header (sid:1;)',
        '# Log the raw rule text.',
    ])
    assert parsed.malformed_rule_lines == (2,)


def test_regression_preserves_yaml_setting_extraction():
    parsed = SuricataParser().parse([
        '%YAML 1.1', '---', 'vars:', '  address-groups:',
        '    HOME_NET: "[192.168.148.0/24]"',
        'rule-files:', '  - suricata.rules', '  - /etc/suricata/rules/local.rules',
        'outputs:', '  - eve-log:', '      enabled: yes',
        'af-packet:', '  - interface: ens33',
        '      # Log the rules that made it past the prefilter stage, per packet',
    ])
    assert parsed.yaml_recognized
    assert parsed.home_net == '[192.168.148.0/24]'
    assert parsed.rule_file_count == 2
    assert parsed.eve_log_enabled is True
    assert parsed.malformed_rule_lines == ()
    assert any('not opened' in warning for warning in parsed.warnings)


def test_normalized_adapter_does_not_report_false_medium_findings():
    source = ['%YAML 1.1', '---', 'suricata-version: "8.0"', 'rule-files:', '  - local.rules']
    source += [comment for _, comment in COMMENTS_FROM_PDF]
    report = SuricataAdapter().analyze(source)
    assert report['summary']['medium_findings'] == 0
    assert report['summary']['unparsed_rule_lines'] == 0
    assert not any(f['code'] == 'SURICATA-008' for f in report['findings'])
    assert report['summary']['security_score'] is None
