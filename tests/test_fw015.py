from app.analyzer.engine import FirewallAnalyzer
from app.models.firewall import FirewallConfig
from app.models.rule import FirewallRule


def make_rule(
    rule_id,
    source,
    destination="10.10.10.10/32",
    protocol="tcp",
    destination_ports=None,
    action="permit",
    acl="outside",
):
    return FirewallRule(
        id=rule_id,
        line_number=rule_id,
        name=acl,
        action=action,
        protocol=protocol,
        source=source,
        destination=[destination],
        destination_ports=destination_ports or [443],
    )


def analyze(rules):
    firewall = FirewallConfig(
        vendor="Cisco ASA",
        hostname="TEST",
        rules=rules,
    )

    return FirewallAnalyzer(firewall).analyze()


def fw015(findings):
    return [
        finding
        for finding in findings
        if finding.code == "FW-015"
    ]


def test_fw015_detects_any_source_when_specific_source_exists():
    rules = [
        make_rule(
            1,
            ["10.20.30.0/24"],
        ),
        make_rule(
            2,
            ["any"],
        ),
    ]

    findings = analyze(rules)

    matches = fw015(findings)

    assert len(matches) == 1
    assert matches[0].rule_id == 2
    assert matches[0].related_rule_id == 1


def test_fw015_detects_broader_network_source():
    rules = [
        make_rule(
            1,
            ["10.20.30.0/24"],
        ),
        make_rule(
            2,
            ["10.20.0.0/16"],
        ),
    ]

    findings = analyze(rules)

    matches = fw015(findings)

    assert len(matches) == 1
    assert matches[0].rule_id == 2
    assert matches[0].related_rule_id == 1


def test_fw015_does_not_flag_narrower_source():
    rules = [
        make_rule(
            1,
            ["10.20.0.0/16"],
        ),
        make_rule(
            2,
            ["10.20.30.0/24"],
        ),
    ]

    findings = analyze(rules)

    assert not fw015(findings)


def test_fw015_does_not_flag_unrelated_source():
    rules = [
        make_rule(
            1,
            ["10.20.30.0/24"],
        ),
        make_rule(
            2,
            ["10.40.30.0/24"],
        ),
    ]

    findings = analyze(rules)

    assert not fw015(findings)


def test_fw015_requires_same_destination():
    rules = [
        make_rule(
            1,
            ["10.20.30.0/24"],
            destination="10.10.10.10/32",
        ),
        make_rule(
            2,
            ["any"],
            destination="10.10.20.10/32",
        ),
    ]

    findings = analyze(rules)

    assert not fw015(findings)


def test_fw015_requires_same_protocol():
    rules = [
        make_rule(
            1,
            ["10.20.30.0/24"],
            protocol="tcp",
        ),
        make_rule(
            2,
            ["any"],
            protocol="udp",
        ),
    ]

    findings = analyze(rules)

    assert not fw015(findings)


def test_fw015_requires_same_destination_port():
    rules = [
        make_rule(
            1,
            ["10.20.30.0/24"],
            destination_ports=[443],
        ),
        make_rule(
            2,
            ["any"],
            destination_ports=[8443],
        ),
    ]

    findings = analyze(rules)

    assert not fw015(findings)


def test_fw015_only_checks_permit_rules():
    rules = [
        make_rule(
            1,
            ["10.20.30.0/24"],
            action="permit",
        ),
        make_rule(
            2,
            ["any"],
            action="deny",
        ),
    ]

    findings = analyze(rules)

    assert not fw015(findings)


def test_fw015_does_not_flag_first_rule():
    rules = [
        make_rule(
            1,
            ["any"],
        ),
    ]

    findings = analyze(rules)

    assert not fw015(findings)


def test_fw015_ignores_disabled_rules():
    rules = [
        make_rule(
            1,
            ["10.20.30.0/24"],
        ),
        make_rule(
            2,
            ["any"],
        ),
    ]

    rules[0].disabled = True

    findings = analyze(rules)

    assert not fw015(findings)


def test_fw015_does_not_duplicate_fw001_for_any_to_any():
    rules = [
        FirewallRule(
            id=1,
            line_number=1,
            name="outside",
            action="permit",
            protocol="ip",
            source=["any"],
            destination=["any"],
        )
    ]

    findings = analyze(rules)

    assert not fw015(findings)


def test_fw015_has_low_severity():
    rules = [
        make_rule(
            1,
            ["10.20.30.0/24"],
        ),
        make_rule(
            2,
            ["any"],
        ),
    ]

    findings = analyze(rules)

    matches = fw015(findings)

    assert len(matches) == 1
    assert matches[0].severity == "LOW"


def test_fw015_contains_recommendation():
    rules = [
        make_rule(
            1,
            ["10.20.30.0/24"],
        ),
        make_rule(
            2,
            ["any"],
        ),
    ]

    findings = analyze(rules)

    matches = fw015(findings)

    assert len(matches) == 1
    assert matches[0].recommendation
    assert "source" in matches[0].recommendation.lower()


def test_fw015_does_not_flag_same_source_scope():
    rules = [
        make_rule(
            1,
            ["10.20.30.0/24"],
        ),
        make_rule(
            2,
            ["10.20.30.0/24"],
        ),
    ]

    findings = analyze(rules)

    assert not fw015(findings)