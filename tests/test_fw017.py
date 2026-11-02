from app.analyzer.engine import FirewallAnalyzer
from app.models.firewall import FirewallConfig
from app.models.rule import FirewallRule


def make_rule(
    rule_id,
    protocol,
    source="10.10.10.0/24",
    destination="10.20.20.0/24",
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
        source=[source],
        destination=[destination],
        destination_ports=destination_ports or [443],
    )


def make_analyzer(rules):
    firewall = FirewallConfig(
        vendor="Cisco ASA",
        hostname="TEST-FW",
        networks=[],
        services=[],
        rules=rules,
        nat_rules=[],
        routes=[],
    )

    return FirewallAnalyzer(firewall)


def get_fw017_findings(rules):
    analyzer = make_analyzer(rules)
    findings = analyzer._check_broad_protocol_scope()

    return [
        finding
        for finding in findings
        if finding.code == "FW-017"
    ]


def test_any_protocol_is_broader_than_tcp():
    rules = [
        make_rule(
            1,
            protocol="tcp",
        ),
        make_rule(
            2,
            protocol="ip",
        ),
    ]

    findings = get_fw017_findings(rules)

    assert len(findings) == 1
    assert findings[0].rule_id == 2
    assert findings[0].related_rule_id == 1


def test_any_protocol_is_broader_than_udp():
    rules = [
        make_rule(
            1,
            protocol="udp",
        ),
        make_rule(
            2,
            protocol="ip",
        ),
    ]

    findings = get_fw017_findings(rules)

    assert len(findings) == 1
    assert findings[0].rule_id == 2


def test_tcp_is_not_broader_than_any_protocol():
    rules = [
        make_rule(
            1,
            protocol="ip",
        ),
        make_rule(
            2,
            protocol="tcp",
        ),
    ]

    findings = get_fw017_findings(rules)

    assert findings == []


def test_same_protocol_is_not_broader():
    rules = [
        make_rule(
            1,
            protocol="tcp",
        ),
        make_rule(
            2,
            protocol="tcp",
        ),
    ]

    findings = get_fw017_findings(rules)

    assert findings == []


def test_unrelated_protocol_is_not_broader():
    rules = [
        make_rule(
            1,
            protocol="tcp",
        ),
        make_rule(
            2,
            protocol="udp",
        ),
    ]

    findings = get_fw017_findings(rules)

    assert findings == []


def test_different_source_does_not_trigger():
    rules = [
        make_rule(
            1,
            protocol="tcp",
            source="10.10.10.0/24",
        ),
        make_rule(
            2,
            protocol="ip",
            source="10.30.30.0/24",
        ),
    ]

    findings = get_fw017_findings(rules)

    assert findings == []


def test_different_destination_does_not_trigger():
    rules = [
        make_rule(
            1,
            protocol="tcp",
            destination="10.20.20.0/24",
        ),
        make_rule(
            2,
            protocol="ip",
            destination="10.40.40.0/24",
        ),
    ]

    findings = get_fw017_findings(rules)

    assert findings == []


def test_different_destination_ports_do_not_trigger():
    rules = [
        make_rule(
            1,
            protocol="tcp",
            destination_ports=[443],
        ),
        make_rule(
            2,
            protocol="ip",
            destination_ports=[80],
        ),
    ]

    findings = get_fw017_findings(rules)

    assert findings == []


def test_deny_rules_do_not_trigger():
    rules = [
        make_rule(
            1,
            protocol="tcp",
            action="deny",
        ),
        make_rule(
            2,
            protocol="ip",
            action="permit",
        ),
    ]

    findings = get_fw017_findings(rules)

    assert findings == []


def test_current_rule_must_be_later_rule():
    rules = [
        make_rule(
            1,
            protocol="ip",
        ),
        make_rule(
            2,
            protocol="tcp",
        ),
    ]

    findings = get_fw017_findings(rules)

    assert findings == []


def test_disabled_rules_are_ignored():
    rules = [
        make_rule(
            1,
            protocol="tcp",
        ),
        make_rule(
            2,
            protocol="ip",
        ),
    ]

    rules[0].disabled = True

    findings = get_fw017_findings(rules)

    assert findings == []


def test_finding_has_low_severity():
    rules = [
        make_rule(
            1,
            protocol="tcp",
        ),
        make_rule(
            2,
            protocol="ip",
        ),
    ]

    findings = get_fw017_findings(rules)

    assert len(findings) == 1
    assert findings[0].severity == "LOW"


def test_finding_contains_recommendation():
    rules = [
        make_rule(
            1,
            protocol="tcp",
        ),
        make_rule(
            2,
            protocol="ip",
        ),
    ]

    findings = get_fw017_findings(rules)

    assert len(findings) == 1
    assert "protocol" in findings[0].recommendation.lower()


def test_first_rule_is_not_flagged():
    rules = [
        make_rule(
            1,
            protocol="ip",
        ),
    ]

    findings = get_fw017_findings(rules)

    assert findings == []