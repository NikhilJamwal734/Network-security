from app.analyzer.engine import FirewallAnalyzer
from app.models.firewall import FirewallConfig
from app.models.rule import FirewallRule


def make_rule(
    rule_id,
    destination_ports,
    source="10.10.10.0/24",
    destination="10.20.20.0/24",
    protocol="tcp",
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
        destination_ports=destination_ports,
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


def get_fw018_findings(rules):
    analyzer = make_analyzer(rules)

    findings = analyzer._check_broad_service_scope()

    return [
        finding
        for finding in findings
        if finding.code == "FW-018"
    ]


def test_any_port_is_broader_than_specific_port():
    rules = [
        make_rule(
            1,
            destination_ports=[443],
        ),
        make_rule(
            2,
            destination_ports=[],
        ),
    ]

    # An empty destination-port list represents an unrestricted
    # port scope for this test.
    findings = get_fw018_findings(rules)

    assert len(findings) == 1
    assert findings[0].rule_id == 2
    assert findings[0].related_rule_id == 1


def test_multiple_ports_are_broader_when_they_contain_earlier_port():
    rules = [
        make_rule(
            1,
            destination_ports=[443],
        ),
        make_rule(
            2,
            destination_ports=[80, 443, 8080],
        ),
    ]

    findings = get_fw018_findings(rules)

    assert len(findings) == 1
    assert findings[0].rule_id == 2
    assert findings[0].related_rule_id == 1


def test_same_port_is_not_broader():
    rules = [
        make_rule(
            1,
            destination_ports=[443],
        ),
        make_rule(
            2,
            destination_ports=[443],
        ),
    ]

    findings = get_fw018_findings(rules)

    assert findings == []


def test_narrower_port_scope_is_not_flagged():
    rules = [
        make_rule(
            1,
            destination_ports=[80, 443],
        ),
        make_rule(
            2,
            destination_ports=[443],
        ),
    ]

    findings = get_fw018_findings(rules)

    assert findings == []


def test_unrelated_ports_are_not_flagged():
    rules = [
        make_rule(
            1,
            destination_ports=[443],
        ),
        make_rule(
            2,
            destination_ports=[80],
        ),
    ]

    findings = get_fw018_findings(rules)

    assert findings == []


def test_different_source_does_not_trigger():
    rules = [
        make_rule(
            1,
            destination_ports=[443],
            source="10.10.10.0/24",
        ),
        make_rule(
            2,
            destination_ports=[80, 443],
            source="10.30.30.0/24",
        ),
    ]

    findings = get_fw018_findings(rules)

    assert findings == []


def test_different_destination_does_not_trigger():
    rules = [
        make_rule(
            1,
            destination_ports=[443],
            destination="10.20.20.0/24",
        ),
        make_rule(
            2,
            destination_ports=[80, 443],
            destination="10.40.40.0/24",
        ),
    ]

    findings = get_fw018_findings(rules)

    assert findings == []


def test_different_protocol_does_not_trigger():
    rules = [
        make_rule(
            1,
            destination_ports=[443],
            protocol="tcp",
        ),
        make_rule(
            2,
            destination_ports=[80, 443],
            protocol="udp",
        ),
    ]

    findings = get_fw018_findings(rules)

    assert findings == []


def test_deny_rules_do_not_trigger():
    rules = [
        make_rule(
            1,
            destination_ports=[443],
            action="deny",
        ),
        make_rule(
            2,
            destination_ports=[80, 443],
            action="permit",
        ),
    ]

    findings = get_fw018_findings(rules)

    assert findings == []


def test_current_rule_must_be_later_rule():
    rules = [
        make_rule(
            1,
            destination_ports=[80, 443],
        ),
        make_rule(
            2,
            destination_ports=[443],
        ),
    ]

    findings = get_fw018_findings(rules)

    assert findings == []


def test_disabled_rules_are_ignored():
    rules = [
        make_rule(
            1,
            destination_ports=[443],
        ),
        make_rule(
            2,
            destination_ports=[80, 443],
        ),
    ]

    rules[0].disabled = True

    findings = get_fw018_findings(rules)

    assert findings == []


def test_finding_has_low_severity():
    rules = [
        make_rule(
            1,
            destination_ports=[443],
        ),
        make_rule(
            2,
            destination_ports=[80, 443],
        ),
    ]

    findings = get_fw018_findings(rules)

    assert len(findings) == 1
    assert findings[0].severity == "LOW"


def test_finding_contains_recommendation():
    rules = [
        make_rule(
            1,
            destination_ports=[443],
        ),
        make_rule(
            2,
            destination_ports=[80, 443],
        ),
    ]

    findings = get_fw018_findings(rules)

    assert len(findings) == 1
    assert "port" in findings[0].recommendation.lower()


def test_first_rule_is_not_flagged():
    rules = [
        make_rule(
            1,
            destination_ports=[443],
        ),
    ]

    findings = get_fw018_findings(rules)

    assert findings == []