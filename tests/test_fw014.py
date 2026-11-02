from app.analyzer.engine import FirewallAnalyzer
from app.models.firewall import FirewallConfig
from app.models.rule import FirewallRule


def make_rule(
    rule_id,
    action,
    source,
    destination,
    protocol="tcp",
    destination_ports=None,
    name="TEST_ACL",
):
    return FirewallRule(
        id=rule_id,
        line_number=rule_id,
        name=name,
        action=action,
        protocol=protocol,
        source=source,
        destination=destination,
        destination_ports=destination_ports or [],
    )


def analyze_rules(rules):
    firewall = FirewallConfig(
        vendor="test"
    )

    for rule in rules:
        firewall.add_rule(rule)

    analyzer = FirewallAnalyzer(firewall)

    return analyzer.analyze()


def get_fw014(findings):
    return [
        finding
        for finding in findings
        if finding.code == "FW-014"
    ]


# ================================================================
# FW-014: unreachable / redundant rules
# ================================================================


def test_deny_rule_shadowed_by_earlier_deny():
    findings = analyze_rules(
        [
            make_rule(
                rule_id=1,
                action="deny",
                source=["10.10.10.0/24"],
                destination=["10.20.20.0/24"],
            ),
            make_rule(
                rule_id=2,
                action="deny",
                source=["10.10.10.10/32"],
                destination=["10.20.20.20/32"],
            ),
        ]
    )

    fw014 = get_fw014(findings)

    assert len(fw014) == 1
    assert fw014[0].rule_id == 2
    assert fw014[0].related_rule_id == 1


def test_permit_rule_unreachable_after_earlier_deny():
    findings = analyze_rules(
        [
            make_rule(
                rule_id=1,
                action="deny",
                source=["10.10.10.0/24"],
                destination=["10.20.20.0/24"],
            ),
            make_rule(
                rule_id=2,
                action="permit",
                source=["10.10.10.10/32"],
                destination=["10.20.20.20/32"],
            ),
        ]
    )

    fw014 = get_fw014(findings)

    assert len(fw014) == 1
    assert fw014[0].rule_id == 2
    assert fw014[0].related_rule_id == 1


def test_earlier_permit_later_permit_uses_fw004_not_fw014():
    findings = analyze_rules(
        [
            make_rule(
                rule_id=1,
                action="permit",
                source=["10.10.10.0/24"],
                destination=["10.20.20.0/24"],
            ),
            make_rule(
                rule_id=2,
                action="permit",
                source=["10.10.10.10/32"],
                destination=["10.20.20.20/32"],
            ),
        ]
    )

    fw014 = get_fw014(findings)

    assert fw014 == []


def test_earlier_permit_later_deny_uses_fw007_not_fw014():
    findings = analyze_rules(
        [
            make_rule(
                rule_id=1,
                action="permit",
                source=["10.10.10.0/24"],
                destination=["10.20.20.0/24"],
            ),
            make_rule(
                rule_id=2,
                action="deny",
                source=["10.10.10.10/32"],
                destination=["10.20.20.20/32"],
            ),
        ]
    )

    fw014 = get_fw014(findings)

    assert fw014 == []


def test_exact_duplicate_is_not_fw014():
    findings = analyze_rules(
        [
            make_rule(
                rule_id=1,
                action="deny",
                source=["10.10.10.0/24"],
                destination=["10.20.20.0/24"],
            ),
            make_rule(
                rule_id=2,
                action="deny",
                source=["10.10.10.0/24"],
                destination=["10.20.20.0/24"],
            ),
        ]
    )

    fw014 = get_fw014(findings)

    assert fw014 == []


def test_different_source_is_not_redundant():
    findings = analyze_rules(
        [
            make_rule(
                rule_id=1,
                action="deny",
                source=["10.10.10.0/24"],
                destination=["10.20.20.0/24"],
            ),
            make_rule(
                rule_id=2,
                action="deny",
                source=["10.30.30.0/24"],
                destination=["10.20.20.0/24"],
            ),
        ]
    )

    fw014 = get_fw014(findings)

    assert fw014 == []


def test_different_destination_is_not_redundant():
    findings = analyze_rules(
        [
            make_rule(
                rule_id=1,
                action="deny",
                source=["10.10.10.0/24"],
                destination=["10.20.20.0/24"],
            ),
            make_rule(
                rule_id=2,
                action="deny",
                source=["10.10.10.0/24"],
                destination=["10.30.30.0/24"],
            ),
        ]
    )

    fw014 = get_fw014(findings)

    assert fw014 == []


def test_different_protocol_is_not_redundant():
    findings = analyze_rules(
        [
            make_rule(
                rule_id=1,
                action="deny",
                source=["10.10.10.0/24"],
                destination=["10.20.20.0/24"],
                protocol="tcp",
            ),
            make_rule(
                rule_id=2,
                action="deny",
                source=["10.10.10.0/24"],
                destination=["10.20.20.0/24"],
                protocol="udp",
            ),
        ]
    )

    fw014 = get_fw014(findings)

    assert fw014 == []


def test_different_destination_port_is_not_redundant():
    findings = analyze_rules(
        [
            make_rule(
                rule_id=1,
                action="deny",
                source=["10.10.10.0/24"],
                destination=["10.20.20.0/24"],
                destination_ports=[443],
            ),
            make_rule(
                rule_id=2,
                action="deny",
                source=["10.10.10.0/24"],
                destination=["10.20.20.0/24"],
                destination_ports=[22],
            ),
        ]
    )

    fw014 = get_fw014(findings)

    assert fw014 == []


def test_disabled_earlier_rule_does_not_shadow_later_rule():
    findings = analyze_rules(
        [
            FirewallRule(
                id=1,
                line_number=1,
                name="TEST_ACL",
                action="deny",
                protocol="tcp",
                source=["10.10.10.0/24"],
                destination=["10.20.20.0/24"],
                disabled=True,
            ),
            make_rule(
                rule_id=2,
                action="deny",
                source=["10.10.10.10/32"],
                destination=["10.20.20.20/32"],
            ),
        ]
    )

    fw014 = get_fw014(findings)

    assert fw014 == []


def test_disabled_later_rule_does_not_generate_fw014():
    findings = analyze_rules(
        [
            make_rule(
                rule_id=1,
                action="deny",
                source=["10.10.10.0/24"],
                destination=["10.20.20.0/24"],
            ),
            FirewallRule(
                id=2,
                line_number=2,
                name="TEST_ACL",
                action="deny",
                protocol="tcp",
                source=["10.10.10.10/32"],
                destination=["10.20.20.20/32"],
                disabled=True,
            ),
        ]
    )

    fw014 = get_fw014(findings)

    assert fw014 == []


def test_same_acl_is_required():
    findings = analyze_rules(
        [
            make_rule(
                rule_id=1,
                action="deny",
                source=["10.10.10.0/24"],
                destination=["10.20.20.0/24"],
                name="ACL_ONE",
            ),
            make_rule(
                rule_id=2,
                action="deny",
                source=["10.10.10.10/32"],
                destination=["10.20.20.20/32"],
                name="ACL_TWO",
            ),
        ]
    )

    fw014 = get_fw014(findings)

    assert fw014 == []


def test_multiple_redundant_rules_are_detected():
    findings = analyze_rules(
        [
            make_rule(
                rule_id=1,
                action="deny",
                source=["10.10.10.0/24"],
                destination=["10.20.20.0/24"],
            ),
            make_rule(
                rule_id=2,
                action="deny",
                source=["10.10.10.10/32"],
                destination=["10.20.20.20/32"],
            ),
            make_rule(
                rule_id=3,
                action="deny",
                source=["10.10.10.11/32"],
                destination=["10.20.20.21/32"],
            ),
        ]
    )

    fw014 = get_fw014(findings)

    assert len(fw014) == 2
    assert {finding.rule_id for finding in fw014} == {
        2,
        3,
    }


def test_fw014_has_low_severity():
    findings = analyze_rules(
        [
            make_rule(
                rule_id=1,
                action="deny",
                source=["10.10.10.0/24"],
                destination=["10.20.20.0/24"],
            ),
            make_rule(
                rule_id=2,
                action="deny",
                source=["10.10.10.10/32"],
                destination=["10.20.20.20/32"],
            ),
        ]
    )

    fw014 = get_fw014(findings)

    assert len(fw014) == 1
    assert fw014[0].severity == "LOW"


def test_fw014_contains_recommendation():
    findings = analyze_rules(
        [
            make_rule(
                rule_id=1,
                action="deny",
                source=["10.10.10.0/24"],
                destination=["10.20.20.0/24"],
            ),
            make_rule(
                rule_id=2,
                action="deny",
                source=["10.10.10.10/32"],
                destination=["10.20.20.20/32"],
            ),
        ]
    )

    fw014 = get_fw014(findings)

    assert len(fw014) == 1

    assert fw014[0].recommendation
    assert (
        "redundant"
        in fw014[0].recommendation.lower()
        or "remove"
        in fw014[0].recommendation.lower()
    )