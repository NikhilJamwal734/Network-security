from app.analyzer.engine import FirewallAnalyzer
from app.models.firewall import FirewallConfig, NATRule


def make_nat(
    nat_id: int,
    source: str = "10.10.10.0/24",
    translated_source: str = "203.0.113.10",
    destination: str = "any",
    translated_destination: str = "any",
    protocol: str = "ip",
    source_port=None,
    destination_port=None,
    line_number: int = 10,
) -> NATRule:
    return NATRule(
        id=nat_id,
        source=source,
        translated_source=translated_source,
        destination=destination,
        translated_destination=translated_destination,
        protocol=protocol,
        source_port=source_port,
        destination_port=destination_port,
        line_number=line_number,
    )


def make_analyzer(
    nat_rules,
) -> FirewallAnalyzer:
    firewall = FirewallConfig(
        vendor="Cisco ASA",
        hostname="TEST-FIREWALL",
        nat_rules=nat_rules,
    )

    return FirewallAnalyzer(
        firewall
    )


def get_fw020_findings(
    analyzer: FirewallAnalyzer,
):
    return [
        finding
        for finding in analyzer.analyze()
        if finding.code == "FW-020"
    ]


def test_fw020_detects_overlapping_sources_with_different_translations():
    analyzer = make_analyzer(
        [
            make_nat(
                nat_id=1,
                source="10.10.10.0/24",
                translated_source="203.0.113.10",
                line_number=10,
            ),
            make_nat(
                nat_id=2,
                source="10.10.10.128/25",
                translated_source="203.0.113.20",
                line_number=20,
            ),
        ]
    )

    findings = get_fw020_findings(
        analyzer
    )

    assert len(findings) == 1
    assert findings[0].code == "FW-020"
    assert findings[0].rule_id == 2
    assert findings[0].related_rule_id == 1
    assert findings[0].severity == "MEDIUM"


def test_fw020_does_not_report_disjoint_sources():
    analyzer = make_analyzer(
        [
            make_nat(
                nat_id=1,
                source="10.10.10.0/24",
                translated_source="203.0.113.10",
            ),
            make_nat(
                nat_id=2,
                source="10.10.20.0/24",
                translated_source="203.0.113.20",
            ),
        ]
    )

    findings = get_fw020_findings(
        analyzer
    )

    assert findings == []


def test_fw020_does_not_report_same_translated_source():
    analyzer = make_analyzer(
        [
            make_nat(
                nat_id=1,
                source="10.10.10.0/24",
                translated_source="203.0.113.10",
            ),
            make_nat(
                nat_id=2,
                source="10.10.10.128/25",
                translated_source="203.0.113.10",
            ),
        ]
    )

    findings = get_fw020_findings(
        analyzer
    )

    assert findings == []


def test_fw020_does_not_report_exact_duplicate_nat_rules():
    analyzer = make_analyzer(
        [
            make_nat(
                nat_id=1,
                source="10.10.10.0/24",
                translated_source="203.0.113.10",
                destination="10.20.20.0/24",
                translated_destination="198.51.100.10",
                protocol="tcp",
                source_port=443,
                destination_port=8443,
            ),
            make_nat(
                nat_id=2,
                source="10.10.10.0/24",
                translated_source="203.0.113.10",
                destination="10.20.20.0/24",
                translated_destination="198.51.100.10",
                protocol="tcp",
                source_port=443,
                destination_port=8443,
            ),
        ]
    )

    findings = get_fw020_findings(
        analyzer
    )

    assert findings == []


def test_fw020_does_not_report_different_protocols():
    analyzer = make_analyzer(
        [
            make_nat(
                nat_id=1,
                source="10.10.10.0/24",
                translated_source="203.0.113.10",
                protocol="tcp",
            ),
            make_nat(
                nat_id=2,
                source="10.10.10.128/25",
                translated_source="203.0.113.20",
                protocol="udp",
            ),
        ]
    )

    findings = get_fw020_findings(
        analyzer
    )

    assert findings == []


def test_fw020_detects_ip_against_specific_protocol():
    analyzer = make_analyzer(
        [
            make_nat(
                nat_id=1,
                source="10.10.10.0/24",
                translated_source="203.0.113.10",
                protocol="ip",
            ),
            make_nat(
                nat_id=2,
                source="10.10.10.128/25",
                translated_source="203.0.113.20",
                protocol="tcp",
            ),
        ]
    )

    findings = get_fw020_findings(
        analyzer
    )

    assert len(findings) == 1
    assert findings[0].rule_id == 2


def test_fw020_does_not_report_different_source_ports():
    analyzer = make_analyzer(
        [
            make_nat(
                nat_id=1,
                source="10.10.10.0/24",
                translated_source="203.0.113.10",
                source_port=443,
            ),
            make_nat(
                nat_id=2,
                source="10.10.10.128/25",
                translated_source="203.0.113.20",
                source_port=80,
            ),
        ]
    )

    findings = get_fw020_findings(
        analyzer
    )

    assert findings == []


def test_fw020_does_not_report_different_destination_ports():
    analyzer = make_analyzer(
        [
            make_nat(
                nat_id=1,
                source="10.10.10.0/24",
                translated_source="203.0.113.10",
                destination_port=443,
            ),
            make_nat(
                nat_id=2,
                source="10.10.10.128/25",
                translated_source="203.0.113.20",
                destination_port=80,
            ),
        ]
    )

    findings = get_fw020_findings(
        analyzer
    )

    assert findings == []


def test_fw020_detects_overlapping_host_inside_network():
    analyzer = make_analyzer(
        [
            make_nat(
                nat_id=1,
                source="10.10.10.0/24",
                translated_source="203.0.113.10",
            ),
            make_nat(
                nat_id=2,
                source="10.10.10.10",
                translated_source="203.0.113.20",
            ),
        ]
    )

    findings = get_fw020_findings(
        analyzer
    )

    assert len(findings) == 1
    assert findings[0].rule_id == 2
    assert findings[0].related_rule_id == 1


def test_fw020_detects_multiple_overlapping_rules():
    analyzer = make_analyzer(
        [
            make_nat(
                nat_id=1,
                source="10.10.10.0/24",
                translated_source="203.0.113.10",
            ),
            make_nat(
                nat_id=2,
                source="10.10.10.0/25",
                translated_source="203.0.113.20",
            ),
            make_nat(
                nat_id=3,
                source="10.10.10.128/25",
                translated_source="203.0.113.30",
            ),
        ]
    )

    findings = get_fw020_findings(
        analyzer
    )

    assert len(findings) == 2

    assert findings[0].rule_id == 2
    assert findings[0].related_rule_id == 1

    assert findings[1].rule_id == 3
    assert findings[1].related_rule_id == 1