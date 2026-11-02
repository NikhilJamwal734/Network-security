from ipaddress import ip_network
from app.analyzer.engine import analyze_firewall
from app.models.firewall import FirewallConfig, NATRule
from app.models.rule import FirewallRule
from app.models.service import Service
from app.models.network import NetworkObject
from app.models.firewall import Route


def make_rule(
    rule_id,
    action="permit",
    protocol="ip",
    source=None,
    destination=None,
    source_ports=None,
    destination_ports=None,
    source_services=None,
    destination_services=None,
    name=None,
    logging=False,
    disabled=False,
    line_number=None,
):
    return FirewallRule(
        id=rule_id,
        line_number=line_number or rule_id + 1,
        name=name,
        action=action,
        protocol=protocol,
        source=source or ["any"],
        destination=destination or ["any"],
        source_ports=source_ports or [],
        destination_ports=destination_ports or [],
        source_services=source_services or [],
        destination_services=destination_services or [],
        logging=logging,
        disabled=disabled,
    )


def make_firewall():
    return FirewallConfig(
        vendor="Cisco ASA",
        hostname="TEST-FIREWALL",
    )


def finding_codes(findings):
    return [finding.code for finding in findings]


def findings_for_code(findings, code):
    return [
        finding
        for finding in findings
        if finding.code == code
    ]


# ============================================================================
# FW-001 — Unrestricted permit rule
# ============================================================================

def test_fw001_detects_unrestricted_permit():
    firewall = make_firewall()

    firewall.add_rule(
        make_rule(
            0,
            action="permit",
            protocol="ip",
            source=["any"],
            destination=["any"],
        )
    )

    findings = analyze_firewall(firewall)
    fw001 = findings_for_code(findings, "FW-001")

    assert len(fw001) == 1
    assert fw001[0].severity.lower() == "critical"


def test_fw001_does_not_flag_restricted_rule():
    firewall = make_firewall()

    firewall.add_rule(
        make_rule(
            0,
            action="permit",
            protocol="tcp",
            source=["any"],
            destination=["10.10.10.10"],
            destination_ports=[443],
        )
    )

    findings = analyze_firewall(firewall)
    fw001 = findings_for_code(findings, "FW-001")

    assert fw001 == []


# ============================================================================
# FW-002 — Dangerous ports
# ============================================================================

def test_fw002_detects_ssh():
    firewall = make_firewall()

    firewall.add_rule(
        make_rule(
            0,
            action="permit",
            protocol="tcp",
            source=["any"],
            destination=["any"],
            destination_ports=[22],
        )
    )

    findings = analyze_firewall(firewall)
    fw002 = findings_for_code(findings, "FW-002")

    assert len(fw002) == 1


def test_fw002_detects_rdp():
    firewall = make_firewall()

    firewall.add_rule(
        make_rule(
            0,
            action="permit",
            protocol="tcp",
            source=["any"],
            destination=["any"],
            destination_ports=[3389],
        )
    )

    findings = analyze_firewall(firewall)
    fw002 = findings_for_code(findings, "FW-002")

    assert len(fw002) == 1


def test_fw002_does_not_flag_https():
    firewall = make_firewall()

    firewall.add_rule(
        make_rule(
            0,
            action="permit",
            protocol="tcp",
            source=["any"],
            destination=["any"],
            destination_ports=[443],
        )
    )

    findings = analyze_firewall(firewall)
    fw002 = findings_for_code(findings, "FW-002")

    assert fw002 == []


# ============================================================================
# FW-003 — Missing logging
# ============================================================================

def test_fw003_detects_missing_logging():
    firewall = make_firewall()

    firewall.add_rule(
        make_rule(
            0,
            action="permit",
            protocol="tcp",
            source=["any"],
            destination=["10.10.10.10"],
            destination_ports=[443],
            logging=False,
        )
    )

    findings = analyze_firewall(firewall)
    fw003 = findings_for_code(findings, "FW-003")

    assert len(fw003) == 1


def test_fw003_does_not_flag_logged_rule():
    firewall = make_firewall()

    firewall.add_rule(
        make_rule(
            0,
            action="permit",
            protocol="tcp",
            source=["any"],
            destination=["10.10.10.10"],
            destination_ports=[443],
            logging=True,
        )
    )

    findings = analyze_firewall(firewall)
    fw003 = findings_for_code(findings, "FW-003")

    assert fw003 == []


# ============================================================================
# FW-004 — Shadowed rules
# ============================================================================

def test_fw004_detects_shadowed_permit():
    firewall = make_firewall()

    firewall.add_rule(
        make_rule(
            0,
            action="permit",
            protocol="tcp",
            source=["any"],
            destination=["10.10.10.0/24"],
            destination_ports=[443],
        )
    )

    firewall.add_rule(
        make_rule(
            1,
            action="permit",
            protocol="tcp",
            source=["any"],
            destination=["10.10.10.10"],
            destination_ports=[443],
        )
    )

    findings = analyze_firewall(firewall)
    fw004 = findings_for_code(findings, "FW-004")

    assert len(fw004) == 1


def test_fw004_does_not_flag_first_rule():
    firewall = make_firewall()

    firewall.add_rule(
        make_rule(
            0,
            action="permit",
            protocol="tcp",
            source=["any"],
            destination=["10.10.10.10"],
            destination_ports=[443],
        )
    )

    findings = analyze_firewall(firewall)
    fw004 = findings_for_code(findings, "FW-004")

    assert fw004 == []


# ============================================================================
# FW-005 — Overlapping permit rules
# ============================================================================

def test_fw005_detects_overlapping_permits():
    firewall = make_firewall()

    firewall.add_rule(
        make_rule(
            0,
            action="permit",
            protocol="tcp",
            source=["10.10.10.0/25",
                     "10.10.20.0/24"],
            destination=["172.16.10.0/25",
                         "172.16.20.0/24"],
            destination_ports=[443],
        )
    )

    firewall.add_rule(
        make_rule(
            1,
            action="permit",
            protocol="tcp",
            source=["10.10.10.0/25",
                    "10.10.30.0/24"],
            destination=["172.16.10.0/25",
                         "172.16.30.0/24"],
            destination_ports=[443],
        )
    )

    findings = analyze_firewall(firewall)
    fw005 = findings_for_code(findings, "FW-005")

    assert len(fw005) == 1


# ============================================================================
# FW-006 — Duplicate rules
# ============================================================================

def test_fw006_detects_duplicate_rules():
    firewall = make_firewall()

    firewall.add_rule(
        make_rule(
            0,
            action="permit",
            protocol="tcp",
            source=["any"],
            destination=["10.10.10.10"],
            destination_ports=[443],
        )
    )

    firewall.add_rule(
        make_rule(
            1,
            action="permit",
            protocol="tcp",
            source=["any"],
            destination=["10.10.10.10"],
            destination_ports=[443],
        )
    )

    findings = analyze_firewall(firewall)
    fw006 = findings_for_code(findings, "FW-006")

    assert len(fw006) == 1


def test_fw006_does_not_flag_different_rules():
    firewall = make_firewall()

    firewall.add_rule(
        make_rule(
            0,
            action="permit",
            protocol="tcp",
            source=["any"],
            destination=["10.10.10.10"],
            destination_ports=[443],
        )
    )

    firewall.add_rule(
        make_rule(
            1,
            action="permit",
            protocol="tcp",
            source=["any"],
            destination=["10.10.10.11"],
            destination_ports=[443],
        )
    )

    findings = analyze_firewall(firewall)
    fw006 = findings_for_code(findings, "FW-006")

    assert fw006 == []


# ============================================================================
# FW-007 — Unreachable deny rules
# ============================================================================

def test_fw007_detects_unreachable_deny():
    firewall = make_firewall()

    firewall.add_rule(
        make_rule(
            0,
            action="permit",
            protocol="ip",
            source=["any"],
            destination=["any"],
        )
    )

    firewall.add_rule(
        make_rule(
            1,
            action="deny",
            protocol="ip",
            source=["any"],
            destination=["any"],
        )
    )

    findings = analyze_firewall(firewall)
    fw007 = findings_for_code(findings, "FW-007")

    assert len(fw007) == 1


def test_fw007_does_not_flag_reachable_deny():
    firewall = make_firewall()

    firewall.add_rule(
        make_rule(
            0,
            action="permit",
            protocol="tcp",
            source=["any"],
            destination=["10.10.10.10"],
            destination_ports=[443],
        )
    )

    firewall.add_rule(
        make_rule(
            1,
            action="deny",
            protocol="tcp",
            source=["any"],
            destination=["10.10.10.20"],
            destination_ports=[443],
        )
    )

    findings = analyze_firewall(firewall)
    fw007 = findings_for_code(findings, "FW-007")

    assert fw007 == []


# ============================================================================
# FW-008 — Static NAT
# ============================================================================

def test_fw008_detects_static_nat():
    firewall = make_firewall()

    firewall.add_nat_rule(
        NATRule(
            id=0,
            source="10.10.10.10",
            translated_source="203.0.113.10",
            destination="any",
            translated_destination="any",
            protocol="ip",
        )
    )

    findings = analyze_firewall(firewall)
    fw008 = findings_for_code(findings, "FW-008")

    assert len(fw008) == 1


# ============================================================================
# FW-009 — Duplicate NAT
# ============================================================================

def test_fw009_detects_duplicate_nat():
    firewall = make_firewall()

    firewall.add_nat_rule(
        NATRule(
            id=0,
            source="10.10.10.10",
            translated_source="203.0.113.10",
            destination="any",
            translated_destination="any",
            protocol="ip",
        )
    )

    firewall.add_nat_rule(
        NATRule(
            id=1,
            source="10.10.10.10",
            translated_source="203.0.113.10",
            destination="any",
            translated_destination="any",
            protocol="ip",
        )
    )

    findings = analyze_firewall(firewall)
    fw009 = findings_for_code(findings, "FW-009")

    assert len(fw009) == 1


# ============================================================================
# FW-010 — NAT / ACL consistency
# ============================================================================

def test_fw010_detects_nat_acl_match():
    firewall = make_firewall()

    firewall.add_nat_rule(
        NATRule(
            id=0,
            source="10.10.10.10",
            translated_source="203.0.113.10",
            destination="any",
            translated_destination="any",
            protocol="ip",
        )
    )

    firewall.add_rule(
        make_rule(
            0,
            action="permit",
            protocol="ip",
            source=["any"],
            destination=["203.0.113.0/24"],
        )
    )

    findings = analyze_firewall(firewall)
    fw010 = findings_for_code(findings, "FW-010")

    assert len(fw010) == 1


def test_fw010_detects_missing_matching_acl():
    firewall = make_firewall()

    firewall.add_nat_rule(
        NATRule(
            id=0,
            source="10.10.10.10",
            translated_source="203.0.113.10",
            destination="any",
            translated_destination="any",
            protocol="ip",
        )
    )

    firewall.add_rule(
        make_rule(
            0,
            action="permit",
            protocol="tcp",
            source=["any"],
            destination=["192.168.1.0/24"],
            destination_ports=[443],
        )
    )

    findings = analyze_firewall(firewall)
    fw010 = findings_for_code(findings, "FW-010")

    assert len(fw010) == 1


# ============================================================================
# FW-011 — Dangerous service exposure
# ============================================================================

def test_fw011_detects_dangerous_service():
    firewall = make_firewall()

    firewall.add_service(
        Service(
            name="SSH_SERVICE",
            protocol="tcp",
            ports=[22],
        )
    )

    firewall.add_rule(
        make_rule(
            0,
            action="permit",
            protocol="tcp",
            source=["any"],
            destination=["any"],
            destination_services=["SSH_SERVICE"],
        )
    )

    findings = analyze_firewall(firewall)
    fw011 = findings_for_code(findings, "FW-011")

    assert len(fw011) == 1


# ============================================================================
# General engine behavior
# ============================================================================

def test_disabled_rule_is_not_analyzed():
    firewall = make_firewall()

    firewall.add_rule(
        make_rule(
            0,
            action="permit",
            protocol="ip",
            source=["any"],
            destination=["any"],
            disabled=True,
        )
    )

    findings = analyze_firewall(firewall)

    assert findings_for_code(findings, "FW-001") == []


def test_analyze_firewall_returns_all_findings():
    firewall = make_firewall()

    firewall.add_rule(
        make_rule(
            0,
            action="permit",
            protocol="ip",
            source=["any"],
            destination=["any"],
        )
    )

    findings = analyze_firewall(firewall)
    codes = finding_codes(findings)

    assert "FW-001" in codes
    assert "FW-003" in codes


def test_engine_finding_codes_are_unique_per_expected_condition():
    firewall = make_firewall()

    firewall.add_rule(
        make_rule(
            0,
            action="permit",
            protocol="ip",
            source=["any"],
            destination=["any"],
        )
    )

    firewall.add_rule(
        make_rule(
            1,
            action="deny",
            protocol="ip",
            source=["any"],
            destination=["any"],
        )
    )

    findings = analyze_firewall(firewall)
    codes = finding_codes(findings)

    assert "FW-001" in codes
    assert "FW-007" in codes
    assert codes.count("FW-001") == 1
    assert codes.count("FW-007") == 1


def test_engine_handles_empty_firewall():
    firewall = make_firewall()

    findings = analyze_firewall(firewall)

    assert findings == []


def test_engine_handles_multiple_rules():
    firewall = make_firewall()

    firewall.add_rule(
        make_rule(
            0,
            action="permit",
            protocol="ip",
            source=["any"],
            destination=["any"],
        )
    )

    firewall.add_rule(
        make_rule(
            1,
            action="permit",
            protocol="tcp",
            source=["any"],
            destination=["any"],
            destination_ports=[22],
        )
    )

    firewall.add_rule(
        make_rule(
            2,
            action="permit",
            protocol="tcp",
            source=["any"],
            destination=["any"],
            destination_ports=[3389],
        )
    )

    findings = analyze_firewall(firewall)
    codes = finding_codes(findings)

    assert "FW-001" in codes
    assert codes.count("FW-002") == 2
    assert codes.count("FW-003") == 3

    # ============================================================================
# FW-012 — Unused network objects
# ============================================================================

def test_fw012_detects_unused_network_object():
    firewall = make_firewall()

    firewall.add_network(
        NetworkObject(
            name="UNUSED_SERVER",
            networks=["10.10.10.10/32"],
        )
    )

    findings = analyze_firewall(firewall)
    fw012 = findings_for_code(findings, "FW-012")

    assert len(fw012) == 1


def test_fw012_does_not_flag_used_network_object():
    firewall = make_firewall()

    firewall.add_network(
        NetworkObject(
            name="WEB_SERVER",
            networks=["10.10.10.10/32"],
        )
    )

    firewall.add_rule(
        make_rule(
            0,
            action="permit",
            protocol="tcp",
            source=["any"],
            destination=["WEB_SERVER"],
            destination_ports=[443],
        )
    )

    findings = analyze_firewall(firewall)
    fw012 = findings_for_code(findings, "FW-012")

    assert fw012 == []


# ============================================================================
# FW-013 — Unused service objects
# ============================================================================

def test_fw013_detects_unused_service_object():
    firewall = make_firewall()

    firewall.add_service(
        Service(
            name="UNUSED_SERVICE",
            protocol="tcp",
            ports=[8080],
        )
    )

    findings = analyze_firewall(firewall)
    fw013 = findings_for_code(findings, "FW-013")

    assert len(fw013) == 1


def test_fw013_does_not_flag_used_service_object():
    firewall = make_firewall()

    firewall.add_service(
        Service(
            name="HTTPS_SERVICE",
            protocol="tcp",
            ports=[443],
        )
    )

    firewall.add_rule(
        make_rule(
            0,
            action="permit",
            protocol="tcp",
            source=["any"],
            destination=["10.10.10.10"],
            destination_services=["HTTPS_SERVICE"],
        )
    )

    findings = analyze_firewall(firewall)
    fw013 = findings_for_code(findings, "FW-013")

    assert fw013 == []