from app.analyzer.engine import FirewallAnalyzer
from app.models.firewall import FirewallConfig, Route


def make_firewall(routes):
    firewall = FirewallConfig(vendor="Cisco ASA")

    for route in routes:
        firewall.routes.append(route)

    return firewall


def make_route(
    destination,
    next_hop="10.0.0.1",
    interface="inside",
    metric=None,
    line_number=None,
):
    return Route(
        destination=destination,
        next_hop=next_hop,
        interface=interface,
        metric=metric,
        line_number=line_number,
    )


def get_findings(firewall, code):
    analyzer = FirewallAnalyzer(firewall)

    return [
        finding
        for finding in analyzer.analyze()
        if finding.code == code
    ]


def test_more_specific_route_with_different_next_hop_detected():
    firewall = make_firewall([
        make_route(
            "10.10.0.0/16",
            next_hop="10.0.0.1",
            line_number=10,
        ),
        make_route(
            "10.10.10.0/24",
            next_hop="10.0.0.2",
            line_number=20,
        ),
    ])

    findings = get_findings(firewall, "FW-023")

    assert len(findings) == 1
    assert findings[0].line_number == 20


def test_more_specific_route_with_different_interface_detected():
    firewall = make_firewall([
        make_route(
            "10.10.0.0/16",
            interface="inside",
            line_number=10,
        ),
        make_route(
            "10.10.10.0/24",
            interface="outside",
            line_number=20,
        ),
    ])

    findings = get_findings(firewall, "FW-023")

    assert len(findings) == 1
    assert findings[0].line_number == 20


def test_different_next_hop_and_interface_detected():
    firewall = make_firewall([
        make_route(
            "10.10.0.0/16",
            next_hop="10.0.0.1",
            interface="inside",
            line_number=10,
        ),
        make_route(
            "10.10.10.0/24",
            next_hop="10.0.0.2",
            interface="outside",
            line_number=20,
        ),
    ])

    findings = get_findings(firewall, "FW-023")

    assert len(findings) == 1

    finding = findings[0]

    assert finding.line_number == 20
    assert finding.severity == "MEDIUM"
    assert finding.code == "FW-023"
    assert finding.title == "Potentially conflicting route"


def test_same_forwarding_path_is_fw022_not_fw023():
    firewall = make_firewall([
        make_route(
            "10.10.0.0/16",
            next_hop="10.0.0.1",
            interface="inside",
            line_number=10,
        ),
        make_route(
            "10.10.10.0/24",
            next_hop="10.0.0.1",
            interface="inside",
            line_number=20,
        ),
    ])

    fw022 = get_findings(firewall, "FW-022")
    fw023 = get_findings(firewall, "FW-023")

    assert len(fw022) == 1
    assert len(fw023) == 0


def test_disjoint_routes_not_conflicting():
    firewall = make_firewall([
        make_route(
            "10.10.0.0/16",
            next_hop="10.0.0.1",
            line_number=10,
        ),
        make_route(
            "10.20.0.0/16",
            next_hop="10.0.0.2",
            line_number=20,
        ),
    ])

    findings = get_findings(firewall, "FW-023")

    assert len(findings) == 0


def test_same_destination_different_path_not_fw023():
    firewall = make_firewall([
        make_route(
            "10.10.10.0/24",
            next_hop="10.0.0.1",
            interface="inside",
            line_number=10,
        ),
        make_route(
            "10.10.10.0/24",
            next_hop="10.0.0.2",
            interface="outside",
            line_number=20,
        ),
    ])

    findings = get_findings(firewall, "FW-023")

    assert len(findings) == 0


def test_multiple_more_specific_routes_generate_findings():
    firewall = make_firewall([
        make_route(
            "10.10.0.0/16",
            next_hop="10.0.0.1",
            interface="inside",
            line_number=10,
        ),
        make_route(
            "10.10.10.0/24",
            next_hop="10.0.0.2",
            interface="inside",
            line_number=20,
        ),
        make_route(
            "10.10.20.0/24",
            next_hop="10.0.0.3",
            interface="outside",
            line_number=30,
        ),
    ])

    findings = get_findings(firewall, "FW-023")

    assert len(findings) == 2
    assert {finding.line_number for finding in findings} == {
        20,
        30,
    }


def test_ipv4_and_ipv6_routes_do_not_conflict():
    firewall = make_firewall([
        make_route(
            "10.10.0.0/16",
            next_hop="10.0.0.1",
            line_number=10,
        ),
        make_route(
            "2001:db8::/32",
            next_hop="2001:db8::1",
            line_number=20,
        ),
    ])

    findings = get_findings(firewall, "FW-023")

    assert len(findings) == 0