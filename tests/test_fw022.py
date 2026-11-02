from app.analyzer.engine import FirewallAnalyzer
from app.models.firewall import FirewallConfig, Route


def make_firewall(routes):
    firewall = FirewallConfig(
        vendor="Cisco ASA"
    )

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


def test_more_specific_route_with_same_path_detected():
    firewall = make_firewall(
        [
            make_route(
                "10.10.0.0/16",
                line_number=10,
            ),
            make_route(
                "10.10.10.0/24",
                line_number=20,
            ),
        ]
    )

    findings = get_findings(
        firewall,
        "FW-022",
    )

    assert len(findings) == 1
    assert findings[0].line_number == 20


def test_disjoint_routes_not_redundant():
    firewall = make_firewall(
        [
            make_route(
                "10.10.0.0/16",
                line_number=10,
            ),
            make_route(
                "10.20.0.0/16",
                line_number=20,
            ),
        ]
    )

    findings = get_findings(
        firewall,
        "FW-022",
    )

    assert len(findings) == 0


def test_more_specific_route_with_different_next_hop_not_reported():
    firewall = make_firewall(
        [
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
        ]
    )

    findings = get_findings(
        firewall,
        "FW-022",
    )

    assert len(findings) == 0


def test_more_specific_route_with_different_interface_not_reported():
    firewall = make_firewall(
        [
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
        ]
    )

    findings = get_findings(
        firewall,
        "FW-022",
    )

    assert len(findings) == 0


def test_exact_duplicate_is_fw021_not_fw022():
    firewall = make_firewall(
        [
            make_route(
                "10.10.10.0/24",
                line_number=10,
            ),
            make_route(
                "10.10.10.0/24",
                line_number=20,
            ),
        ]
    )

    fw021 = get_findings(
        firewall,
        "FW-021",
    )

    fw022 = get_findings(
        firewall,
        "FW-022",
    )

    assert len(fw021) == 1
    assert len(fw022) == 0


def test_default_route_does_not_make_specific_route_redundant():
    firewall = make_firewall(
        [
            make_route(
                "0.0.0.0/0",
                line_number=10,
            ),
            make_route(
                "10.10.10.0/24",
                line_number=20,
            ),
        ]
    )

    findings = get_findings(
        firewall,
        "FW-022",
    )

    assert len(findings) == 1