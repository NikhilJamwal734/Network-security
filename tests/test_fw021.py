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


def test_duplicate_routes_detected():
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

    findings = get_findings(
        firewall,
        "FW-021",
    )

    assert len(findings) == 1
    assert findings[0].line_number == 20


def test_duplicate_routes_with_different_metric_detected():
    firewall = make_firewall(
        [
            make_route(
                "10.10.10.0/24",
                metric=1,
                line_number=10,
            ),
            make_route(
                "10.10.10.0/24",
                metric=10,
                line_number=20,
            ),
        ]
    )

    findings = get_findings(
        firewall,
        "FW-021",
    )

    assert len(findings) == 1


def test_different_next_hop_not_duplicate():
    firewall = make_firewall(
        [
            make_route(
                "10.10.10.0/24",
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
        "FW-021",
    )

    assert len(findings) == 0


def test_different_interface_not_duplicate():
    firewall = make_firewall(
        [
            make_route(
                "10.10.10.0/24",
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
        "FW-021",
    )

    assert len(findings) == 0


def test_three_duplicate_routes_generate_two_findings():
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
            make_route(
                "10.10.10.0/24",
                line_number=30,
            ),
        ]
    )

    findings = get_findings(
        firewall,
        "FW-021",
    )

    assert len(findings) == 2