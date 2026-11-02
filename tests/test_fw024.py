from app.analyzer.engine import FirewallAnalyzer
from app.models.firewall import FirewallConfig, Route


def make_firewall(routes):
    """
    Create a firewall configuration containing the supplied routes.
    """
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
    """
    Create a route for testing.
    """
    return Route(
        destination=destination,
        next_hop=next_hop,
        interface=interface,
        metric=metric,
        line_number=line_number,
    )


def get_findings(firewall, code):
    """
    Run the firewall analyzer and return findings
    matching the supplied finding code.
    """
    analyzer = FirewallAnalyzer(firewall)

    return [
        finding
        for finding in analyzer.analyze()
        if finding.code == code
    ]


def test_missing_default_route_detected():
    """
    FW-024 should be reported when IPv4 routes exist
    but no IPv4 default route is configured.
    """
    firewall = make_firewall([
        make_route(
            "10.10.0.0/16",
            line_number=10,
        ),
        make_route(
            "192.168.1.0/24",
            line_number=20,
        ),
    ])

    findings = get_findings(firewall, "FW-024")

    assert len(findings) == 1
    assert findings[0].code == "FW-024"
    assert findings[0].severity == "MEDIUM"
    assert findings[0].line_number is None


def test_default_route_prevents_fw024():
    """
    An IPv4 default route should prevent FW-024.
    """
    firewall = make_firewall([
        make_route(
            "0.0.0.0/0",
            next_hop="10.0.0.1",
            line_number=10,
        ),
    ])

    findings = get_findings(firewall, "FW-024")

    assert len(findings) == 0


def test_default_route_with_other_routes_prevents_fw024():
    """
    FW-024 should not be reported when an IPv4 default
    route exists alongside other IPv4 routes.
    """
    firewall = make_firewall([
        make_route(
            "10.10.0.0/16",
            line_number=10,
        ),
        make_route(
            "192.168.1.0/24",
            line_number=20,
        ),
        make_route(
            "0.0.0.0/0",
            next_hop="10.0.0.1",
            line_number=30,
        ),
    ])

    findings = get_findings(firewall, "FW-024")

    assert len(findings) == 0


def test_ipv6_default_route_does_not_satisfy_ipv4_default_route():
    """
    An IPv6-only routing table should not trigger FW-024.

    FW-024 evaluates IPv4 routing configurations only.
    """
    firewall = make_firewall([
        make_route(
            "::/0",
            next_hop="2001:db8::1",
            line_number=10,
        ),
    ])

    findings = get_findings(firewall, "FW-024")

    assert len(findings) == 0


def test_more_specific_routes_do_not_count_as_default_route():
    """
    Two /1 IPv4 routes should not be treated as
    an explicit IPv4 default route.
    """
    firewall = make_firewall([
        make_route(
            "0.0.0.0/1",
            next_hop="10.0.0.1",
            line_number=10,
        ),
        make_route(
            "128.0.0.0/1",
            next_hop="10.0.0.2",
            line_number=20,
        ),
    ])

    findings = get_findings(firewall, "FW-024")

    assert len(findings) == 1
    assert findings[0].code == "FW-024"


def test_default_route_with_host_bits_is_normalized():
    """
    A route written as 10.20.30.40/0 should normalize
    to 0.0.0.0/0 and prevent FW-024.
    """
    firewall = make_firewall([
        make_route(
            "10.20.30.40/0",
            next_hop="10.0.0.1",
            line_number=10,
        ),
    ])

    findings = get_findings(firewall, "FW-024")

    assert len(findings) == 0


def test_invalid_route_does_not_count_as_default_route():
    """
    Invalid-only routing configuration should not
    trigger FW-024 because no valid IPv4 routes exist.
    """
    firewall = make_firewall([
        make_route(
            "not-a-network",
            line_number=10,
        ),
    ])

    findings = get_findings(firewall, "FW-024")

    assert len(findings) == 0


def test_empty_firewall_does_not_report_missing_default_route():
    """
    An empty route table should not trigger FW-024.
    """
    firewall = make_firewall([])

    findings = get_findings(firewall, "FW-024")

    assert len(findings) == 0


def test_ipv6_default_route_does_not_cover_ipv4_routes():
    """
    An IPv6 default route must not suppress FW-024
    when IPv4 routes exist without an IPv4 default route.
    """
    firewall = make_firewall([
        make_route(
            "10.10.0.0/16",
            next_hop="10.0.0.1",
            line_number=10,
        ),
        make_route(
            "::/0",
            next_hop="2001:db8::1",
            line_number=20,
        ),
    ])

    findings = get_findings(firewall, "FW-024")

    assert len(findings) == 1
    assert findings[0].code == "FW-024"
    assert findings[0].severity == "MEDIUM"