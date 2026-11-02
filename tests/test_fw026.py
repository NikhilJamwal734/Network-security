from app.analyzer.engine import FirewallAnalyzer
from app.analyzer.route_matcher import RouteMatcher
from app.models.firewall import FirewallConfig, Route


def make_route(
    destination="10.10.0.0/16",
    next_hop="10.0.0.1",
    interface="inside",
    line_number=10,
):
    return Route(
        destination=destination,
        next_hop=next_hop,
        interface=interface,
        line_number=line_number,
    )


def get_fw026_findings(routes):
    firewall = FirewallConfig(vendor="Cisco ASA")
    firewall.routes.extend(routes)

    analyzer = FirewallAnalyzer(firewall)

    return [
        finding
        for finding in analyzer.analyze()
        if finding.code == "FW-026"
    ]


def test_ipv4_destination_ipv4_next_hop():
    findings = get_fw026_findings([
        make_route(
            destination="10.10.0.0/16",
            next_hop="10.0.0.1",
        ),
    ])

    assert len(findings) == 0


def test_ipv6_destination_ipv6_next_hop():
    findings = get_fw026_findings([
        make_route(
            destination="2001:db8:100::/64",
            next_hop="2001:db8::1",
        ),
    ])

    assert len(findings) == 0


def test_ipv4_destination_ipv6_next_hop():
    findings = get_fw026_findings([
        make_route(
            destination="10.10.0.0/16",
            next_hop="2001:db8::1",
            line_number=20,
        ),
    ])

    assert len(findings) == 1
    assert findings[0].code == "FW-026"
    assert findings[0].severity == "MEDIUM"
    assert findings[0].line_number == 20


def test_ipv6_destination_ipv4_next_hop():
    findings = get_fw026_findings([
        make_route(
            destination="2001:db8:100::/64",
            next_hop="10.0.0.1",
            line_number=30,
        ),
    ])

    assert len(findings) == 1
    assert findings[0].line_number == 30


def test_multiple_mismatched_routes():
    findings = get_fw026_findings([
        make_route(
            destination="10.10.0.0/16",
            next_hop="2001:db8::1",
            line_number=10,
        ),
        make_route(
            destination="2001:db8:100::/64",
            next_hop="10.0.0.1",
            line_number=20,
        ),
    ])

    assert len(findings) == 2
    assert {
        finding.line_number
        for finding in findings
    } == {10, 20}


def test_mixed_valid_and_mismatched_routes():
    findings = get_fw026_findings([
        make_route(
            destination="10.10.0.0/16",
            next_hop="10.0.0.1",
            line_number=10,
        ),
        make_route(
            destination="192.168.1.0/24",
            next_hop="2001:db8::1",
            line_number=20,
        ),
    ])

    assert len(findings) == 1
    assert findings[0].line_number == 20


def test_invalid_next_hop_is_not_fw026():
    findings = get_fw026_findings([
        make_route(
            destination="10.10.0.0/16",
            next_hop="999.999.999.999",
        ),
    ])

    assert len(findings) == 0


def test_invalid_destination_is_not_fw026():
    findings = get_fw026_findings([
        make_route(
            destination="invalid-network",
            next_hop="10.0.0.1",
        ),
    ])

    assert len(findings) == 0


def test_empty_routes():
    findings = get_fw026_findings([])

    assert len(findings) == 0


def test_ipv4_default_route_with_ipv6_next_hop():
    findings = get_fw026_findings([
        make_route(
            destination="0.0.0.0/0",
            next_hop="2001:db8::1",
        ),
    ])

    assert len(findings) == 1


def test_ipv6_default_route_with_ipv4_next_hop():
    findings = get_fw026_findings([
        make_route(
            destination="::/0",
            next_hop="10.0.0.1",
        ),
    ])

    assert len(findings) == 1


def test_family_mismatch_helper():
    assert RouteMatcher.has_next_hop_family_mismatch(
        "10.10.0.0/16",
        "2001:db8::1",
    )

    assert RouteMatcher.has_next_hop_family_mismatch(
        "2001:db8:100::/64",
        "10.0.0.1",
    )

    assert not RouteMatcher.has_next_hop_family_mismatch(
        "10.10.0.0/16",
        "10.0.0.1",
    )

    assert not RouteMatcher.has_next_hop_family_mismatch(
        "2001:db8:100::/64",
        "2001:db8::1",
    )

    assert not RouteMatcher.has_next_hop_family_mismatch(
        "10.10.0.0/16",
        "invalid-next-hop",
    )


def test_cisco_style_destination_mask():
    findings = get_fw026_findings([
        make_route(
            destination="10.10.0.0 255.255.0.0",
            next_hop="2001:db8::1",
        ),
    ])

    assert len(findings) == 1