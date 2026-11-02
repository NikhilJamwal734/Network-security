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


def get_fw025_findings(routes):
    firewall = FirewallConfig(vendor="Cisco ASA")
    firewall.routes.extend(routes)

    analyzer = FirewallAnalyzer(firewall)

    return [
        finding
        for finding in analyzer.analyze()
        if finding.code == "FW-025"
    ]


def test_valid_ipv4_next_hop():
    findings = get_fw025_findings([
        make_route(next_hop="10.0.0.1"),
    ])

    assert len(findings) == 0


def test_valid_ipv6_next_hop():
    findings = get_fw025_findings([
        make_route(
            destination="2001:db8:100::/64",
            next_hop="2001:db8::1",
        ),
    ])

    assert len(findings) == 0


def test_invalid_ipv4_next_hop():
    findings = get_fw025_findings([
        make_route(
            next_hop="999.999.999.999",
            line_number=20,
        ),
    ])

    assert len(findings) == 1
    assert findings[0].code == "FW-025"
    assert findings[0].severity == "MEDIUM"
    assert findings[0].line_number == 20


def test_invalid_hostname_next_hop():
    findings = get_fw025_findings([
        make_route(next_hop="invalid-gateway"),
    ])

    assert len(findings) == 1


def test_empty_next_hop():
    findings = get_fw025_findings([
        make_route(next_hop=""),
    ])

    assert len(findings) == 1


def test_whitespace_next_hop():
    findings = get_fw025_findings([
        make_route(next_hop="   "),
    ])

    assert len(findings) == 1


def test_multiple_invalid_next_hops():
    findings = get_fw025_findings([
        make_route(
            destination="10.10.0.0/16",
            next_hop="999.999.999.999",
            line_number=10,
        ),
        make_route(
            destination="192.168.1.0/24",
            next_hop="invalid-gateway",
            line_number=20,
        ),
    ])

    assert len(findings) == 2
    assert {finding.line_number for finding in findings} == {
        10,
        20,
    }


def test_mixed_valid_and_invalid_next_hops():
    findings = get_fw025_findings([
        make_route(
            destination="10.10.0.0/16",
            next_hop="10.0.0.1",
            line_number=10,
        ),
        make_route(
            destination="192.168.1.0/24",
            next_hop="999.999.999.999",
            line_number=20,
        ),
    ])

    assert len(findings) == 1
    assert findings[0].line_number == 20


def test_no_routes():
    findings = get_fw025_findings([])

    assert len(findings) == 0


def test_next_hop_validation_helper():
    assert RouteMatcher.is_valid_next_hop("10.0.0.1")
    assert RouteMatcher.is_valid_next_hop("2001:db8::1")
    assert RouteMatcher.is_valid_next_hop(" 10.0.0.1 ")

    assert not RouteMatcher.is_valid_next_hop("999.999.999.999")
    assert not RouteMatcher.is_valid_next_hop("invalid-gateway")
    assert not RouteMatcher.is_valid_next_hop("")
    assert not RouteMatcher.is_valid_next_hop("   ")
    assert not RouteMatcher.is_valid_next_hop(None)