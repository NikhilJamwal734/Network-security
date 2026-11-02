from ipaddress import ip_network

from app.analyzer.object_resolver import NetworkObjectResolver
from app.analyzer.rule_matcher import RuleMatcher
from app.models.firewall import FirewallConfig
from app.models.rule import FirewallRule


def create_matcher():
    firewall = FirewallConfig(
        vendor="Cisco ASA",
        hostname="TEST-FIREWALL",
    )

    resolver = NetworkObjectResolver(
        firewall
    )

    return RuleMatcher(
        resolver
    )


def create_rule(
    rule_id,
    action="permit",
    protocol="ip",
    source=None,
    destination=None,
    source_ports=None,
    destination_ports=None,
):
    return FirewallRule(
        id=rule_id,
        line_number=rule_id + 1,
        name="TEST_ACL",
        action=action,
        protocol=protocol,
        source=source or ["any"],
        destination=destination or ["any"],
        source_ports=source_ports or [],
        destination_ports=destination_ports or [],
    )


def test_any_source_contains_specific_source():
    matcher = create_matcher()

    broader = create_rule(
        1,
        source=["any"],
    )

    narrower = create_rule(
        2,
        source=["10.10.10.10"],
    )

    assert matcher.matches_contained_by(
        broader,
        narrower,
    )


def test_specific_source_does_not_contain_any():
    matcher = create_matcher()

    broader = create_rule(
        1,
        source=["10.10.10.0/24"],
    )

    narrower = create_rule(
        2,
        source=["any"],
    )

    assert not matcher.matches_contained_by(
        broader,
        narrower,
    )


def test_network_contains_host():
    matcher = create_matcher()

    broader = create_rule(
        1,
        source=["10.10.10.0/24"],
    )

    narrower = create_rule(
        2,
        source=["10.10.10.10"],
    )

    assert matcher.matches_contained_by(
        broader,
        narrower,
    )


def test_host_does_not_contain_network():
    matcher = create_matcher()

    broader = create_rule(
        1,
        source=["10.10.10.10"],
    )

    narrower = create_rule(
        2,
        source=["10.10.10.0/24"],
    )

    assert not matcher.matches_contained_by(
        broader,
        narrower,
    )


def test_equal_rules():
    matcher = create_matcher()

    first = create_rule(
        1,
        protocol="tcp",
        source=["10.10.10.0/24"],
        destination=["10.20.10.0/24"],
        destination_ports=[443],
    )

    second = create_rule(
        2,
        protocol="tcp",
        source=["10.10.10.0/24"],
        destination=["10.20.10.0/24"],
        destination_ports=[443],
    )

    assert matcher.rules_equal(
        first,
        second,
    )


def test_different_actions_are_not_equal():
    matcher = create_matcher()

    first = create_rule(
        1,
        action="permit",
    )

    second = create_rule(
        2,
        action="deny",
    )

    assert not matcher.rules_equal(
        first,
        second,
    )


def test_different_protocols_are_not_equal():
    matcher = create_matcher()

    first = create_rule(
        1,
        protocol="tcp",
    )

    second = create_rule(
        2,
        protocol="udp",
    )

    assert not matcher.rules_equal(
        first,
        second,
    )


def test_different_sources_are_not_equal():
    matcher = create_matcher()

    first = create_rule(
        1,
        source=["10.10.10.10"],
    )

    second = create_rule(
        2,
        source=["10.10.10.11"],
    )

    assert not matcher.rules_equal(
        first,
        second,
    )


def test_different_ports_are_not_equal():
    matcher = create_matcher()

    first = create_rule(
        1,
        protocol="tcp",
        destination_ports=[443],
    )

    second = create_rule(
        2,
        protocol="tcp",
        destination_ports=[80],
    )

    assert not matcher.rules_equal(
        first,
        second,
    )


def test_ip_protocol_contains_tcp():
    matcher = create_matcher()

    broader = create_rule(
        1,
        protocol="ip",
    )

    narrower = create_rule(
        2,
        protocol="tcp",
    )

    assert matcher.matches_contained_by(
        broader,
        narrower,
    )


def test_tcp_does_not_contain_udp():
    matcher = create_matcher()

    broader = create_rule(
        1,
        protocol="tcp",
    )

    narrower = create_rule(
        2,
        protocol="udp",
    )

    assert not matcher.matches_contained_by(
        broader,
        narrower,
    )


def test_tcp_and_udp_do_not_overlap():
    matcher = create_matcher()

    first = create_rule(
        1,
        protocol="tcp",
    )

    second = create_rule(
        2,
        protocol="udp",
    )

    assert not matcher.rules_overlap(
        first,
        second,
    )


def test_ip_and_tcp_overlap():
    matcher = create_matcher()

    first = create_rule(
        1,
        protocol="ip",
    )

    second = create_rule(
        2,
        protocol="tcp",
    )

    assert matcher.rules_overlap(
        first,
        second,
    )


def test_same_networks_overlap():
    matcher = create_matcher()

    first = create_rule(
        1,
        source=["10.10.10.0/24"],
    )

    second = create_rule(
        2,
        source=["10.10.10.0/24"],
    )

    assert matcher.rules_overlap(
        first,
        second,
    )


def test_different_networks_do_not_overlap():
    matcher = create_matcher()

    first = create_rule(
        1,
        source=["10.10.10.0/24"],
    )

    second = create_rule(
        2,
        source=["10.20.10.0/24"],
    )

    assert not matcher.rules_overlap(
        first,
        second,
    )


def test_any_source_overlaps_specific_source():
    matcher = create_matcher()

    first = create_rule(
        1,
        source=["any"],
    )

    second = create_rule(
        2,
        source=["10.10.10.0/24"],
    )

    assert matcher.rules_overlap(
        first,
        second,
    )


def test_any_destination_overlaps_specific_destination():
    matcher = create_matcher()

    first = create_rule(
        1,
        destination=["any"],
    )

    second = create_rule(
        2,
        destination=["10.20.10.0/24"],
    )

    assert matcher.rules_overlap(
        first,
        second,
    )


def test_broader_port_set_contains_narrower_port():
    matcher = create_matcher()

    broader = create_rule(
        1,
        protocol="tcp",
        destination_ports=[80, 443, 8080],
    )

    narrower = create_rule(
        2,
        protocol="tcp",
        destination_ports=[443],
    )

    assert matcher.matches_contained_by(
        broader,
        narrower,
    )


def test_narrower_port_does_not_contain_broader_port_set():
    matcher = create_matcher()

    broader = create_rule(
        1,
        protocol="tcp",
        destination_ports=[443],
    )

    narrower = create_rule(
        2,
        protocol="tcp",
        destination_ports=[80, 443],
    )

    assert not matcher.matches_contained_by(
        broader,
        narrower,
    )


def test_same_ports_are_equal():
    matcher = create_matcher()

    first = create_rule(
        1,
        protocol="tcp",
        destination_ports=[22, 443],
    )

    second = create_rule(
        2,
        protocol="tcp",
        destination_ports=[443, 22],
    )

    assert matcher.rules_equal(
        first,
        second,
    )


def test_different_ports_are_not_equal():
    matcher = create_matcher()

    first = create_rule(
        1,
        protocol="tcp",
        destination_ports=[22],
    )

    second = create_rule(
        2,
        protocol="tcp",
        destination_ports=[443],
    )

    assert not matcher.rules_equal(
        first,
        second,
    )


def test_overlapping_ports():
    matcher = create_matcher()

    first = create_rule(
        1,
        protocol="tcp",
        destination_ports=[22, 443],
    )

    second = create_rule(
        2,
        protocol="tcp",
        destination_ports=[443, 3389],
    )

    assert matcher.rules_overlap(
        first,
        second,
    )


def test_non_overlapping_ports():
    matcher = create_matcher()

    first = create_rule(
        1,
        protocol="tcp",
        destination_ports=[22],
    )

    second = create_rule(
        2,
        protocol="tcp",
        destination_ports=[443],
    )

    assert not matcher.rules_overlap(
        first,
        second,
    )


def test_empty_ports_mean_any_port():
    matcher = create_matcher()

    first = create_rule(
        1,
        protocol="tcp",
    )

    second = create_rule(
        2,
        protocol="tcp",
        destination_ports=[443],
    )

    assert matcher.matches_contained_by(
        first,
        second,
    )

    assert matcher.rules_overlap(
        first,
        second,
    )


def test_object_group_is_resolved():
    firewall = FirewallConfig(
        vendor="Cisco ASA"
    )

    from app.models.network import NetworkObject

    firewall.add_network(
        NetworkObject(
            name="WEB_SERVERS",
            networks=[
                ip_network("10.10.10.10/32"),
                ip_network("10.10.10.11/32"),
            ],
        )
    )

    resolver = NetworkObjectResolver(
        firewall
    )

    matcher = RuleMatcher(
        resolver
    )

    broader = create_rule(
        1,
        destination=[
            "object-group:WEB_SERVERS"
        ],
    )

    narrower = create_rule(
        2,
        destination=[
            "10.10.10.10"
        ],
    )

    assert matcher.matches_contained_by(
        broader,
        narrower,
    )


def test_multiple_networks_can_contain_multiple_targets():
    matcher = create_matcher()

    broader = create_rule(
        1,
        source=[
            "10.10.10.0/24",
            "10.20.10.0/24",
        ],
    )

    narrower = create_rule(
        2,
        source=[
            "10.10.10.10",
            "10.20.10.10",
        ],
    )

    assert matcher.matches_contained_by(
        broader,
        narrower,
    )