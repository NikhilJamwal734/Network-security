from app.analyzer.nat_matcher import NATMatcher
from app.models.firewall import NATRule
from app.models.rule import FirewallRule


def make_nat(
    rule_id=0,
    source="10.10.10.10",
    translated_source="203.0.113.10",
    destination="any",
    translated_destination="any",
    protocol="ip",
    source_port=None,
    destination_port=None,
):
    return NATRule(
        id=rule_id,
        source=source,
        translated_source=translated_source,
        destination=destination,
        translated_destination=translated_destination,
        protocol=protocol,
        source_port=source_port,
        destination_port=destination_port,
    )


def make_rule(
    rule_id=0,
    destination=None,
    protocol="ip",
):
    return FirewallRule(
        id=rule_id,
        line_number=rule_id + 1,
        name=None,
        action="permit",
        protocol=protocol,
        source=["any"],
        destination=destination or ["any"],
    )


# ============================================================================
# matches_same_scope
# ============================================================================

def test_matches_same_scope_accepts_identical_rules():
    matcher = NATMatcher()

    first = make_nat()
    second = make_nat()

    assert matcher.matches_same_scope(
        first,
        second,
    )


def test_matches_same_scope_is_case_insensitive():
    matcher = NATMatcher()

    first = make_nat(
        protocol="TCP",
        destination="ANY",
        translated_destination="ANY",
    )

    second = make_nat(
        protocol="tcp",
        destination="any",
        translated_destination="any",
    )

    assert matcher.matches_same_scope(
        first,
        second,
    )


def test_matches_same_scope_rejects_different_protocol():
    matcher = NATMatcher()

    first = make_nat(protocol="tcp")
    second = make_nat(protocol="udp")

    assert not matcher.matches_same_scope(
        first,
        second,
    )


def test_matches_same_scope_rejects_different_destination():
    matcher = NATMatcher()

    first = make_nat(
        destination="10.10.10.0/24",
    )

    second = make_nat(
        destination="10.10.20.0/24",
    )

    assert not matcher.matches_same_scope(
        first,
        second,
    )


def test_matches_same_scope_rejects_different_translated_destination():
    matcher = NATMatcher()

    first = make_nat(
        translated_destination="203.0.113.0/24",
    )

    second = make_nat(
        translated_destination="198.51.100.0/24",
    )

    assert not matcher.matches_same_scope(
        first,
        second,
    )


# ============================================================================
# shadows
# ============================================================================

def test_shadows_detects_exact_semantic_duplicate():
    matcher = NATMatcher()

    earlier = make_nat(
        source="10.10.10.10",
        translated_source="203.0.113.10",
    )

    later = make_nat(
        source="host:10.10.10.10",
        translated_source="203.0.113.10/32",
    )

    assert matcher.shadows(
        earlier,
        later,
    )


def test_shadows_rejects_different_source():
    matcher = NATMatcher()

    earlier = make_nat(
        source="10.10.10.10",
    )

    later = make_nat(
        source="10.10.10.11",
    )

    assert not matcher.shadows(
        earlier,
        later,
    )


def test_shadows_rejects_different_translated_source():
    matcher = NATMatcher()

    earlier = make_nat(
        translated_source="203.0.113.10",
    )

    later = make_nat(
        translated_source="203.0.113.11",
    )

    assert not matcher.shadows(
        earlier,
        later,
    )


def test_shadows_rejects_different_source_port():
    matcher = NATMatcher()

    earlier = make_nat(
        source_port=443,
    )

    later = make_nat(
        source_port=80,
    )

    assert not matcher.shadows(
        earlier,
        later,
    )


def test_shadows_rejects_different_destination_port():
    matcher = NATMatcher()

    earlier = make_nat(
        destination_port=443,
    )

    later = make_nat(
        destination_port=80,
    )

    assert not matcher.shadows(
        earlier,
        later,
    )


# ============================================================================
# translated_address_matches_rule
# ============================================================================

def test_translated_address_matches_any_destination():
    matcher = NATMatcher()

    nat_rule = make_nat(
        translated_source="203.0.113.10",
    )

    firewall_rule = make_rule(
        destination=["any"],
    )

    assert matcher.translated_address_matches_rule(
        nat_rule,
        firewall_rule,
    )


def test_translated_address_matches_exact_host():
    matcher = NATMatcher()

    nat_rule = make_nat(
        translated_source="203.0.113.10",
    )

    firewall_rule = make_rule(
        destination=["203.0.113.10"],
    )

    assert matcher.translated_address_matches_rule(
        nat_rule,
        firewall_rule,
    )


def test_translated_address_matches_host_prefix():
    matcher = NATMatcher()

    nat_rule = make_nat(
        translated_source="203.0.113.10",
    )

    firewall_rule = make_rule(
        destination=["host:203.0.113.10"],
    )

    assert matcher.translated_address_matches_rule(
        nat_rule,
        firewall_rule,
    )


def test_translated_address_matches_containing_network():
    matcher = NATMatcher()

    nat_rule = make_nat(
        translated_source="203.0.113.10",
    )

    firewall_rule = make_rule(
        destination=["203.0.113.0/24"],
    )

    assert matcher.translated_address_matches_rule(
        nat_rule,
        firewall_rule,
    )


def test_translated_address_matches_netmask_format():
    matcher = NATMatcher()

    nat_rule = make_nat(
        translated_source="203.0.113.10",
    )

    firewall_rule = make_rule(
        destination=["203.0.113.0 255.255.255.0"],
    )

    assert matcher.translated_address_matches_rule(
        nat_rule,
        firewall_rule,
    )


def test_translated_address_does_not_match_unrelated_network():
    matcher = NATMatcher()

    nat_rule = make_nat(
        translated_source="203.0.113.10",
    )

    firewall_rule = make_rule(
        destination=["198.51.100.0/24"],
    )

    assert not matcher.translated_address_matches_rule(
        nat_rule,
        firewall_rule,
    )


def test_translated_address_rejects_interface_translation():
    matcher = NATMatcher()

    nat_rule = make_nat(
        translated_source="interface:outside",
    )

    firewall_rule = make_rule(
        destination=["any"],
    )

    assert not matcher.translated_address_matches_rule(
        nat_rule,
        firewall_rule,
    )


def test_translated_address_rejects_invalid_translation():
    matcher = NATMatcher()

    nat_rule = make_nat(
        translated_source="not-an-ip",
    )

    firewall_rule = make_rule(
        destination=["any"],
    )

    assert not matcher.translated_address_matches_rule(
        nat_rule,
        firewall_rule,
    )


# ============================================================================
# source_matches
# ============================================================================

def test_source_matches_normalizes_host_and_ip():
    matcher = NATMatcher()

    first = make_nat(
        source="10.10.10.10",
    )

    second = make_nat(
        source="host:10.10.10.10",
    )

    assert matcher.source_matches(
        first,
        second,
    )


def test_source_matches_normalizes_netmask():
    matcher = NATMatcher()

    first = make_nat(
        source="10.10.10.0/24",
    )

    second = make_nat(
        source="10.10.10.0 255.255.255.0",
    )

    assert matcher.source_matches(
        first,
        second,
    )


def test_source_matches_rejects_different_networks():
    matcher = NATMatcher()

    first = make_nat(
        source="10.10.10.0/24",
    )

    second = make_nat(
        source="10.10.20.0/24",
    )

    assert not matcher.source_matches(
        first,
        second,
    )


# ============================================================================
# translated_source_matches
# ============================================================================

def test_translated_source_matches_normalizes_addresses():
    matcher = NATMatcher()

    first = make_nat(
        translated_source="203.0.113.10",
    )

    second = make_nat(
        translated_source="host:203.0.113.10",
    )

    assert matcher.translated_source_matches(
        first,
        second,
    )


def test_translated_source_matches_rejects_different_addresses():
    matcher = NATMatcher()

    first = make_nat(
        translated_source="203.0.113.10",
    )

    second = make_nat(
        translated_source="203.0.113.11",
    )

    assert not matcher.translated_source_matches(
        first,
        second,
    )


# ============================================================================
# addresses_overlap
# ============================================================================

def test_addresses_overlap_detects_containing_network():
    matcher = NATMatcher()

    assert matcher.addresses_overlap(
        "10.10.10.0/24",
        "10.10.10.10",
    )


def test_addresses_overlap_detects_partial_network_overlap():
    matcher = NATMatcher()

    assert matcher.addresses_overlap(
        "10.10.10.0/24",
        "10.10.10.128/25",
    )


def test_addresses_overlap_rejects_disjoint_networks():
    matcher = NATMatcher()

    assert not matcher.addresses_overlap(
        "10.10.10.0/24",
        "10.10.20.0/24",
    )


def test_addresses_overlap_rejects_ipv4_ipv6_mismatch():
    matcher = NATMatcher()

    assert not matcher.addresses_overlap(
        "10.10.10.10",
        "2001:db8::1",
    )


def test_addresses_overlap_rejects_invalid_values():
    matcher = NATMatcher()

    assert not matcher.addresses_overlap(
        "not-an-ip",
        "10.10.10.10",
    )


def test_addresses_overlap_rejects_any():
    matcher = NATMatcher()

    assert not matcher.addresses_overlap(
        "any",
        "10.10.10.10",
    )


# ============================================================================
# Internal parsing behavior
# ============================================================================

def test_parse_network_parses_bare_ip_as_host():
    matcher = NATMatcher()

    network = matcher._parse_network(
        "10.10.10.10"
    )

    assert network is not None
    assert str(network) == "10.10.10.10/32"


def test_parse_network_parses_host_prefix():
    matcher = NATMatcher()

    network = matcher._parse_network(
        "host:10.10.10.10"
    )

    assert network is not None
    assert str(network) == "10.10.10.10/32"


def test_parse_network_parses_cidr():
    matcher = NATMatcher()

    network = matcher._parse_network(
        "10.10.10.0/24"
    )

    assert network is not None
    assert str(network) == "10.10.10.0/24"


def test_parse_network_parses_netmask():
    matcher = NATMatcher()

    network = matcher._parse_network(
        "10.10.10.0 255.255.255.0"
    )

    assert network is not None
    assert str(network) == "10.10.10.0/24"


def test_parse_network_returns_none_for_any():
    matcher = NATMatcher()

    assert matcher._parse_network("any") is None


def test_parse_network_returns_none_for_empty_value():
    matcher = NATMatcher()

    assert matcher._parse_network("") is None
    assert matcher._parse_network(None) is None


def test_parse_network_parses_ipv6():
    matcher = NATMatcher()

    network = matcher._parse_network(
        "2001:db8::1"
    )

    assert network is not None
    assert str(network) == "2001:db8::1/128"

# ============================================================================
# NAT overlap
# ============================================================================

def test_nat_rules_overlap_when_sources_overlap():
    matcher = NATMatcher()

    first = make_nat(
        source="10.10.10.0/24",
        translated_source="203.0.113.0/24",
    )

    second = make_nat(
        source="10.10.10.128/25",
        translated_source="203.0.113.128/25",
    )

    assert matcher.rules_overlap(
        first,
        second,
    )


def test_nat_rules_overlap_when_destinations_overlap():
    matcher = NATMatcher()

    first = make_nat(
        source="10.10.10.0/24",
        translated_source="203.0.113.10",
        destination="10.20.20.0/24",
    )

    second = make_nat(
        source="10.10.10.0/24",
        translated_source="203.0.113.20",
        destination="10.20.20.128/25",
    )

    assert matcher.rules_overlap(
        first,
        second,
    )


def test_nat_rules_overlap_when_translated_destinations_overlap():
    matcher = NATMatcher()

    first = make_nat(
        translated_source="203.0.113.10",
        translated_destination="198.51.100.0/24",
    )

    second = make_nat(
        translated_source="203.0.113.20",
        translated_destination="198.51.100.128/25",
    )

    assert matcher.rules_overlap(
        first,
        second,
    )


def test_nat_rules_do_not_overlap_when_sources_are_disjoint():
    matcher = NATMatcher()

    first = make_nat(
        source="10.10.10.0/24",
    )

    second = make_nat(
        source="10.10.20.0/24",
    )

    assert not matcher.rules_overlap(
        first,
        second,
    )


def test_nat_rules_do_not_overlap_when_destinations_are_disjoint():
    matcher = NATMatcher()

    first = make_nat(
        destination="10.20.20.0/24",
    )

    second = make_nat(
        destination="10.30.30.0/24",
    )

    assert not matcher.rules_overlap(
        first,
        second,
    )


def test_nat_rules_do_not_overlap_when_protocols_differ():
    matcher = NATMatcher()

    first = make_nat(
        protocol="tcp",
    )

    second = make_nat(
        protocol="udp",
    )

    assert not matcher.rules_overlap(
        first,
        second,
    )


def test_nat_rules_overlap_when_protocol_is_ip():
    matcher = NATMatcher()

    first = make_nat(
        protocol="ip",
    )

    second = make_nat(
        protocol="tcp",
    )

    assert matcher.rules_overlap(
        first,
        second,
    )


def test_nat_rules_do_not_overlap_when_source_ports_differ():
    matcher = NATMatcher()

    first = make_nat(
        source_port=443,
    )

    second = make_nat(
        source_port=80,
    )

    assert not matcher.rules_overlap(
        first,
        second,
    )


def test_nat_rules_do_not_overlap_when_destination_ports_differ():
    matcher = NATMatcher()

    first = make_nat(
        destination_port=443,
    )

    second = make_nat(
        destination_port=80,
    )

    assert not matcher.rules_overlap(
        first,
        second,
    )


def test_nat_rules_overlap_when_ports_are_equal():
    matcher = NATMatcher()

    first = make_nat(
        source_port=443,
        destination_port=8443,
    )

    second = make_nat(
        source_port=443,
        destination_port=8443,
    )

    assert matcher.rules_overlap(
        first,
        second,
    )


def test_nat_rules_overlap_when_one_destination_is_any():
    matcher = NATMatcher()

    first = make_nat(
        destination="any",
    )

    second = make_nat(
        destination="10.20.20.0/24",
    )

    assert matcher.rules_overlap(
        first,
        second,
    )


def test_nat_rules_overlap_when_one_translated_destination_is_any():
    matcher = NATMatcher()

    first = make_nat(
        translated_destination="any",
    )

    second = make_nat(
        translated_destination="198.51.100.0/24",
    )

    assert matcher.rules_overlap(
        first,
        second,
    )


def test_nat_rules_overlap_when_source_is_exact_host():
    matcher = NATMatcher()

    first = make_nat(
        source="10.10.10.10",
    )

    second = make_nat(
        source="10.10.10.0/24",
    )

    assert matcher.rules_overlap(
        first,
        second,
    )


def test_nat_rules_do_not_overlap_when_ipv4_and_ipv6_differ():
    matcher = NATMatcher()

    first = make_nat(
        source="10.10.10.10",
    )

    second = make_nat(
        source="2001:db8::10",
    )

    assert not matcher.rules_overlap(
        first,
        second,
    )


def test_nat_rules_do_not_overlap_when_source_value_is_invalid():
    matcher = NATMatcher()

    first = make_nat(
        source="object-group:internal-networks",
    )

    second = make_nat(
        source="10.10.10.0/24",
    )

    assert not matcher.rules_overlap(
        first,
        second,
    )