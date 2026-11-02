from ipaddress import ip_network

from app.analyzer.network_matcher import NetworkMatcher


def test_contains_smaller_network():
    broader = [
        ip_network("10.10.0.0/16")
    ]

    narrower = [
        ip_network("10.10.10.0/24")
    ]

    assert NetworkMatcher.contains(
        broader,
        narrower,
    )


def test_contains_host_inside_network():
    broader = [
        ip_network("10.10.10.0/24")
    ]

    narrower = [
        ip_network("10.10.10.10/32")
    ]

    assert NetworkMatcher.contains(
        broader,
        narrower,
    )


def test_does_not_contain_broader_network():
    broader = [
        ip_network("10.10.10.0/24")
    ]

    narrower = [
        ip_network("10.10.0.0/16")
    ]

    assert not NetworkMatcher.contains(
        broader,
        narrower,
    )


def test_equal_networks():
    first = [
        ip_network("10.10.10.0/24")
    ]

    second = [
        ip_network("10.10.10.0/24")
    ]

    assert NetworkMatcher.equal(
        first,
        second,
    )


def test_different_networks_are_not_equal():
    first = [
        ip_network("10.10.10.0/24")
    ]

    second = [
        ip_network("10.10.20.0/24")
    ]

    assert not NetworkMatcher.equal(
        first,
        second,
    )


def test_overlapping_networks():
    first = [
        ip_network("10.10.0.0/16")
    ]

    second = [
        ip_network("10.10.10.0/24")
    ]

    assert NetworkMatcher.overlaps(
        first,
        second,
    )


def test_non_overlapping_networks():
    first = [
        ip_network("10.10.0.0/16")
    ]

    second = [
        ip_network("10.20.0.0/16")
    ]

    assert not NetworkMatcher.overlaps(
        first,
        second,
    )


def test_any_ipv4_contains_ipv4_network():
    any_network = NetworkMatcher.resolve_any(
        [],
        any_value=True,
    )

    target = [
        ip_network("10.10.10.0/24")
    ]

    assert NetworkMatcher.contains(
        any_network,
        target,
    )


def test_any_ipv4_and_ipv6_are_returned():
    any_networks = NetworkMatcher.resolve_any(
        [],
        any_value=True,
    )

    assert ip_network(
        "0.0.0.0/0"
    ) in any_networks

    assert ip_network(
        "::/0"
    ) in any_networks


def test_ipv4_does_not_overlap_ipv6():
    first = [
        ip_network("10.10.10.0/24")
    ]

    second = [
        ip_network("2001:db8::/32")
    ]

    assert not NetworkMatcher.overlaps(
        first,
        second,
    )


def test_multiple_networks_are_supported():
    broader = [
        ip_network("10.10.10.0/24"),
        ip_network("10.20.10.0/24"),
    ]

    narrower = [
        ip_network("10.10.10.10/32"),
        ip_network("10.20.10.10/32"),
    ]

    assert NetworkMatcher.contains(
        broader,
        narrower,
    )


def test_partial_coverage_is_not_containment():
    broader = [
        ip_network("10.10.10.0/25")
    ]

    target = [
        ip_network("10.10.10.0/24")
    ]

    assert not NetworkMatcher.contains(
        broader,
        target,
    )