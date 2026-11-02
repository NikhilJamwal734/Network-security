from app.analyzer.route_matcher import RouteMatcher
from app.models.firewall import Route


def make_route(
    destination,
    next_hop="10.0.0.1",
    interface="inside",
    metric=None,
):
    return Route(
        destination=destination,
        next_hop=next_hop,
        interface=interface,
        metric=metric,
    )


def test_parse_cidr_network():
    network = RouteMatcher.parse_network(
        "10.10.10.0/24"
    )

    assert network is not None
    assert str(network) == "10.10.10.0/24"


def test_parse_ip_and_netmask():
    network = RouteMatcher.parse_network(
        "10.10.10.0 255.255.255.0"
    )

    assert network is not None
    assert str(network) == "10.10.10.0/24"


def test_destinations_equal():
    assert RouteMatcher.destinations_equal(
        "10.10.10.0/24",
        "10.10.10.0 255.255.255.0",
    )


def test_destinations_not_equal():
    assert not RouteMatcher.destinations_equal(
        "10.10.10.0/24",
        "10.10.20.0/24",
    )


def test_destinations_overlap():
    assert RouteMatcher.destinations_overlap(
        "10.10.0.0/16",
        "10.10.10.0/24",
    )


def test_disjoint_destinations_do_not_overlap():
    assert not RouteMatcher.destinations_overlap(
        "10.10.0.0/16",
        "10.20.0.0/16",
    )


def test_more_specific_route():
    assert RouteMatcher.is_more_specific(
        "10.10.10.0/24",
        "10.10.0.0/16",
    )


def test_less_specific_route_is_not_more_specific():
    assert not RouteMatcher.is_more_specific(
        "10.10.0.0/16",
        "10.10.10.0/24",
    )


def test_default_route():
    assert RouteMatcher.is_default_route(
        "0.0.0.0/0"
    )


def test_non_default_route():
    assert not RouteMatcher.is_default_route(
        "10.10.0.0/16"
    )


def test_duplicate_routes():
    first = make_route(
        "10.10.10.0/24",
        next_hop="10.0.0.1",
        interface="inside",
    )

    second = make_route(
        "10.10.10.0/24",
        next_hop="10.0.0.1",
        interface="inside",
    )

    assert RouteMatcher.routes_are_duplicates(
        first,
        second,
    )


def test_different_next_hop_not_duplicate():
    first = make_route(
        "10.10.10.0/24",
        next_hop="10.0.0.1",
        interface="inside",
    )

    second = make_route(
        "10.10.10.0/24",
        next_hop="10.0.0.2",
        interface="inside",
    )

    assert not RouteMatcher.routes_are_duplicates(
        first,
        second,
    )


def test_different_interface_not_duplicate():
    first = make_route(
        "10.10.10.0/24",
        next_hop="10.0.0.1",
        interface="inside",
    )

    second = make_route(
        "10.10.10.0/24",
        next_hop="10.0.0.1",
        interface="outside",
    )

    assert not RouteMatcher.routes_are_duplicates(
        first,
        second,
    )


def test_same_destination():
    first = make_route(
        "10.10.10.0/24",
    )

    second = make_route(
        "10.10.10.0 255.255.255.0",
    )

    assert RouteMatcher.routes_have_same_destination(
        first,
        second,
    )


def test_invalid_destination_returns_false():
    assert not RouteMatcher.destinations_equal(
        "invalid",
        "10.10.10.0/24",
    )


def test_ipv4_and_ipv6_do_not_overlap():
    assert not RouteMatcher.destinations_overlap(
        "10.10.0.0/16",
        "2001:db8::/32",
    )