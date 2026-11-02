from ipaddress import ip_network

import pytest

from app.analyzer.object_resolver import NetworkObjectResolver
from app.models.firewall import FirewallConfig
from app.models.network import NetworkObject


def create_firewall():
    return FirewallConfig(
        vendor="Cisco ASA",
        hostname="TEST-FIREWALL",
    )


def test_resolve_ipv4_host():
    firewall = create_firewall()

    resolver = NetworkObjectResolver(
        firewall
    )

    result = resolver.resolve(
        "10.10.10.10"
    )

    assert result == [
        ip_network("10.10.10.10/32")
    ]


def test_resolve_host_prefix():
    firewall = create_firewall()

    resolver = NetworkObjectResolver(
        firewall
    )

    result = resolver.resolve(
        "host:10.10.10.10"
    )

    assert result == [
        ip_network("10.10.10.10/32")
    ]


def test_resolve_cidr_network():
    firewall = create_firewall()

    resolver = NetworkObjectResolver(
        firewall
    )

    result = resolver.resolve(
        "10.10.0.0/16"
    )

    assert result == [
        ip_network("10.10.0.0/16")
    ]


def test_resolve_network_and_netmask():
    firewall = create_firewall()

    resolver = NetworkObjectResolver(
        firewall
    )

    result = resolver.resolve(
        "10.10.0.0 255.255.0.0"
    )

    assert result == [
        ip_network("10.10.0.0/16")
    ]


def test_resolve_any_returns_empty_list():
    firewall = create_firewall()

    resolver = NetworkObjectResolver(
        firewall
    )

    result = resolver.resolve(
        "any"
    )

    assert result == []


def test_resolve_network_object():
    firewall = create_firewall()

    firewall.add_network(
        NetworkObject(
            name="WEB01",
            networks=[
                ip_network("10.10.10.10/32")
            ],
        )
    )

    resolver = NetworkObjectResolver(
        firewall
    )

    result = resolver.resolve(
        "object:WEB01"
    )

    assert result == [
        ip_network("10.10.10.10/32")
    ]


def test_resolve_network_object_case_insensitive():
    firewall = create_firewall()

    firewall.add_network(
        NetworkObject(
            name="WEB01",
            networks=[
                ip_network("10.10.10.10/32")
            ],
        )
    )

    resolver = NetworkObjectResolver(
        firewall
    )

    result = resolver.resolve(
        "object:web01"
    )

    assert result == [
        ip_network("10.10.10.10/32")
    ]


def test_resolve_object_group():
    firewall = create_firewall()

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

    result = resolver.resolve(
        "object-group:WEB_SERVERS"
    )

    assert set(result) == {
        ip_network("10.10.10.10/32"),
        ip_network("10.10.10.11/32"),
    }


def test_resolve_nested_object_group():
    firewall = create_firewall()

    firewall.add_network(
        NetworkObject(
            name="WEB_SERVERS",
            networks=[
                ip_network("10.10.10.10/32"),
                ip_network("10.10.10.11/32"),
            ],
        )
    )

    firewall.add_network(
        NetworkObject(
            name="ALL_WEB_SERVERS",
            networks=[
                ip_network("10.10.30.10/32")
            ],
            group_references=[
                "WEB_SERVERS"
            ],
        )
    )

    resolver = NetworkObjectResolver(
        firewall
    )

    result = resolver.resolve(
        "object-group:ALL_WEB_SERVERS"
    )

    assert set(result) == {
        ip_network("10.10.30.10/32"),
        ip_network("10.10.10.10/32"),
        ip_network("10.10.10.11/32"),
    }


def test_resolve_list():
    firewall = create_firewall()

    resolver = NetworkObjectResolver(
        firewall
    )

    result = resolver.resolve_list(
        [
            "10.10.10.10",
            "10.10.10.0/24",
        ]
    )

    assert set(result) == {
        ip_network("10.10.10.10/32"),
        ip_network("10.10.10.0/24"),
    }


def test_resolve_list_removes_duplicates():
    firewall = create_firewall()

    resolver = NetworkObjectResolver(
        firewall
    )

    result = resolver.resolve_list(
        [
            "10.10.10.10",
            "host:10.10.10.10",
        ]
    )

    assert result == [
        ip_network("10.10.10.10/32")
    ]


def test_is_any_detects_any():
    firewall = create_firewall()

    resolver = NetworkObjectResolver(
        firewall
    )

    assert resolver.is_any(
        ["any"]
    )


def test_is_any_is_case_insensitive():
    firewall = create_firewall()

    resolver = NetworkObjectResolver(
        firewall
    )

    assert resolver.is_any(
        ["ANY"]
    )


def test_is_any_returns_false_for_network():
    firewall = create_firewall()

    resolver = NetworkObjectResolver(
        firewall
    )

    assert not resolver.is_any(
        ["10.10.10.0/24"]
    )


def test_undefined_object_raises_error():
    firewall = create_firewall()

    resolver = NetworkObjectResolver(
        firewall
    )

    with pytest.raises(
        ValueError,
        match="Undefined network object",
    ):
        resolver.resolve(
            "object:MISSING_OBJECT"
        )


def test_undefined_object_group_raises_error():
    firewall = create_firewall()

    resolver = NetworkObjectResolver(
        firewall
    )

    with pytest.raises(
        ValueError,
        match="Undefined network object-group",
    ):
        resolver.resolve(
            "object-group:MISSING_GROUP"
        )


def test_circular_object_group_reference_raises_error():
    firewall = create_firewall()

    firewall.add_network(
        NetworkObject(
            name="GROUP_A",
            group_references=[
                "GROUP_B"
            ],
        )
    )

    firewall.add_network(
        NetworkObject(
            name="GROUP_B",
            group_references=[
                "GROUP_A"
            ],
        )
    )

    resolver = NetworkObjectResolver(
        firewall
    )

    with pytest.raises(
        ValueError,
        match="Circular object-group reference",
    ):
        resolver.resolve(
            "object-group:GROUP_A"
        )


def test_invalid_network_returns_empty_list():
    firewall = create_firewall()

    resolver = NetworkObjectResolver(
        firewall
    )

    result = resolver.resolve(
        "not-an-ip-address"
    )

    assert result == []