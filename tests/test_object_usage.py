from ipaddress import ip_network

from app.analyzer.object_usage import ObjectUsageAnalyzer
from app.models.firewall import FirewallConfig, NATRule
from app.models.network import NetworkObject
from app.models.rule import FirewallRule
from app.models.service import Service


def make_firewall():
    return FirewallConfig(
        vendor="test"
    )


def make_rule(
    rule_id=1,
    source=None,
    destination=None,
    source_services=None,
    destination_services=None,
    disabled=False,
):
    return FirewallRule(
        id=rule_id,
        line_number=rule_id,
        name="TEST_ACL",
        action="permit",
        protocol="tcp",
        source=source or [],
        destination=destination or [],
        source_services=source_services or [],
        destination_services=destination_services or [],
        disabled=disabled,
    )


# ================================================================
# Direct network-object usage
# ================================================================


def test_direct_network_object_used_by_acl():
    firewall = make_firewall()

    firewall.add_network(
        NetworkObject(
            name="WEB01",
            networks=[
                ip_network("10.10.10.10/32")
            ],
        )
    )

    firewall.add_rule(
        make_rule(
            source=["object:WEB01"]
        )
    )

    analyzer = ObjectUsageAnalyzer(firewall)

    used = analyzer.used_network_objects()

    assert used == {"web01"}


def test_direct_network_object_without_object_prefix():
    firewall = make_firewall()

    firewall.add_network(
        NetworkObject(
            name="WEB01",
            networks=[
                ip_network("10.10.10.10/32")
            ],
        )
    )

    firewall.add_rule(
        make_rule(
            source=["WEB01"]
        )
    )

    analyzer = ObjectUsageAnalyzer(firewall)

    used = analyzer.used_network_objects()

    assert used == {"web01"}


def test_unused_network_object_is_not_reported_as_used():
    firewall = make_firewall()

    firewall.add_network(
        NetworkObject(
            name="WEB01",
            networks=[
                ip_network("10.10.10.10/32")
            ],
        )
    )

    firewall.add_network(
        NetworkObject(
            name="DB01",
            networks=[
                ip_network("10.10.20.10/32")
            ],
        )
    )

    firewall.add_rule(
        make_rule(
            source=["object:WEB01"]
        )
    )

    analyzer = ObjectUsageAnalyzer(firewall)

    used = analyzer.used_network_objects()

    assert used == {"web01"}
    assert "db01" not in used


# ================================================================
# Object-group usage
# ================================================================


def test_object_group_marks_group_as_used():
    firewall = make_firewall()

    firewall.add_network(
        NetworkObject(
            name="WEB_SERVERS"
        )
    )

    firewall.add_rule(
        make_rule(
            source=["object-group:WEB_SERVERS"]
        )
    )

    analyzer = ObjectUsageAnalyzer(firewall)

    used = analyzer.used_network_objects()

    assert used == {"web_servers"}


def test_object_group_marks_members_as_used():
    firewall = make_firewall()

    firewall.add_network(
        NetworkObject(
            name="WEB01",
            networks=[
                ip_network("10.10.10.10/32")
            ],
        )
    )

    firewall.add_network(
        NetworkObject(
            name="WEB_SERVERS",
            group_references=[
                "WEB01"
            ],
        )
    )

    firewall.add_rule(
        make_rule(
            source=["object-group:WEB_SERVERS"]
        )
    )

    analyzer = ObjectUsageAnalyzer(firewall)

    used = analyzer.used_network_objects()

    assert used == {
        "web_servers",
        "web01",
    }


def test_nested_object_groups_are_traversed():
    firewall = make_firewall()

    firewall.add_network(
        NetworkObject(
            name="WEB01",
            networks=[
                ip_network("10.10.10.10/32")
            ],
        )
    )

    firewall.add_network(
        NetworkObject(
            name="WEB_SERVERS",
            group_references=[
                "WEB01"
            ],
        )
    )

    firewall.add_network(
        NetworkObject(
            name="PRODUCTION",
            group_references=[
                "WEB_SERVERS"
            ],
        )
    )

    firewall.add_rule(
        make_rule(
            source=["object-group:PRODUCTION"]
        )
    )

    analyzer = ObjectUsageAnalyzer(firewall)

    used = analyzer.used_network_objects()

    assert used == {
        "production",
        "web_servers",
        "web01",
    }


def test_deeply_nested_object_groups_are_traversed():
    firewall = make_firewall()

    firewall.add_network(
        NetworkObject(
            name="HOST01",
            networks=[
                ip_network("10.10.10.10/32")
            ],
        )
    )

    firewall.add_network(
        NetworkObject(
            name="GROUP_A",
            group_references=[
                "HOST01"
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

    firewall.add_network(
        NetworkObject(
            name="GROUP_C",
            group_references=[
                "GROUP_B"
            ],
        )
    )

    firewall.add_network(
        NetworkObject(
            name="GROUP_D",
            group_references=[
                "GROUP_C"
            ],
        )
    )

    firewall.add_rule(
        make_rule(
            source=["object-group:GROUP_D"]
        )
    )

    analyzer = ObjectUsageAnalyzer(firewall)

    used = analyzer.used_network_objects()

    assert used == {
        "group_d",
        "group_c",
        "group_b",
        "group_a",
        "host01",
    }


# ================================================================
# NAT usage
# ================================================================


def test_network_object_used_by_nat_source():
    firewall = make_firewall()

    firewall.add_network(
        NetworkObject(
            name="INTERNAL_SERVER",
            networks=[
                ip_network("10.10.10.10/32")
            ],
        )
    )

    firewall.add_nat_rule(
        NATRule(
            id=1,
            source="object:INTERNAL_SERVER",
            translated_source="203.0.113.10",
        )
    )

    analyzer = ObjectUsageAnalyzer(firewall)

    used = analyzer.used_network_objects()

    assert used == {
        "internal_server"
    }


def test_network_object_used_by_nat_destination():
    firewall = make_firewall()

    firewall.add_network(
        NetworkObject(
            name="PUBLIC_SERVER",
            networks=[
                ip_network("203.0.113.10/32")
            ],
        )
    )

    firewall.add_nat_rule(
        NATRule(
            id=1,
            source="any",
            translated_source="203.0.113.10",
            destination="object:PUBLIC_SERVER",
        )
    )

    analyzer = ObjectUsageAnalyzer(firewall)

    used = analyzer.used_network_objects()

    assert used == {
        "public_server"
    }


def test_network_object_group_used_by_nat():
    firewall = make_firewall()

    firewall.add_network(
        NetworkObject(
            name="SERVER01",
            networks=[
                ip_network("10.10.10.10/32")
            ],
        )
    )

    firewall.add_network(
        NetworkObject(
            name="SERVERS",
            group_references=[
                "SERVER01"
            ],
        )
    )

    firewall.add_nat_rule(
        NATRule(
            id=1,
            source="object-group:SERVERS",
            translated_source="interface:outside",
        )
    )

    analyzer = ObjectUsageAnalyzer(firewall)

    used = analyzer.used_network_objects()

    assert used == {
        "servers",
        "server01",
    }


# ================================================================
# Case-insensitive references
# ================================================================


def test_network_object_reference_is_case_insensitive():
    firewall = make_firewall()

    firewall.add_network(
        NetworkObject(
            name="Web_Server",
            networks=[
                ip_network("10.10.10.10/32")
            ],
        )
    )

    firewall.add_rule(
        make_rule(
            source=["OBJECT:web_server"]
        )
    )

    analyzer = ObjectUsageAnalyzer(firewall)

    used = analyzer.used_network_objects()

    assert used == {
        "web_server"
    }


def test_object_group_reference_is_case_insensitive():
    firewall = make_firewall()

    firewall.add_network(
        NetworkObject(
            name="WEB01",
            networks=[
                ip_network("10.10.10.10/32")
            ],
        )
    )

    firewall.add_network(
        NetworkObject(
            name="WEB_SERVERS",
            group_references=[
                "web01"
            ],
        )
    )

    firewall.add_rule(
        make_rule(
            source=["OBJECT-GROUP:web_servers"]
        )
    )

    analyzer = ObjectUsageAnalyzer(firewall)

    used = analyzer.used_network_objects()

    assert used == {
        "web_servers",
        "web01",
    }


# ================================================================
# Circular dependencies
# ================================================================


def test_circular_object_groups_do_not_loop_forever():
    firewall = make_firewall()

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

    firewall.add_rule(
        make_rule(
            source=["object-group:GROUP_A"]
        )
    )

    analyzer = ObjectUsageAnalyzer(firewall)

    used = analyzer.used_network_objects()

    assert used == {
        "group_a",
        "group_b",
    }


# ================================================================
# Undefined references
# ================================================================


def test_undefined_network_object_is_ignored():
    firewall = make_firewall()

    firewall.add_rule(
        make_rule(
            source=["object:DOES_NOT_EXIST"]
        )
    )

    analyzer = ObjectUsageAnalyzer(firewall)

    used = analyzer.used_network_objects()

    assert used == set()


def test_undefined_object_group_is_ignored():
    firewall = make_firewall()

    firewall.add_rule(
        make_rule(
            source=["object-group:DOES_NOT_EXIST"]
        )
    )

    analyzer = ObjectUsageAnalyzer(firewall)

    used = analyzer.used_network_objects()

    assert used == set()


# ================================================================
# Literal addresses
# ================================================================


def test_literal_ip_address_is_not_treated_as_object():
    firewall = make_firewall()

    firewall.add_network(
        NetworkObject(
            name="WEB01",
            networks=[
                ip_network("10.10.10.10/32")
            ],
        )
    )

    firewall.add_rule(
        make_rule(
            source=["10.10.10.10"]
        )
    )

    analyzer = ObjectUsageAnalyzer(firewall)

    used = analyzer.used_network_objects()

    assert used == set()


def test_cidr_is_not_treated_as_object():
    firewall = make_firewall()

    firewall.add_network(
        NetworkObject(
            name="WEB01",
            networks=[
                ip_network("10.10.10.10/32")
            ],
        )
    )

    firewall.add_rule(
        make_rule(
            source=["10.10.10.0/24"]
        )
    )

    analyzer = ObjectUsageAnalyzer(firewall)

    used = analyzer.used_network_objects()

    assert used == set()


def test_any_is_not_treated_as_object():
    firewall = make_firewall()

    firewall.add_rule(
        make_rule(
            source=["any"],
            destination=["any"],
        )
    )

    analyzer = ObjectUsageAnalyzer(firewall)

    used = analyzer.used_network_objects()

    assert used == set()


# ================================================================
# Disabled rules
# ================================================================


def test_disabled_rule_does_not_mark_network_object_as_used():
    firewall = make_firewall()

    firewall.add_network(
        NetworkObject(
            name="WEB01",
            networks=[
                ip_network("10.10.10.10/32")
            ],
        )
    )

    firewall.add_rule(
        make_rule(
            source=["object:WEB01"],
            disabled=True,
        )
    )

    analyzer = ObjectUsageAnalyzer(firewall)

    used = analyzer.used_network_objects()

    assert used == set()


# ================================================================
# Service objects
# ================================================================


def test_direct_service_object_is_used():
    firewall = make_firewall()

    firewall.add_service(
        Service(
            name="HTTPS",
            protocol="tcp",
            ports=[443],
        )
    )

    firewall.add_rule(
        make_rule(
            destination_services=["HTTPS"]
        )
    )

    analyzer = ObjectUsageAnalyzer(firewall)

    used = analyzer.used_service_objects()

    assert used == {
        "https"
    }


def test_service_object_reference_is_case_insensitive():
    firewall = make_firewall()

    firewall.add_service(
        Service(
            name="HTTPS",
            protocol="tcp",
            ports=[443],
        )
    )

    firewall.add_rule(
        make_rule(
            destination_services=["https"]
        )
    )

    analyzer = ObjectUsageAnalyzer(firewall)

    used = analyzer.used_service_objects()

    assert used == {
        "https"
    }


def test_unused_service_object_is_not_marked_as_used():
    firewall = make_firewall()

    firewall.add_service(
        Service(
            name="HTTPS",
            protocol="tcp",
            ports=[443],
        )
    )

    firewall.add_service(
        Service(
            name="SSH",
            protocol="tcp",
            ports=[22],
        )
    )

    firewall.add_rule(
        make_rule(
            destination_services=["HTTPS"]
        )
    )

    analyzer = ObjectUsageAnalyzer(firewall)

    used = analyzer.used_service_objects()

    assert used == {
        "https"
    }

    assert "ssh" not in used


def test_disabled_rule_does_not_mark_service_object_as_used():
    firewall = make_firewall()

    firewall.add_service(
        Service(
            name="HTTPS",
            protocol="tcp",
            ports=[443],
        )
    )

    firewall.add_rule(
        make_rule(
            destination_services=["HTTPS"],
            disabled=True,
        )
    )

    analyzer = ObjectUsageAnalyzer(firewall)

    used = analyzer.used_service_objects()

    assert used == set()


# ================================================================
# Network usage graph
# ================================================================


def test_network_usage_graph():
    firewall = make_firewall()

    firewall.add_network(
        NetworkObject(
            name="WEB01"
        )
    )

    firewall.add_network(
        NetworkObject(
            name="WEB_SERVERS",
            group_references=[
                "WEB01"
            ],
        )
    )

    firewall.add_network(
        NetworkObject(
            name="PRODUCTION",
            group_references=[
                "WEB_SERVERS"
            ],
        )
    )

    analyzer = ObjectUsageAnalyzer(firewall)

    graph = analyzer.network_usage_graph()

    assert graph == {
        "web01": set(),
        "web_servers": {
            "web01"
        },
        "production": {
            "web_servers"
        },
    }


def test_network_usage_graph_ignores_undefined_references():
    firewall = make_firewall()

    firewall.add_network(
        NetworkObject(
            name="WEB_SERVERS",
            group_references=[
                "DOES_NOT_EXIST"
            ],
        )
    )

    analyzer = ObjectUsageAnalyzer(firewall)

    graph = analyzer.network_usage_graph()

    assert graph == {
        "web_servers": set()
    }