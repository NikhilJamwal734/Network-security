"""
API-003 tests for firewall configuration serialization.
"""

import json

from fastapi.testclient import TestClient

from app.api.main import app
from app.api.serializers import (
    serialize_firewall,
    to_json_compatible,
)
from app.models.firewall import FirewallConfig


client = TestClient(app)


def upload_config(content: str):
    return client.post(
        "/api/v1/analyze",
        files={
            "file": (
                "firewall.conf",
                content.encode("utf-8"),
                "text/plain",
            )
        },
    )


def test_configuration_field_exists():
    response = upload_config(
        "hostname TEST-ASA\n"
    )

    assert response.status_code == 200
    assert "configuration" in response.json()


def test_configuration_contains_all_sections():
    response = upload_config(
        "hostname TEST-ASA\n"
    )

    assert response.status_code == 200

    configuration = response.json()["configuration"]

    assert set(configuration) == {
        "interfaces",
        "network_objects",
        "service_objects",
        "rules",
        "nat_rules",
        "routes",
    }


def test_empty_configuration_sections():
    response = upload_config(
        "hostname TEST-ASA\n"
    )

    assert response.status_code == 200

    configuration = response.json()["configuration"]

    for section in configuration.values():
        assert section == []


def test_firewall_rules_are_serialized():
    response = upload_config(
        "hostname TEST-ASA\n"
        "access-list OUTSIDE extended permit ip any any\n"
    )

    assert response.status_code == 200

    rules = response.json()["configuration"]["rules"]

    assert len(rules) == 1
    assert rules[0]["action"] == "permit"
    assert rules[0]["protocol"] == "ip"
    assert rules[0]["source"] == ["any"]
    assert rules[0]["destination"] == ["any"]


def test_rule_line_number_is_preserved():
    response = upload_config(
        "hostname TEST-ASA\n"
        "access-list OUTSIDE extended deny ip any any\n"
    )

    assert response.status_code == 200

    rule = response.json()["configuration"]["rules"][0]

    assert rule["line_number"] == 2


def test_network_objects_are_serialized():
    response = upload_config(
        "hostname TEST-ASA\n"
        "object network WEB_SERVER\n"
        " host 10.10.10.10\n"
    )

    assert response.status_code == 200

    objects = response.json()["configuration"]["network_objects"]

    assert len(objects) == 1
    assert objects[0]["name"] == "WEB_SERVER"


def test_service_objects_are_serialized():
    response = upload_config(
        "hostname TEST-ASA\n"
        "object service HTTPS_SERVICE\n"
        " service tcp destination eq 443\n"
    )

    assert response.status_code == 200

    services = response.json()["configuration"]["service_objects"]

    assert len(services) == 1
    assert services[0]["name"] == "HTTPS_SERVICE"
    assert services[0]["protocol"] == "tcp"


def test_interfaces_are_serialized():
    response = upload_config(
        "hostname TEST-ASA\n"
        "interface GigabitEthernet0/0\n"
        " nameif outside\n"
    )

    assert response.status_code == 200

    interfaces = response.json()["configuration"]["interfaces"]

    assert len(interfaces) == 1
    assert interfaces[0]["name"] == "GigabitEthernet0/0"
    assert interfaces[0]["security_zone"] == "outside"


def test_routes_are_serialized():
    response = upload_config(
        "hostname TEST-ASA\n"
        "route outside 10.10.0.0 255.255.0.0 192.0.2.1 1\n"
    )

    assert response.status_code == 200

    routes = response.json()["configuration"]["routes"]

    assert len(routes) == 1
    assert routes[0]["destination"] == "10.10.0.0/16"
    assert routes[0]["next_hop"] == "192.0.2.1"


def test_nat_rules_are_serialized():
    response = upload_config(
        "hostname TEST-ASA\n"
        "object network WEB_SERVER\n"
        " host 10.10.10.10\n"
        " nat (inside,outside) static 203.0.113.10\n"
    )

    assert response.status_code == 200

    nat_rules = response.json()["configuration"]["nat_rules"]

    assert len(nat_rules) == 1
    assert nat_rules[0]["translated_source"] == "203.0.113.10"


def test_response_remains_backward_compatible():
    response = upload_config(
        "hostname TEST-ASA\n"
    )

    assert response.status_code == 200

    data = response.json()

    for key in (
        "vendor",
        "hostname",
        "summary",
        "findings",
        "warnings",
    ):
        assert key in data


def test_configuration_is_json_serializable():
    firewall = FirewallConfig(vendor="Cisco ASA")

    configuration = serialize_firewall(firewall)

    json.dumps(configuration)


def test_serializer_converts_ip_networks():
    from ipaddress import ip_network

    result = to_json_compatible(
        {"networks": [ip_network("10.10.10.0/24")]}
    )

    assert result == {
        "networks": ["10.10.10.0/24"]
    }


def test_serializer_rejects_unsupported_values():
    class Unsupported:
        pass

    try:
        to_json_compatible(Unsupported())
    except TypeError:
        pass
    else:
        raise AssertionError("Expected TypeError")


def test_configuration_counts_match_summary():
    response = upload_config(
        "hostname TEST-ASA\n"
        "access-list OUTSIDE extended permit ip any any\n"
        "route outside 10.10.0.0 255.255.0.0 192.0.2.1 1\n"
    )

    assert response.status_code == 200

    data = response.json()
    configuration = data["configuration"]
    summary = data["summary"]

    assert len(configuration["rules"]) == summary["total_rules"]
    assert len(configuration["routes"]) == summary["total_routes"]