"""
API-003: Firewall configuration serialization.

Converts parsed firewall models into JSON-compatible data
for the React frontend.
"""

from dataclasses import asdict, is_dataclass
from ipaddress import (
    IPv4Address,
    IPv4Network,
    IPv6Address,
    IPv6Network,
)
from typing import Any

from app.models.firewall import FirewallConfig


IP_TYPES = (
    IPv4Address,
    IPv4Network,
    IPv6Address,
    IPv6Network,
)


def to_json_compatible(value: Any) -> Any:
    """
    Recursively convert model values into JSON-compatible data.

    Supports:
        - Dataclasses
        - IP addresses and networks
        - Dictionaries
        - Lists and tuples
        - Sets
        - Primitive values
    """

    if isinstance(value, IP_TYPES):
        return str(value)

    if is_dataclass(value) and not isinstance(value, type):
        return to_json_compatible(asdict(value))

    if isinstance(value, dict):
        return {
            str(key): to_json_compatible(item)
            for key, item in value.items()
        }

    if isinstance(value, (list, tuple)):
        return [
            to_json_compatible(item)
            for item in value
        ]

    if isinstance(value, (set, frozenset)):
        converted = [
            to_json_compatible(item)
            for item in value
        ]
        return sorted(converted, key=str)

    if value is None or isinstance(
        value, (str, int, float, bool)
    ):
        return value

    raise TypeError(
        f"Unsupported configuration value: {type(value).__name__}"
    )


def serialize_firewall(
    firewall: FirewallConfig,
) -> dict:
    """
    Serialize the parsed firewall configuration.

    Collections are returned as arrays so the React frontend
    can display them directly in tables.
    """

    return {
        "interfaces": [
            to_json_compatible(interface)
            for interface in firewall.interfaces.values()
        ],
        "network_objects": [
            to_json_compatible(network)
            for network in firewall.networks.values()
        ],
        "service_objects": [
            to_json_compatible(service)
            for service in firewall.services.values()
        ],
        "rules": [
            to_json_compatible(rule)
            for rule in firewall.rules
        ],
        "nat_rules": [
            to_json_compatible(nat_rule)
            for nat_rule in firewall.nat_rules
        ],
        "routes": [
            to_json_compatible(route)
            for route in firewall.routes
        ],
    }