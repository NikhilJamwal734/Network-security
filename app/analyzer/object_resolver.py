from ipaddress import ip_network
from typing import List, Set

from app.models.firewall import FirewallConfig
from app.models.network import IPNetwork


class NetworkObjectResolver:
    """
    Resolves firewall address values into normalized IP networks.

    Supported values include:

        any
        host:10.10.10.10
        10.10.10.10
        10.10.10.0/24
        10.10.10.0 255.255.255.0
        object:WEB01
        object-group:WEB_SERVERS
    """

    def __init__(self, firewall: FirewallConfig):
        self.firewall = firewall

    def resolve(self, value: str) -> List[IPNetwork]:
        if value is None:
            return []

        value = value.strip()

        if not value:
            return []

        # "any" represents unrestricted addresses.
        # The caller handles "any" separately because it is not
        # itself a concrete network object.
        if value.lower() == "any":
            return []

        # Host notation:
        #
        #   host:10.10.10.10
        #
        # Normalize it to:
        #
        #   10.10.10.10/32
        if value.lower().startswith("host:"):
            address = value.split(":", 1)[1].strip()

            if not address:
                return []

            try:
                return [
                    ip_network(
                        f"{address}/32",
                        strict=False,
                    )
                ]
            except ValueError:
                return []

        # Network object reference:
        #
        #   object:WEB01
        #
        if value.lower().startswith("object:"):
            name = value.split(":", 1)[1].strip()

            if not name:
                return []

            return self._resolve_object(
                name,
                set(),
            )

        # Network object-group reference:
        #
        #   object-group:WEB_SERVERS
        #
        if value.lower().startswith("object-group:"):
            name = value.split(":", 1)[1].strip()

            if not name:
                return []

            return self._resolve_group(
                name,
                set(),
            )

        # Cisco ASA subnet notation:
        #
        #   10.10.0.0 255.255.0.0
        #
        parts = value.split()

        if len(parts) == 2:
            try:
                return [
                    ip_network(
                        f"{parts[0]}/{parts[1]}",
                        strict=False,
                    )
                ]
            except ValueError:
                return []

        # Normal CIDR or single IP address.
        #
        # Examples:
        #
        #   10.10.10.0/24
        #   10.10.10.10
        try:
            network = ip_network(
                value,
                strict=False,
            )

            return [network]

        except ValueError:
            return []

    def resolve_list(
        self,
        values: List[str],
    ) -> List[IPNetwork]:
        result: List[IPNetwork] = []

        for value in values:
            result.extend(
                self.resolve(value)
            )

        return self._remove_duplicates(result)

    def is_any(
        self,
        values: List[str],
    ) -> bool:
        return any(
            value.strip().lower() == "any"
            for value in values
            if value is not None
        )

    def _resolve_object(
        self,
        name: str,
        visited: Set[str],
    ) -> List[IPNetwork]:
        normalized_name = name.strip()

        lookup_name = normalized_name.lower()

        if lookup_name in visited:
            raise ValueError(
                "Circular network object reference: "
                f"{normalized_name}"
            )

        obj = self._find_network_object(
            normalized_name
        )

        if obj is None:
            raise ValueError(
                "Undefined network object: "
                f"{normalized_name}"
            )

        return list(obj.networks)

    def _resolve_group(
        self,
        name: str,
        visited: Set[str],
    ) -> List[IPNetwork]:
        normalized_name = name.strip()

        lookup_name = normalized_name.lower()

        if lookup_name in visited:
            raise ValueError(
                "Circular object-group reference: "
                f"{normalized_name}"
            )

        obj = self._find_network_object(
            normalized_name
        )

        if obj is None:
            raise ValueError(
                "Undefined network object-group: "
                f"{normalized_name}"
            )

        visited = set(visited)
        visited.add(lookup_name)

        result = list(obj.networks)

        group_references = getattr(
            obj,
            "group_references",
            [],
        )

        for group_name in group_references:
            result.extend(
                self._resolve_group(
                    group_name,
                    visited,
                )
            )

        return self._remove_duplicates(result)

    def _find_network_object(self, name: str):
        """
        Find a network object without depending on dictionary
        key capitalization.
        """

        # Fast path: exact match.
        obj = self.firewall.networks.get(name)

        if obj is not None:
            return obj

        # Case-insensitive fallback.
        target = name.lower()

        for object_name, network_object in self.firewall.networks.items():
            if object_name.lower() == target:
                return network_object

        return None

    @staticmethod
    def _remove_duplicates(
        networks: List[IPNetwork],
    ) -> List[IPNetwork]:
        result: List[IPNetwork] = []

        for network in networks:
            if network not in result:
                result.append(network)

        return result

