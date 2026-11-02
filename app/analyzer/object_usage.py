from typing import Dict, List, Set

from app.models.firewall import FirewallConfig


class ObjectUsageAnalyzer:
    """
    Analyze object dependencies and determine which configured
    network and service objects are actually used.

    Network dependencies may look like:

        ACL -> object
        ACL -> object-group -> object
        ACL -> object-group -> nested-object-group -> object
        NAT -> object
        NAT -> object-group

    Network object-groups are represented by
    NetworkObject.group_references.

    Object names are matched case-insensitively.
    """

    def __init__(
        self,
        firewall: FirewallConfig,
    ):
        self.firewall = firewall

        self._network_lookup = {
            name.strip().lower(): name
            for name in firewall.networks
        }

        self._service_lookup = {
            name.strip().lower(): name
            for name in firewall.services
        }

    # ================================================================
    # Public API
    # ================================================================

    def used_network_objects(self) -> Set[str]:
        """
        Return normalized names of all network objects that are
        reachable from an active configuration reference.

        This includes objects referenced:

            directly by ACLs
            indirectly through object-groups
            directly by NAT
            indirectly through NAT object-groups
            through nested object-groups
        """

        used: Set[str] = set()

        # ------------------------------------------------------------
        # ACL references
        # ------------------------------------------------------------

        for rule in self.firewall.rules:

            if rule.disabled:
                continue

            for value in (
                rule.source
                + rule.destination
            ):
                self._collect_network_reference(
                    value,
                    used,
                )

        # ------------------------------------------------------------
        # NAT references
        # ------------------------------------------------------------

        for nat_rule in self.firewall.nat_rules:

            for value in (
                nat_rule.source,
                nat_rule.destination,
                nat_rule.translated_source,
                nat_rule.translated_destination,
            ):
                self._collect_network_reference(
                    value,
                    used,
                )

        return used

    def used_service_objects(self) -> Set[str]:
        """
        Return normalized names of all service objects referenced
        by active firewall rules.

        Service groups are not currently represented by the model,
        so this method currently tracks direct service-object
        references.
        """

        used: Set[str] = set()

        for rule in self.firewall.rules:

            if rule.disabled:
                continue

            for service_name in (
                rule.source_services
                + rule.destination_services
            ):
                self._collect_service_reference(
                    service_name,
                    used,
                )

        return used

    def network_usage_graph(self) -> Dict[str, Set[str]]:
        """
        Return the network object dependency graph.

        Each key is a configured network object.

        The value contains the configured network objects directly
        referenced by that object's group_references.

        Example:

            GROUP_A -> {"GROUP_B", "OBJECT_A"}
            GROUP_B -> {"OBJECT_A"}
            OBJECT_A -> set()
        """

        graph: Dict[str, Set[str]] = {}

        for object_name, network_object in (
            self.firewall.networks.items()
        ):

            normalized_name = (
                object_name.strip().lower()
            )

            dependencies: Set[str] = set()

            for reference in getattr(
                network_object,
                "group_references",
                [],
            ):
                resolved_name = self._lookup_network_name(
                    reference
                )

                if resolved_name is None:
                    continue

                dependencies.add(
                    resolved_name.strip().lower()
                )

            graph[normalized_name] = dependencies

        return graph

    # ================================================================
    # Network references
    # ================================================================

    def _collect_network_reference(
        self,
        value: str,
        used: Set[str],
    ) -> None:
        """
        Resolve one configuration value as a network object
        reference.

        Literal addresses, CIDRs, host values, and 'any' are
        ignored.

        Object references mark only the referenced object.

        Object-group references mark the group and recursively
        mark every object/group contained by it.
        """

        if not value:
            return

        normalized = value.strip()

        if not normalized:
            return

        lower_value = normalized.lower()

        if lower_value == "any":
            return

        if lower_value.startswith("host:"):
            return

        # ------------------------------------------------------------
        # Explicit object reference
        # ------------------------------------------------------------

        if lower_value.startswith("object:"):

            name = normalized[
                len("object:"):
            ].strip()

            if not name:
                return

            object_name = self._lookup_network_name(
                name
            )

            if object_name is None:
                return

            used.add(
                object_name.strip().lower()
            )

            return

        # ------------------------------------------------------------
        # Explicit object-group reference
        # ------------------------------------------------------------

        if lower_value.startswith(
            "object-group:"
        ):

            name = normalized[
                len("object-group:"):
            ].strip()

            if not name:
                return

            self._mark_network_group(
                name,
                used,
                set(),
            )

            return

        # ------------------------------------------------------------
        # Cisco-style object-group with a space
        # ------------------------------------------------------------

        if lower_value.startswith(
            "object-group "
        ):

            name = normalized[
                len("object-group "):
            ].strip()

            if not name:
                return

            self._mark_network_group(
                name,
                used,
                set(),
            )

            return

        # ------------------------------------------------------------
        # Plain object name
        # ------------------------------------------------------------

        object_name = self._lookup_network_name(
            normalized
        )

        if object_name is None:
            return

        used.add(
            object_name.strip().lower()
        )

    def _mark_network_group(
        self,
        name: str,
        used: Set[str],
        visited: Set[str],
    ) -> None:
        """
        Mark a network object-group and all of its recursive
        dependencies as used.

        Circular references are safely ignored.
        """

        object_name = self._lookup_network_name(
            name
        )

        if object_name is None:
            return

        normalized_name = (
            object_name.strip().lower()
        )

        if normalized_name in visited:
            return

        visited = set(visited)
        visited.add(normalized_name)

        used.add(normalized_name)

        network_object = self.firewall.networks.get(
            object_name
        )

        if network_object is None:
            return

        for reference in getattr(
            network_object,
            "group_references",
            [],
        ):

            reference_name = self._lookup_network_name(
                reference
            )

            if reference_name is None:
                continue

            reference_object = (
                self.firewall.networks.get(
                    reference_name
                )
            )

            if reference_object is None:
                continue

            reference_normalized = (
                reference_name.strip().lower()
            )

            used.add(
                reference_normalized
            )

            self._mark_network_group(
                reference_name,
                used,
                visited,
            )

    # ================================================================
    # Service references
    # ================================================================

    def _collect_service_reference(
        self,
        value: str,
        used: Set[str],
    ) -> None:
        """
        Mark a service object as used.

        Service references are case-insensitive.
        """

        if not value:
            return

        normalized = value.strip()

        if not normalized:
            return

        object_name = self._lookup_service_name(
            normalized
        )

        if object_name is None:
            return

        used.add(
            object_name.strip().lower()
        )

    # ================================================================
    # Lookup helpers
    # ================================================================

    def _lookup_network_name(
        self,
        name: str,
    ):
        """
        Resolve a configured network-object name
        case-insensitively.

        Returns the actual configured dictionary key.
        """

        if not name:
            return None

        normalized = name.strip().lower()

        if not normalized:
            return None

        return self._network_lookup.get(
            normalized
        )

    def _lookup_service_name(
        self,
        name: str,
    ):
        """
        Resolve a configured service-object name
        case-insensitively.

        Returns the actual configured dictionary key.
        """

        if not name:
            return None

        normalized = name.strip().lower()

        if not normalized:
            return None

        return self._service_lookup.get(
            normalized
        )