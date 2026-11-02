from ipaddress import ip_address, ip_network
from typing import Optional


class RouteMatcher:
    """
    Provides semantic matching for firewall routes.

    Responsibilities:
        - Compare route destinations
        - Detect duplicate routes
        - Detect overlapping routes
        - Determine whether one route is more specific
        - Detect default routes
        - Normalize IPv4 network/mask representations
        - Validate IPv4 and IPv6 next-hop addresses
    """

    @staticmethod
    def parse_network(
        destination: Optional[str],
    ):
        """
        Convert a route destination into an ip_network object.

        Supported formats:
            10.10.10.0/24
            10.10.10.10/32
            10.10.10.0 255.255.255.0
            0.0.0.0/0
        """

        if destination is None:
            return None

        value = destination.strip()

        if not value:
            return None

        parts = value.split()

        # Cisco-style network and subnet mask:
        # 10.10.10.0 255.255.255.0
        if len(parts) == 2:
            try:
                return ip_network(
                    f"{parts[0]}/{parts[1]}",
                    strict=False,
                )
            except ValueError:
                return None

        try:
            return ip_network(
                value,
                strict=False,
            )
        except ValueError:
            return None

    # ================================================================
    # FW-025: Next-hop IP address validation
    # ================================================================

    @staticmethod
    def is_valid_next_hop(
        next_hop: str,
    ) -> bool:
        """
        Return True if the next hop is a valid IPv4 or IPv6 address.

        This validates address syntax only.
        It does not check whether the next hop is reachable.
        """

        if not isinstance(next_hop, str):
            return False

        value = next_hop.strip()

        if not value:
            return False

        try:
            ip_address(value)
        except ValueError:
            return False

        return True

        # ================================================================
    # FW-026: Route next-hop address-family consistency
    # ================================================================

    @classmethod
    def has_next_hop_family_mismatch(
        cls,
        destination: str,
        next_hop: str,
    ) -> bool:
        """
        Return True when the route destination and next-hop
        IP address belong to different address families.

        Examples:
            IPv4 destination + IPv4 next hop -> False
            IPv6 destination + IPv6 next hop -> False
            IPv4 destination + IPv6 next hop -> True
            IPv6 destination + IPv4 next hop -> True

        Invalid destinations or next-hop addresses are ignored.
        Those are handled by separate validation checks.
        """

        network = cls.parse_network(destination)

        if network is None:
            return False

        if not cls.is_valid_next_hop(next_hop):
            return False

        try:
            address = ip_address(next_hop.strip())
        except ValueError:
            return False

        return network.version != address.version

    # ================================================================
    # Route destination equality
    # ================================================================

    @classmethod
    def destinations_equal(
        cls,
        first: str,
        second: str,
    ) -> bool:
        """
        Determine whether two route destinations represent
        the same network.
        """

        first_network = cls.parse_network(first)
        second_network = cls.parse_network(second)

        if first_network is None or second_network is None:
            return False

        return first_network == second_network

    # ================================================================
    # Route destination overlap
    # ================================================================

    @classmethod
    def destinations_overlap(
        cls,
        first: str,
        second: str,
    ) -> bool:
        """
        Determine whether two route destinations overlap.

        Example:
            10.10.0.0/16
            10.10.10.0/24

        Result:
            True
        """

        first_network = cls.parse_network(first)
        second_network = cls.parse_network(second)

        if first_network is None or second_network is None:
            return False

        if first_network.version != second_network.version:
            return False

        return first_network.overlaps(second_network)

    # ================================================================
    # More-specific route detection
    # ================================================================

    @classmethod
    def is_more_specific(
        cls,
        first: str,
        second: str,
    ) -> bool:
        """
        Determine whether the first route is more specific
        than the second route.

        Example:
            first:  10.10.10.0/24
            second: 10.10.0.0/16

        Result:
            True
        """

        first_network = cls.parse_network(first)
        second_network = cls.parse_network(second)

        if first_network is None or second_network is None:
            return False

        if first_network.version != second_network.version:
            return False

        if not second_network.supernet_of(first_network):
            return False

        return (
            first_network.prefixlen
            > second_network.prefixlen
        )

    # ================================================================
    # Default route detection
    # ================================================================

    @classmethod
    def is_default_route(
        cls,
        destination: str,
    ) -> bool:
        """
        Determine whether a route is a default route.

        Examples:
            0.0.0.0/0 -> True
            ::/0      -> True
            10.0.0.0/8 -> False
        """

        network = cls.parse_network(destination)

        if network is None:
            return False

        return network.prefixlen == 0

    # ================================================================
    # Next-hop comparison
    # ================================================================

    @staticmethod
    def same_next_hop(
        first: str,
        second: str,
    ) -> bool:
        """
        Compare two next-hop values.
        """

        first_value = (
            first or ""
        ).strip().lower()

        second_value = (
            second or ""
        ).strip().lower()

        return first_value == second_value

    # ================================================================
    # Interface comparison
    # ================================================================

    @staticmethod
    def same_interface(
        first: str,
        second: str,
    ) -> bool:
        """
        Compare two route interfaces.
        """

        first_value = (
            first or ""
        ).strip().lower()

        second_value = (
            second or ""
        ).strip().lower()

        return first_value == second_value

    # ================================================================
    # Duplicate route detection
    # ================================================================

    @classmethod
    def routes_are_duplicates(
        cls,
        first,
        second,
    ) -> bool:
        """
        Determine whether two routes have the same:
            - Destination
            - Next hop
            - Interface

        Metric differences are intentionally ignored.
        """

        if not cls.destinations_equal(
            first.destination,
            second.destination,
        ):
            return False

        if not cls.same_next_hop(
            first.next_hop,
            second.next_hop,
        ):
            return False

        if not cls.same_interface(
            first.interface,
            second.interface,
        ):
            return False

        return True

    # ================================================================
    # Same destination detection
    # ================================================================

    @classmethod
    def routes_have_same_destination(
        cls,
        first,
        second,
    ) -> bool:
        """
        Determine whether two routes point to the same
        destination network.
        """

        return cls.destinations_equal(
            first.destination,
            second.destination,
        )