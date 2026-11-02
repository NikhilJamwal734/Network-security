from ipaddress import ip_network
from typing import Optional

from app.models.firewall import NATRule
from app.models.rule import FirewallRule


class NATMatcher:
    """
    Provides semantic matching for firewall NAT rules.

    This class is responsible for:
        - Comparing NAT rules
        - Detecting NAT shadowing
        - Detecting overlapping NAT rules
        - Comparing translated addresses with ACL destinations
        - Normalizing NAT and ACL address values
    """

    def matches_same_scope(
        self,
        first: NATRule,
        second: NATRule,
    ) -> bool:
        """
        Determine whether two NAT rules operate in the same scope.

        NAT rules are considered to have the same scope when their
        protocol and destination/translated-destination values match.
        """

        if not self._value_equal(
            first.protocol,
            second.protocol,
        ):
            return False

        if not self._value_equal(
            first.destination,
            second.destination,
        ):
            return False

        if not self._value_equal(
            first.translated_destination,
            second.translated_destination,
        ):
            return False

        return True

    def shadows(
        self,
        earlier: NATRule,
        later: NATRule,
    ) -> bool:
        """
        Determine whether an earlier NAT rule completely shadows
        a later NAT rule.

        This currently identifies exact semantic duplicates in the
        same NAT scope.
        """

        if not self.matches_same_scope(
            earlier,
            later,
        ):
            return False

        if not self.source_matches(
            earlier,
            later,
        ):
            return False

        if not self.translated_source_matches(
            earlier,
            later,
        ):
            return False

        if not self._ports_equal(
            earlier.source_port,
            later.source_port,
        ):
            return False

        if not self._ports_equal(
            earlier.destination_port,
            later.destination_port,
        ):
            return False

        return True

    def translated_address_matches_rule(
        self,
        nat_rule: NATRule,
        firewall_rule: FirewallRule,
    ) -> bool:
        """
        Determine whether the translated source address of a NAT rule
        falls within a firewall rule's destination scope.

        Examples:

            NAT translated source:
                203.0.113.10

            ACL destination:
                203.0.113.0/24

        Result:
            True

        The method also understands:
            any
            host:10.10.10.10
            10.10.10.10
            10.10.10.0/24
            10.10.10.0 255.255.255.0

        Interface-based NAT translations are not treated as IP
        addresses and therefore return False.
        """

        translated_value = (
            nat_rule.translated_source or ""
        ).strip()

        if not translated_value:
            return False

        if translated_value.lower().startswith(
            "interface:"
        ):
            return False

        translated_network = self._parse_network(
            translated_value
        )

        if translated_network is None:
            return False

        if firewall_rule.is_any_destination():
            return True

        for destination in firewall_rule.destination:

            if not destination:
                continue

            if destination.strip().lower() == "any":
                return True

            destination_network = self._parse_network(
                destination
            )

            if destination_network is None:
                continue

            if (
                destination_network.version
                != translated_network.version
            ):
                continue

            if destination_network.supernet_of(
                translated_network
            ):
                return True

            if destination_network == translated_network:
                return True

        return False

    def source_matches(
        self,
        first: NATRule,
        second: NATRule,
    ) -> bool:
        """
        Determine whether two NAT source addresses are equivalent.
        """

        first_network = self._parse_network(
            first.source
        )

        second_network = self._parse_network(
            second.source
        )

        if first_network is None or second_network is None:
            return self._value_equal(
                first.source,
                second.source,
            )

        return first_network == second_network

    def translated_source_matches(
        self,
        first: NATRule,
        second: NATRule,
    ) -> bool:
        """
        Determine whether two translated source addresses are
        equivalent.
        """

        first_network = self._parse_network(
            first.translated_source
        )

        second_network = self._parse_network(
            second.translated_source
        )

        if first_network is None or second_network is None:
            return self._value_equal(
                first.translated_source,
                second.translated_source,
            )

        return first_network == second_network

    def addresses_overlap(
        self,
        first: str,
        second: str,
    ) -> bool:
        """
        Determine whether two NAT address values overlap.

        Returns False when either value cannot be interpreted
        as an IP network.
        """

        first_network = self._parse_network(
            first
        )

        second_network = self._parse_network(
            second
        )

        if first_network is None or second_network is None:
            return False

        if (
            first_network.version
            != second_network.version
        ):
            return False

        return first_network.overlaps(
            second_network
        )

    def rules_overlap(
        self,
        first: NATRule,
        second: NATRule,
    ) -> bool:
        """
        Determine whether two NAT rules can operate on overlapping
        traffic.

        This is different from shadows():

            shadows()
                Detects complete semantic duplication.

            rules_overlap()
                Detects partial traffic overlap.

        The comparison considers:

            - source address
            - destination address
            - translated destination
            - protocol
            - source port
            - destination port

        Unknown address values are rejected rather than assumed
        to overlap.
        """

        if not self._protocols_overlap(
            first.protocol,
            second.protocol,
        ):
            return False

        if not self._ports_overlap(
            first.source_port,
            second.source_port,
        ):
            return False

        if not self._ports_overlap(
            first.destination_port,
            second.destination_port,
        ):
            return False

        if not self._addresses_overlap_with_any(
            first.source,
            second.source,
        ):
            return False

        if not self._addresses_overlap_with_any(
            first.destination,
            second.destination,
        ):
            return False

        if not self._addresses_overlap_with_any(
            first.translated_destination,
            second.translated_destination,
        ):
            return False

        return True

    @classmethod
    def _addresses_overlap_with_any(
        cls,
        first: Optional[str],
        second: Optional[str],
    ) -> bool:
        """
        Compare two NAT address scopes.

        "any" represents an unrestricted address scope.

        Unknown values are rejected rather than assumed to overlap.
        """

        first_value = (
            first or ""
        ).strip().lower()

        second_value = (
            second or ""
        ).strip().lower()

        if first_value == "any" or second_value == "any":
            return True

        first_network = cls._parse_network(
            first
        )

        second_network = cls._parse_network(
            second
        )

        if first_network is None or second_network is None:
            return False

        if (
            first_network.version
            != second_network.version
        ):
            return False

        return first_network.overlaps(
            second_network
        )

    @staticmethod
    def _protocols_overlap(
        first: Optional[str],
        second: Optional[str],
    ) -> bool:
        """
        Determine whether two NAT protocol scopes overlap.

        "ip" represents all IP protocols.
        """

        first_value = (
            first or ""
        ).strip().lower()

        second_value = (
            second or ""
        ).strip().lower()

        if not first_value or not second_value:
            return False

        if first_value == "ip":
            return True

        if second_value == "ip":
            return True

        return first_value == second_value

    @staticmethod
    def _ports_overlap(
        first: Optional[int],
        second: Optional[int],
    ) -> bool:
        """
        Determine whether two optional NAT ports overlap.

        None represents an unrestricted port scope.
        """

        if first is None or second is None:
            return True

        return first == second

    @staticmethod
    def _value_equal(
        first: Optional[str],
        second: Optional[str],
    ) -> bool:
        """
        Compare two NAT values case-insensitively.
        """

        first_value = (
            first or ""
        ).strip().lower()

        second_value = (
            second or ""
        ).strip().lower()

        return first_value == second_value

    @staticmethod
    def _ports_equal(
        first: Optional[int],
        second: Optional[int],
    ) -> bool:
        """
        Compare optional NAT ports.
        """

        return first == second

    @staticmethod
    def _parse_network(
        value: Optional[str],
    ):
        """
        Convert an address value into an ip_network object.

        Supported formats:

            10.10.10.10
            10.10.10.10/32
            10.10.10.0/24
            10.10.10.0 255.255.255.0
            host:10.10.10.10

        Returns None when the value cannot be parsed.
        """

        if value is None:
            return None

        value = value.strip()

        if not value:
            return None

        if value.lower() == "any":
            return None

        if value.lower().startswith("host:"):
            value = value.split(
                ":",
                1,
            )[1].strip()

            if not value:
                return None

        parts = value.split()

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
            pass

        try:
            return ip_network(
                f"{value}/32",
                strict=False,
            )

        except ValueError:
            return None