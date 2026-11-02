from typing import List

from app.analyzer.network_matcher import NetworkMatcher
from app.analyzer.object_resolver import NetworkObjectResolver
from app.models.rule import FirewallRule


class RuleMatcher:
    def __init__(self, resolver: NetworkObjectResolver):
        self.resolver = resolver

    def matches_contained_by(
        self,
        broader: FirewallRule,
        narrower: FirewallRule,
    ) -> bool:
        if not self._protocol_contains(broader.protocol, narrower.protocol):
            return False

        if not self._address_contains(
            broader.source,
            narrower.source,
        ):
            return False

        if not self._address_contains(
            broader.destination,
            narrower.destination,
        ):
            return False

        if not self._ports_contain(
            broader.source_ports,
            narrower.source_ports,
        ):
            return False

        if not self._ports_contain(
            broader.destination_ports,
            narrower.destination_ports,
        ):
            return False

        return True

    def rules_equal(
        self,
        first: FirewallRule,
        second: FirewallRule,
    ) -> bool:
        """
        Determine whether two rules have the same effective traffic match.

        Equality is semantic rather than textual. For example:

            host:10.10.10.10

        and:

            10.10.10.10/32

        represent the same network and therefore compare as equal.
        """

        if first.action.lower() != second.action.lower():
            return False

        if not self._protocols_equal(
            first.protocol,
            second.protocol,
        ):
            return False

        if not self._addresses_equal(
            first.source,
            second.source,
        ):
            return False

        if not self._addresses_equal(
            first.destination,
            second.destination,
        ):
            return False

        if not self._ports_equal(
            first.source_ports,
            second.source_ports,
        ):
            return False

        if not self._ports_equal(
            first.destination_ports,
            second.destination_ports,
        ):
            return False

        return True

    def rules_overlap(
        self,
        first: FirewallRule,
        second: FirewallRule,
    ) -> bool:
        if not self._protocols_overlap(
            first.protocol,
            second.protocol,
        ):
            return False

        if not self._addresses_overlap(
            first.source,
            second.source,
        ):
            return False

        if not self._addresses_overlap(
            first.destination,
            second.destination,
        ):
            return False

        if not self._ports_overlap(
            first.source_ports,
            second.source_ports,
        ):
            return False

        if not self._ports_overlap(
            first.destination_ports,
            second.destination_ports,
        ):
            return False

        return True

    def _address_contains(
        self,
        broader: List[str],
        narrower: List[str],
    ) -> bool:
        broader_any = self.resolver.is_any(broader)
        narrower_any = self.resolver.is_any(narrower)

        if broader_any:
            return True

        if narrower_any:
            return False

        broader_networks = self.resolver.resolve_list(broader)
        narrower_networks = self.resolver.resolve_list(narrower)

        if not broader_networks:
            return False

        if not narrower_networks:
            return False

        return NetworkMatcher.contains(
            broader_networks,
            narrower_networks,
        )

    def _addresses_equal(
        self,
        first: List[str],
        second: List[str],
    ) -> bool:
        first_any = self.resolver.is_any(first)
        second_any = self.resolver.is_any(second)

        if first_any and second_any:
            return True

        if first_any != second_any:
            return False

        first_networks = self.resolver.resolve_list(first)
        second_networks = self.resolver.resolve_list(second)

        if not first_networks or not second_networks:
            return False

        return NetworkMatcher.equal(
            first_networks,
            second_networks,
        )

    def _addresses_overlap(
        self,
        first: List[str],
        second: List[str],
    ) -> bool:
        first_any = self.resolver.is_any(first)
        second_any = self.resolver.is_any(second)

        if first_any or second_any:
            other = second if first_any else first

            if self.resolver.is_any(other):
                return True

            networks = self.resolver.resolve_list(other)
            return bool(networks)

        first_networks = self.resolver.resolve_list(first)
        second_networks = self.resolver.resolve_list(second)

        if not first_networks or not second_networks:
            return False

        return NetworkMatcher.overlaps(
            first_networks,
            second_networks,
        )

    @staticmethod
    def _protocols_equal(
        first: str,
        second: str,
    ) -> bool:
        return first.strip().lower() == second.strip().lower()

    @staticmethod
    def _protocol_contains(
        broader: str,
        narrower: str,
    ) -> bool:
        broader = broader.strip().lower()
        narrower = narrower.strip().lower()

        if broader in {"ip", "any"}:
            return True

        return broader == narrower

    @staticmethod
    def _protocols_overlap(
        first: str,
        second: str,
    ) -> bool:
        first = first.strip().lower()
        second = second.strip().lower()

        if first == second:
            return True

        if first in {"ip", "any"}:
            return True

        if second in {"ip", "any"}:
            return True

        return False

    @staticmethod
    def _ports_contain(
        broader: List[int],
        narrower: List[int],
    ) -> bool:
        # No ports means "any port".
        if not broader:
            return True

        # A port-specific rule cannot contain an any-port rule.
        if not narrower:
            return False

        return all(
            port in broader
            for port in narrower
        )

    @staticmethod
    def _ports_equal(
        first: List[int],
        second: List[int],
    ) -> bool:
        return set(first) == set(second)

    @staticmethod
    def _ports_overlap(
        first: List[int],
        second: List[int],
    ) -> bool:
        # Both rules allow any port.
        if not first and not second:
            return True

        # One rule allows any port.
        if not first:
            return bool(second)

        if not second:
            return bool(first)

        return any(
            port in second
            for port in first
        )

