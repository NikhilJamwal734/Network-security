from ipaddress import (
    IPv4Network,
    IPv6Network,
    ip_network,
)
from typing import List, Union


IPNetwork = Union[
    IPv4Network,
    IPv6Network,
]


class NetworkMatcher:

    ANY_IPV4 = ip_network(
        "0.0.0.0/0"
    )

    ANY_IPV6 = ip_network(
        "::/0"
    )

    @classmethod
    def resolve_any(
        cls,
        values: List[IPNetwork],
        any_value: bool = False,
    ) -> List[IPNetwork]:

        if any_value:
            return [
                cls.ANY_IPV4,
                cls.ANY_IPV6,
            ]

        return values

    @classmethod
    def contains(
        cls,
        container: List[IPNetwork],
        target: List[IPNetwork],
        container_any: bool = False,
        target_any: bool = False,
    ) -> bool:

        container = cls.resolve_any(
            container,
            container_any,
        )

        target = cls.resolve_any(
            target,
            target_any,
        )

        if not target:
            return False

        for target_network in target:

            covered = False

            for container_network in container:

                if (
                    container_network.version
                    != target_network.version
                ):
                    continue

                if container_network.supernet_of(
                    target_network
                ):

                    covered = True
                    break

            if not covered:
                return False

        return True

    @classmethod
    def equal(
        cls,
        first: List[IPNetwork],
        second: List[IPNetwork],
        first_any: bool = False,
        second_any: bool = False,
    ) -> bool:
        first = cls.resolve_any(first, first_any)
        second = cls.resolve_any(second, second_any)

        if not first or not second:
            return False

        if len(first) != len(second):
            return False

        first_set = {
            (network.version, network.network_address, network.prefixlen)
            for network in first
        }

        second_set = {
            (network.version, network.network_address, network.prefixlen)
            for network in second
        }

        return (first_set == second_set
        )

    @classmethod
    def overlaps(
        cls,
        first: List[IPNetwork],
        second: List[IPNetwork],
        first_any: bool = False,
        second_any: bool = False,
    ) -> bool:

        first = cls.resolve_any(
            first,
            first_any,
        )

        second = cls.resolve_any(
            second,
            second_any,
        )

        for first_network in first:

            for second_network in second:

                if (
                    first_network.version
                    != second_network.version
                ):
                    continue

                if first_network.overlaps(
                    second_network
                ):

                    return True

        return False