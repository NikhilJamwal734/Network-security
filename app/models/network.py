from dataclasses import dataclass, field
from ipaddress import IPv4Network, IPv6Network
from typing import List, Optional, Union


IPNetwork = Union[
    IPv4Network,
    IPv6Network,
]


@dataclass
class NetworkObject:

    name: str

    networks: List[IPNetwork] = field(
        default_factory=list
    )

    description: Optional[str] = None

    line_number: Optional[int] = None

    raw_config: str = ""

    group_references: List[str] = field(
        default_factory=list
    )

    def contains(
        self,
        network: IPNetwork,
    ) -> bool:

        return any(
            candidate.version
            == network.version
            and candidate.supernet_of(
                network
            )
            for candidate in self.networks
        )

    def add_network(
        self,
        network: IPNetwork,
    ):

        if network not in self.networks:

            self.networks.append(
                network
            )

    def add_group_reference(
        self,
        name: str,
    ):

        if name not in self.group_references:

            self.group_references.append(
                name
            )