from dataclasses import dataclass, field
from typing import Dict, List, Optional

from app.models.network import NetworkObject
from app.models.service import Service
from app.models.rule import FirewallRule


@dataclass
class Interface:
    name: str
    security_zone: str = ""
    ip_address: str = ""
    description: str = ""
    enabled: bool = True


@dataclass
class NATRule:
    id: int
    source: str
    translated_source: str
    destination: str = "any"
    translated_destination: str = "any"
    protocol: str = "ip"
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    line_number: Optional[int] = None
    raw_config: str = ""


@dataclass
class Route:
    destination: str
    next_hop: str
    interface: str = ""
    metric: Optional[int] = None
    line_number: Optional[int] = None
    raw_config: str = ""


@dataclass
class FirewallConfig:
    vendor: str
    hostname: str = ""
    interfaces: Dict[str, Interface] = field(
        default_factory=dict
    )
    networks: Dict[str, NetworkObject] = field(
        default_factory=dict
    )
    services: Dict[str, Service] = field(
        default_factory=dict
    )
    rules: List[FirewallRule] = field(
        default_factory=list
    )
    nat_rules: List[NATRule] = field(
        default_factory=list
    )
    routes: List[Route] = field(
        default_factory=list
    )
    warnings: List[str] = field(
        default_factory=list
    )

    def add_interface(
        self,
        interface: Interface,
    ):
        self.interfaces[interface.name] = interface

    def add_network(
        self,
        network: NetworkObject,
    ):
        self.networks[network.name] = network

    def add_service(
        self,
        service: Service,
    ):
        self.services[service.name] = service

    def add_rule(
        self,
        rule: FirewallRule,
    ):
        self.rules.append(rule)

    def add_nat_rule(
        self,
        nat_rule: NATRule,
    ):
        self.nat_rules.append(nat_rule)

    def add_warning(
        self,
        warning: str,
    ):
        self.warnings.append(warning)