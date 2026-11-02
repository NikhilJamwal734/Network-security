from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class FirewallRule:
    """
    Vendor-neutral firewall policy rule.

    The parser for each firewall vendor converts its native syntax
    into this model.
    """

    id: int

    line_number: int

    name: Optional[str]

    action: str

    protocol: str

    source: List[str] = field(default_factory=list)

    destination: List[str] = field(default_factory=list)

    source_ports: List[int] = field(default_factory=list)

    destination_ports: List[int] = field(default_factory=list)

    source_services: List[str] = field(default_factory=list)

    destination_services: List[str] = field(default_factory=list)

    source_interface: Optional[str] = None

    destination_interface: Optional[str] = None

    logging: bool = False

    disabled: bool = False

    description: Optional[str] = None

    raw_config: str = ""

    def is_permit(self) -> bool:
        return self.action.lower() in {
            "permit",
            "allow",
            "accept",
        }

    def is_deny(self) -> bool:
        return self.action.lower() in {
            "deny",
            "drop",
            "reject",
        }

    def is_any_source(self) -> bool:
        return "any" in self.source

    def is_any_destination(self) -> bool:
        return "any" in self.destination

    def is_any_to_any(self) -> bool:
        return (
            self.is_any_source()
            and self.is_any_destination()
        )