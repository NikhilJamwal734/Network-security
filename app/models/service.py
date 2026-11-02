from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class Service:
    name: str
    protocol: str
    ports: List[int] = field(
        default_factory=list
    )
    description: Optional[str] = None
    line_number: Optional[int] = None
    raw_config: str = ""

    def uses_port(
        self,
        port: int,
    ) -> bool:

        return port in self.ports

    def add_port(
        self,
        port: int,
    ):

        if port not in self.ports:
            self.ports.append(port)