import re
from ipaddress import ip_network
from typing import List, Optional

from app.models.firewall import FirewallConfig, Interface, NATRule, Route
from app.models.network import NetworkObject
from app.models.rule import FirewallRule
from app.models.service import Service


class CiscoASAParser:
    HOSTNAME_RE = re.compile(
        r"^\s*hostname\s+(\S+)",
        re.IGNORECASE,
    )

    INTERFACE_RE = re.compile(
        r"^\s*interface\s+(\S+)",
        re.IGNORECASE,
    )

    NAMEIF_RE = re.compile(
        r"^\s*nameif\s+(\S+)",
        re.IGNORECASE,
    )

    DESCRIPTION_RE = re.compile(
        r"^\s*description\s+(.+)",
        re.IGNORECASE,
    )

    IP_ADDRESS_RE = re.compile(
        r"^\s*ip\s+address\s+(\S+)(?:\s+(\S+))?",
        re.IGNORECASE,
    )

    OBJECT_NETWORK_RE = re.compile(
        r"^\s*object\s+network\s+(\S+)",
        re.IGNORECASE,
    )

    OBJECT_GROUP_NETWORK_RE = re.compile(
        r"^\s*object-group\s+network\s+(\S+)",
        re.IGNORECASE,
    )

    OBJECT_SERVICE_RE = re.compile(
        r"^\s*object\s+service\s+(\S+)",
        re.IGNORECASE,
    )

    OBJECT_GROUP_SERVICE_RE = re.compile(
        r"^\s*object-group\s+service\s+(\S+)(?:\s+(\S+))?",
        re.IGNORECASE,
    )

    ACCESS_LIST_RE = re.compile(
        r"^\s*access-list\s+(\S+)\s+extended\s+"
        r"(permit|deny)\s+(\S+)\s+(.+)",
        re.IGNORECASE,
    )

    ROUTE_RE = re.compile(
        r"^\s*route\s+"
        r"(\S+)\s+"
        r"(\S+)\s+"
        r"(\S+)\s+"
        r"(\S+)"
        r"(?:\s+(\S+))?",
        re.IGNORECASE,
    )

    NAT_RE = re.compile(
        r"^\s*nat\s+\(([^,]+),([^)]+)\)\s+static\s+(\S+)",
        re.IGNORECASE,
    )

    def parse(self, lines: List[str]) -> FirewallConfig:
        firewall = FirewallConfig(vendor="Cisco ASA")

        current_interface: Optional[Interface] = None
        current_network: Optional[NetworkObject] = None
        current_service: Optional[Service] = None

        for line_number, raw_line in enumerate(lines, start=1):
            line = raw_line.rstrip()
            stripped = line.strip()

            if not stripped:
                continue

            if stripped == "!":
                current_interface = None
                current_network = None
                current_service = None
                continue

            # ---------------------------------------------------------
            # Hostname
            # ---------------------------------------------------------
            match = self.HOSTNAME_RE.match(line)
            if match:
                firewall.hostname = match.group(1)
                continue

            # ---------------------------------------------------------
            # Interface
            # ---------------------------------------------------------
            match = self.INTERFACE_RE.match(line)
            if match:
                interface_name = match.group(1)

                current_interface = Interface(
                    name=interface_name,
                )

                firewall.add_interface(current_interface)

                current_network = None
                current_service = None
                continue

            if current_interface is not None:
                match = self.NAMEIF_RE.match(line)
                if match:
                    current_interface.security_zone = match.group(1)
                    continue

                match = self.DESCRIPTION_RE.match(line)
                if match:
                    current_interface.description = match.group(1).strip()
                    continue

                match = self.IP_ADDRESS_RE.match(line)
                if match:
                    current_interface.ip_address = match.group(1)
                    continue

                if stripped.lower() == "shutdown":
                    current_interface.enabled = False
                    continue

            # ---------------------------------------------------------
            # Network object
            # ---------------------------------------------------------
            match = self.OBJECT_NETWORK_RE.match(line)
            if match:
                name = match.group(1)

                current_network = NetworkObject(
                    name=name,
                    line_number=line_number,
                    raw_config=line,
                )

                firewall.add_network(current_network)

                current_interface = None
                current_service = None
                continue

            if current_network is not None:
                parts = stripped.split()

                # host 10.10.10.10
                if len(parts) >= 2 and parts[0].lower() == "host":
                    try:
                        network = ip_network(
                            f"{parts[1]}/32",
                            strict=False,
                        )
                        current_network.add_network(network)
                    except ValueError:
                        firewall.add_warning(
                            f"Invalid host address at line {line_number}: {line}"
                        )

                    nat_match = self.NAT_RE.match(stripped)
                    if nat_match:
                        self._add_static_nat(
                            firewall=firewall,
                            network_name=current_network.name,
                            translated_source=nat_match.group(3),
                            line_number=line_number,
                            raw_config=line,
                        )

                    continue

                # subnet 10.10.10.0 255.255.255.0
                if (
                    len(parts) >= 3
                    and parts[0].lower() == "subnet"
                ):
                    try:
                        network = ip_network(
                            f"{parts[1]}/{parts[2]}",
                            strict=False,
                        )
                        current_network.add_network(network)
                    except ValueError:
                        firewall.add_warning(
                            f"Invalid subnet at line {line_number}: {line}"
                        )

                    nat_match = self.NAT_RE.match(stripped)
                    if nat_match:
                        self._add_static_nat(
                            firewall=firewall,
                            network_name=current_network.name,
                            translated_source=nat_match.group(3),
                            line_number=line_number,
                            raw_config=line,
                        )

                    continue

                # subnet 10.10.10.0/24
                if (
                    len(parts) >= 2
                    and parts[0].lower() == "subnet"
                    and "/" in parts[1]
                ):
                    try:
                        network = ip_network(
                            parts[1],
                            strict=False,
                        )
                        current_network.add_network(network)
                    except ValueError:
                        firewall.add_warning(
                            f"Invalid CIDR subnet at line {line_number}: {line}"
                        )

                    continue

                # nat (inside,outside) static ...
                nat_match = self.NAT_RE.match(stripped)
                if nat_match:
                    self._add_static_nat(
                        firewall=firewall,
                        network_name=current_network.name,
                        translated_source=nat_match.group(3),
                        line_number=line_number,
                        raw_config=line,
                    )
                    continue

            # ---------------------------------------------------------
            # Network object-group
            # ---------------------------------------------------------
            match = self.OBJECT_GROUP_NETWORK_RE.match(line)
            if match:
                name = match.group(1)

                current_network = NetworkObject(
                    name=name,
                    line_number=line_number,
                    raw_config=line,
                )

                firewall.add_network(current_network)

                current_interface = None
                current_service = None
                continue

            if current_network is not None:
                parts = stripped.split()

                # network-object host 10.10.10.10
                if (
                    len(parts) >= 3
                    and parts[0].lower() == "network-object"
                    and parts[1].lower() == "host"
                ):
                    try:
                        network = ip_network(
                            f"{parts[2]}/32",
                            strict=False,
                        )
                        current_network.add_network(network)
                    except ValueError:
                        firewall.add_warning(
                            f"Invalid network object at line {line_number}: {line}"
                        )

                    continue

                # network-object 10.10.10.0/24
                if (
                    len(parts) >= 2
                    and parts[0].lower() == "network-object"
                    and "/" in parts[1]
                ):
                    try:
                        network = ip_network(
                            parts[1],
                            strict=False,
                        )
                        current_network.add_network(network)
                    except ValueError:
                        firewall.add_warning(
                            f"Invalid CIDR network object at line {line_number}: {line}"
                        )

                    continue

                # network-object 10.10.10.0 255.255.255.0
                if (
                    len(parts) >= 3
                    and parts[0].lower() == "network-object"
                ):
                    try:
                        network = ip_network(
                            f"{parts[1]}/{parts[2]}",
                            strict=False,
                        )
                        current_network.add_network(network)
                    except ValueError:
                        firewall.add_warning(
                            f"Invalid network object at line {line_number}: {line}"
                        )

                    continue

                # group-object OTHER_GROUP
                if (
                    len(parts) >= 2
                    and parts[0].lower() == "group-object"
                ):
                    current_network.add_group_reference(parts[1])
                    continue

            # ---------------------------------------------------------
            # Service object
            # ---------------------------------------------------------
            match = self.OBJECT_SERVICE_RE.match(line)
            if match:
                name = match.group(1)

                current_service = Service(
                    name=name,
                    protocol="ip",
                    line_number=line_number,
                    raw_config=line,
                )

                firewall.add_service(current_service)

                current_interface = None
                current_network = None
                continue

            if current_service is not None:
                parts = stripped.split()

                # service tcp destination eq 443
                if (
                    len(parts) >= 2
                    and parts[0].lower() == "service"
                ):
                    protocol = parts[1].lower()
                    current_service.protocol = protocol

                    operator_index = -1

                    for index, value in enumerate(
                        parts[2:],
                        start=2,
                    ):
                        if value.lower() in {"eq", "range"}:
                            operator_index = index
                            break

                    if operator_index != -1:
                        operator = parts[operator_index].lower()
                        values = parts[operator_index + 1:]

                        if operator == "eq":
                            for value in values:
                                port = self._parse_port(value)

                                if port is not None:
                                    current_service.add_port(port)

                        elif operator == "range" and len(values) >= 2:
                            start = self._parse_port(values[0])
                            end = self._parse_port(values[1])

                            if (
                                start is not None
                                and end is not None
                                and start <= end
                            ):
                                for port in range(start, end + 1):
                                    current_service.add_port(port)

                    continue

                # port-object eq 443
                if (
                    len(parts) >= 3
                    and parts[0].lower() == "port-object"
                ):
                    operator = parts[1].lower()

                    if operator == "eq":
                        for value in parts[2:]:
                            port = self._parse_port(value)

                            if port is not None:
                                current_service.add_port(port)

                    elif operator == "range" and len(parts) >= 4:
                        start = self._parse_port(parts[2])
                        end = self._parse_port(parts[3])

                        if (
                            start is not None
                            and end is not None
                            and start <= end
                        ):
                            for port in range(start, end + 1):
                                current_service.add_port(port)

                    continue

                # protocol tcp
                if (
                    len(parts) >= 2
                    and parts[0].lower() == "protocol"
                ):
                    current_service.protocol = parts[1].lower()
                    continue

            # ---------------------------------------------------------
            # Service object-group
            # ---------------------------------------------------------
            match = self.OBJECT_GROUP_SERVICE_RE.match(line)
            if match:
                name = match.group(1)
                protocol = match.group(2) or "ip"

                current_service = Service(
                    name=name,
                    protocol=protocol.lower(),
                    line_number=line_number,
                    raw_config=line,
                )

                firewall.add_service(current_service)

                current_interface = None
                current_network = None
                continue

            # ---------------------------------------------------------
            # Access-list
            # ---------------------------------------------------------
            match = self.ACCESS_LIST_RE.match(line)
            if match:
                acl_name = match.group(1)
                action = match.group(2).lower()
                protocol = match.group(3).lower()
                remainder = match.group(4)

                rule = self._parse_acl_rule(
                    acl_name=acl_name,
                    action=action,
                    protocol=protocol,
                    remainder=remainder,
                    line_number=line_number,
                    raw_config=line,
                )

                if rule is not None:
                    firewall.add_rule(rule)

                continue

            # ---------------------------------------------------------
            # Route
            # ---------------------------------------------------------
            match = self.ROUTE_RE.match(line)
            if match:
                interface = match.group(1)
                destination = match.group(2)
                netmask = match.group(3)
                next_hop = match.group(4)
                metric_text = match.group(5)

                try:
                    destination_network = ip_network(
                        f"{destination}/{netmask}",
                        strict=False,
                    )
                except ValueError:
                    firewall.add_warning(
                        f"Invalid route destination at line {line_number}: {line}"
                    )
                    continue

                metric = None

                if metric_text is not None:
                    try:
                        metric = int(metric_text)
                    except ValueError:
                        firewall.add_warning(
                            f"Invalid route metric at line {line_number}: {line}"
                        )

                firewall.routes.append(
                    Route(
                        destination=str(destination_network),
                        next_hop=next_hop,
                        interface=interface,
                        metric=metric,
                        line_number=line_number,
                        raw_config=line,
                    )
                )

                continue

        return firewall

    # -----------------------------------------------------------------
    # Static NAT
    # -----------------------------------------------------------------

    def _add_static_nat(
        self,
        firewall: FirewallConfig,
        network_name: str,
        translated_source: str,
        line_number: int,
        raw_config: str,
    ):
        firewall.add_nat_rule(
            NATRule(
                id=len(firewall.nat_rules) + 1,
                source=f"object:{network_name}",
                translated_source=translated_source,
                line_number=line_number,
                raw_config=raw_config,
            )
        )

    # -----------------------------------------------------------------
    # ACL parsing
    # -----------------------------------------------------------------

    def _parse_acl_rule(
        self,
        acl_name: str,
        action: str,
        protocol: str,
        remainder: str,
        line_number: int,
        raw_config: str,
    ) -> Optional[FirewallRule]:

        tokens = remainder.split()

        if not tokens:
            return None

        source: List[str] = []
        destination: List[str] = []
        source_ports: List[int] = []
        destination_ports: List[int] = []
        source_services: List[str] = []
        destination_services: List[str] = []

        index = 0

        # Source address
        source_value, index = self._parse_acl_address(
            tokens,
            index,
        )

        if source_value is None:
            return None

        source.append(source_value)

        # -------------------------------------------------------------
        # IMPORTANT:
        # Only consume a port/service modifier here if it is actually
        # a port modifier. "object-group" is an address and therefore
        # must NOT be consumed here.
        # -------------------------------------------------------------
        if index < len(tokens):
            next_token = tokens[index].lower()

            if next_token in {
                "eq",
                "range",
                "lt",
                "gt",
                "neq",
            }:
                index = self._parse_ports(
                    tokens,
                    index,
                    source_ports,
                )

            elif next_token == "object":
                if index + 1 < len(tokens):
                    source_services.append(
                        f"object:{tokens[index + 1]}"
                    )
                    index += 2

            # Do NOT consume object-group here.
            #
            # In:
            # object WEB_SERVER object-group WEB_SERVERS eq 443
            #
            # "object-group WEB_SERVERS" is the destination address.

        # Destination address
        if index >= len(tokens):
            return None

        destination_value, index = self._parse_acl_address(
            tokens,
            index,
        )

        if destination_value is None:
            return None

        destination.append(destination_value)

        # Destination port/service
        if index < len(tokens):
            next_token = tokens[index].lower()

            if next_token in {
                "eq",
                "range",
                "lt",
                "gt",
                "neq",
            }:
                index = self._parse_ports(
                    tokens,
                    index,
                    destination_ports,
                )

            elif next_token == "object":
                if index + 1 < len(tokens):
                    destination_services.append(
                        f"object:{tokens[index + 1]}"
                    )
                    index += 2

            elif next_token == "object-group":
                if index + 1 < len(tokens):
                    destination_services.append(
                        f"object-group:{tokens[index + 1]}"
                    )
                    index += 2

        # Remaining modifiers
        logging = False
        disabled = False
        description = None

        while index < len(tokens):
            token = tokens[index].lower()

            if token == "log":
                logging = True
                index += 1
                continue

            if token == "disable":
                disabled = True
                index += 1
                continue

            if token == "remark":
                description = " ".join(tokens[index + 1:])
                break

            index += 1

        return FirewallRule(
            id=line_number,
            line_number=line_number,
            name=acl_name,
            action=action,
            protocol=protocol,
            source=source,
            destination=destination,
            source_ports=source_ports,
            destination_ports=destination_ports,
            source_services=source_services,
            destination_services=destination_services,
            logging=logging,
            disabled=disabled,
            description=description,
            raw_config=raw_config,
        )

    # -----------------------------------------------------------------
    # ACL address parsing
    # -----------------------------------------------------------------

    def _parse_acl_address(
        self,
        tokens: List[str],
        index: int,
    ):
        if index >= len(tokens):
            return None, index

        token = tokens[index]
        lower = token.lower()

        # any
        if lower == "any":
            return "any", index + 1

        # host 10.10.10.10
        if lower == "host":
            if index + 1 >= len(tokens):
                return None, index

            return (
                f"host:{tokens[index + 1]}",
                index + 2,
            )

        # object NAME
        if lower == "object":
            if index + 1 >= len(tokens):
                return None, index

            return (
                f"object:{tokens[index + 1]}",
                index + 2,
            )

        # object-group NAME
        if lower == "object-group":
            if index + 1 >= len(tokens):
                return None, index

            return (
                f"object-group:{tokens[index + 1]}",
                index + 2,
            )

        # CIDR
        if "/" in token:
            try:
                network = ip_network(
                    token,
                    strict=False,
                )

                return str(network), index + 1

            except ValueError:
                pass

        # IP + netmask
        if index + 1 < len(tokens):
            candidate_ip = tokens[index]
            candidate_mask = tokens[index + 1]

            try:
                network = ip_network(
                    f"{candidate_ip}/{candidate_mask}",
                    strict=False,
                )

                return str(network), index + 2

            except ValueError:
                pass

        return None, index

    # -----------------------------------------------------------------
    # Port parsing
    # -----------------------------------------------------------------

    def _parse_ports(
        self,
        tokens: List[str],
        index: int,
        destination: List[int],
    ) -> int:

        if index >= len(tokens):
            return index

        operator = tokens[index].lower()

        if operator == "eq":
            index += 1

            while index < len(tokens):
                value = tokens[index]

                if value.lower() in {
                    "log",
                    "disable",
                    "remark",
                    "object",
                    "object-group",
                }:
                    break

                port = self._parse_port(value)

                if port is None:
                    break

                destination.append(port)
                index += 1

            return index

        if operator == "range":
            if index + 2 >= len(tokens):
                return len(tokens)

            start = self._parse_port(tokens[index + 1])
            end = self._parse_port(tokens[index + 2])

            if (
                start is not None
                and end is not None
                and start <= end
            ):
                for port in range(start, end + 1):
                    destination.append(port)

            return index + 3

        if operator == "lt":
            if index + 1 < len(tokens):
                port = self._parse_port(tokens[index + 1])

                if port is not None:
                    for value in range(1, port):
                        destination.append(value)

            return index + 2

        if operator == "gt":
            if index + 1 < len(tokens):
                port = self._parse_port(tokens[index + 1])

                if port is not None:
                    for value in range(port + 1, 65536):
                        destination.append(value)

            return index + 2

        if operator == "neq":
            return min(index + 2, len(tokens))

        return index

    # -----------------------------------------------------------------
    # Port names
    # -----------------------------------------------------------------

    @staticmethod
    def _parse_port(value: str) -> Optional[int]:
        value = value.lower()

        named_ports = {
            "ftp": 21,
            "ssh": 22,
            "telnet": 23,
            "smtp": 25,
            "dns": 53,
            "http": 80,
            "https": 443,
            "pop3": 110,
            "imap": 143,
            "snmp": 161,
            "ldap": 389,
            "ldaps": 636,
            "rdp": 3389,
        }

        if value in named_ports:
            return named_ports[value]

        try:
            port = int(value)

            if 0 <= port <= 65535:
                return port

        except ValueError:
            pass

        return None