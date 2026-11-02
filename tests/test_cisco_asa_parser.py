from app.parsers.firewalls.cisco_asa import CiscoASAParser


def parse_config(config: str):
    parser = CiscoASAParser()
    return parser.parse(config.splitlines())


def test_parses_hostname():
    firewall = parse_config(
        """
        hostname TEST-ASA
        """
    )

    assert firewall.hostname == "TEST-ASA"


def test_parses_interface():
    firewall = parse_config(
        """
        interface GigabitEthernet0/0
         nameif outside
         description Internet interface
         ip address 203.0.113.1 255.255.255.0
        """
    )

    interface = firewall.interfaces["GigabitEthernet0/0"]

    assert interface.security_zone == "outside"
    assert interface.description == "Internet interface"
    assert interface.ip_address == "203.0.113.1"
    assert interface.enabled is True


def test_parses_shutdown_interface():
    firewall = parse_config(
        """
        interface GigabitEthernet0/1
         nameif inside
         shutdown
        """
    )

    interface = firewall.interfaces["GigabitEthernet0/1"]

    assert interface.security_zone == "inside"
    assert interface.enabled is False


def test_parses_network_object_host():
    firewall = parse_config(
        """
        object network WEB_SERVER
         host 10.10.10.10
        """
    )

    assert "WEB_SERVER" in firewall.networks

    network = firewall.networks["WEB_SERVER"]

    assert len(network.networks) == 1
    assert str(network.networks[0]) == "10.10.10.10/32"


def test_parses_network_object_subnet():
    firewall = parse_config(
        """
        object network INSIDE_NET
         subnet 10.10.10.0 255.255.255.0
        """
    )

    network = firewall.networks["INSIDE_NET"]

    assert len(network.networks) == 1
    assert str(network.networks[0]) == "10.10.10.0/24"


def test_parses_network_object_group():
    firewall = parse_config(
        """
        object-group network SERVERS
         network-object host 10.10.10.10
         network-object 10.10.20.0 255.255.255.0
        """
    )

    group = firewall.networks["SERVERS"]

    assert len(group.networks) == 2
    assert "10.10.10.10/32" in {
        str(network)
        for network in group.networks
    }
    assert "10.10.20.0/24" in {
        str(network)
        for network in group.networks
    }


def test_parses_nested_network_object_group():
    firewall = parse_config(
        """
        object-group network SERVERS
         network-object host 10.10.10.10

        object-group network APPLICATIONS
         group-object SERVERS
         network-object host 10.10.20.10
        """
    )

    group = firewall.networks["APPLICATIONS"]

    assert "SERVERS" in group.group_references
    assert len(group.networks) == 1
    assert str(group.networks[0]) == "10.10.20.10/32"


def test_parses_service_object():
    firewall = parse_config(
        """
        object service HTTPS
         service tcp destination eq 443
        """
    )

    service = firewall.services["HTTPS"]

    assert service.protocol == "tcp"
    assert 443 in service.ports


def test_parses_service_object_group():
    firewall = parse_config(
        """
        object-group service WEB_SERVICES tcp
         port-object eq 80
         port-object eq 443
        """
    )

    service = firewall.services["WEB_SERVICES"]

    assert 80 in service.ports
    assert 443 in service.ports


def test_parses_service_port_range():
    firewall = parse_config(
        """
        object-group service WEB_PORTS tcp
         port-object range 8000 8002
        """
    )

    service = firewall.services["WEB_PORTS"]

    assert 8000 in service.ports
    assert 8001 in service.ports
    assert 8002 in service.ports


def test_parses_acl_any_to_any():
    firewall = parse_config(
        """
        access-list OUTSIDE extended permit ip any any
        """
    )

    assert len(firewall.rules) == 1

    rule = firewall.rules[0]

    assert rule.name == "OUTSIDE"
    assert rule.action == "permit"
    assert rule.protocol == "ip"
    assert rule.source == ["any"]
    assert rule.destination == ["any"]


def test_parses_acl_host_to_host():
    firewall = parse_config(
        """
        access-list OUTSIDE extended permit tcp host 10.10.10.10 host 203.0.113.10 eq 443
        """
    )

    rule = firewall.rules[0]

    assert rule.protocol == "tcp"
    assert rule.source == ["host:10.10.10.10"]
    assert rule.destination == ["host:203.0.113.10"]
    assert rule.destination_ports == [443]


def test_parses_acl_network_to_network():
    firewall = parse_config(
        """
        access-list INSIDE extended permit ip 10.10.10.0 255.255.255.0 10.20.20.0 255.255.255.0
        """
    )

    rule = firewall.rules[0]

    assert rule.source == ["10.10.10.0/24"]
    assert rule.destination == ["10.20.20.0/24"]


def test_parses_acl_object_and_object_group():
    firewall = parse_config(
        """
        access-list OUTSIDE extended permit tcp object WEB_SERVER object-group WEB_SERVERS eq 443
        """
    )

    rule = firewall.rules[0]

    assert rule.source == ["object:WEB_SERVER"]
    assert rule.destination == ["object-group:WEB_SERVERS"]
    assert rule.destination_ports == [443]


def test_parses_acl_logging():
    firewall = parse_config(
        """
        access-list OUTSIDE extended deny tcp any any eq 23 log
        """
    )

    rule = firewall.rules[0]

    assert rule.action == "deny"
    assert rule.destination_ports == [23]
    assert rule.logging is True


def test_parses_acl_disabled_rule():
    firewall = parse_config(
        """
        access-list OUTSIDE extended permit tcp any any eq 443 disable
        """
    )

    rule = firewall.rules[0]

    assert rule.disabled is True


def test_parses_acl_named_ports():
    firewall = parse_config(
        """
        access-list OUTSIDE extended permit tcp any any eq https ssh
        """
    )

    rule = firewall.rules[0]

    assert 443 in rule.destination_ports
    assert 22 in rule.destination_ports


def test_parses_acl_port_range():
    firewall = parse_config(
        """
        access-list OUTSIDE extended permit tcp any any range 8000 8002
        """
    )

    rule = firewall.rules[0]

    assert rule.destination_ports == [
        8000,
        8001,
        8002,
    ]


def test_parses_route():
    firewall = parse_config(
        """
        route outside 0.0.0.0 0.0.0.0 203.0.113.254 1
        """
    )

    assert len(firewall.routes) == 1

    route = firewall.routes[0]

    assert route.interface == "outside"
    assert route.destination == "0.0.0.0/0"
    assert route.next_hop == "203.0.113.254"
    assert route.metric == 1


def test_parses_static_nat():
    firewall = parse_config(
        """
        object network WEB_SERVER
         host 10.10.10.10
         nat (inside,outside) static 203.0.113.10
        """
    )

    assert len(firewall.nat_rules) == 1

    nat_rule = firewall.nat_rules[0]

    assert nat_rule.source == "object:WEB_SERVER"
    assert nat_rule.translated_source == "203.0.113.10"