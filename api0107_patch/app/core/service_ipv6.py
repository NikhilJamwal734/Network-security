"""API-010.7: bounded, conservative, upload-only IPv6/service-group correlation.

This module intentionally does not claim vendor-equivalent policy semantics. It never
reads paths, executes configuration directives, or changes prior security scores.
"""
from __future__ import annotations

from collections import Counter
import ipaddress
import re
import shlex
from typing import Any

PLATFORMS = frozenset({'cisco_asa', 'fortios', 'snort', 'suricata'})
MAX_LINES = 40_000
MAX_OBJECTS = 400
MAX_RULES = 100
MAX_PAIRS = 40
MAX_MEMBERS = 40
MAX_DEPTH = 10
MAX_NETWORKS = 128
MAX_PORTS = 64
Net = ipaddress.IPv4Network | ipaddress.IPv6Network
Service = tuple[str, int, int]  # protocol, inclusive destination range


def tokens(raw: str) -> list[str]:
    try:
        return shlex.split(raw.strip(), comments=True, posix=True)
    except ValueError:
        return []


def parse_net(raw: str, family: int) -> Net | None:
    try:
        net = ipaddress.ip_network(raw, strict=False)
    except ValueError:
        return None
    return net if net.version == family else None


def parse_port(raw: str) -> tuple[int, int] | None:
    if not re.fullmatch(r'[0-9]{1,5}(?:-[0-9]{1,5})?', raw):
        return None
    vals = [int(x) for x in raw.split('-')]
    low, high = vals[0], vals[-1]
    return (low, high) if 1 <= low <= high <= 65535 else None


def contain_nets(a: tuple[Net, ...], b: tuple[Net, ...]) -> bool:
    return bool(a and b) and all(any(x.subnet_of(y) for y in a) for x in b)


def overlap_nets(a: tuple[Net, ...], b: tuple[Net, ...]) -> bool:
    return any(x.overlaps(y) for x in a for y in b)


def contain_services(a: tuple[Service, ...], b: tuple[Service, ...]) -> bool:
    return bool(a and b) and all(any(p == q and low <= l and high >= h for q, low, high in a)
                                 for p, l, h in b)


def overlap_services(a: tuple[Service, ...], b: tuple[Service, ...]) -> bool:
    return any(p == q and max(l, low) <= min(h, high)
               for p, l, h in a for q, low, high in b)


def _compact_networks(values: list[Net]) -> tuple[Net, ...] | None:
    if not values or len(values) > MAX_NETWORKS:
        return None
    if len({net.version for net in values}) != 1:
        return None
    return tuple(ipaddress.collapse_addresses(values))


def _inventory(category: str, name: str, line: int, value: Any, reason: str) -> dict[str, Any]:
    if value is None:
        preview = None
    elif isinstance(value, tuple):
        preview = ', '.join(str(item) for item in value[:5])
    else:
        preview = str(value)[:180]
    return {'kind': category, 'name': name[:100], 'line_number': line,
            'status': 'resolved' if value is not None else 'unresolved',
            'value': preview, 'reason': reason}


def fortios(lines: list[str]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], int, list[str]]:
    limitations = [
        'FortiOS: service-group and IPv6 comparisons use only explicitly defined supported addresses, groups, and TCP/UDP destination ports.',
        'Only equal declared interface and schedule selectors are compared; negation, NAT, policy order, zones, central SNAT and effective reachability are not modeled.',
        'Unknown mutations, duplicate definitions, VDOMs, IPv6 dynamic/DNS objects and unsupported built-in services are excluded rather than guessed.',
    ]
    if any(re.match(r'^\s*config\s+vdom\b', line, re.I) for line in lines):
        return [], [], 0, limitations + ['VDOM configuration detected: this review is not assessed.']
    supported = {'firewall address', 'firewall addrgrp', 'firewall address6', 'firewall addrgrp6',
                 'firewall service custom', 'firewall service group', 'firewall policy', 'firewall policy6'}
    defs: dict[tuple[str, str], list[tuple[int, dict[str, list[str]]]]] = {}
    section: str | None = None
    current: dict[str, list[str]] | None = None
    seen_rules = 0
    nested = False
    for lineno, raw in enumerate(lines, 1):
        t = tokens(raw)
        if not t:
            continue
        key = t[0].lower()
        if key == 'config':
            if current is not None:
                current['__nested__'] = ['yes']
            section = ' '.join(s.lower() for s in t[1:])
            current = None
            nested = section not in supported
        elif key == 'edit' and len(t) == 2 and section in supported and not nested:
            current = {}
            defs.setdefault((section, t[1]), []).append((lineno, current))
            if section in ('firewall policy', 'firewall policy6'):
                seen_rules += 1
        elif key == 'set' and len(t) >= 3 and current is not None:
            k = t[1].lower()
            if k in current:
                current['__repeated_set__'] = ['yes']
            current[k] = t[2:]
        elif key in ('append', 'delete', 'unset', 'rename', 'move', 'clone') and current is not None:
            current['__mutation__'] = ['yes']
        elif key == 'next':
            current = None
        elif key == 'end':
            current = None
            section = None
            nested = False
    # Refuse the whole analysis when the definition cap is exceeded; otherwise
    # slicing definitions could turn real dependencies into apparently missing ones.
    if len(defs) > MAX_OBJECTS:
        return [], [], seen_rules, limitations + ['Object definition cap exceeded; all selectors unassessed.']

    def one(section: str, name: str) -> tuple[int, dict[str, list[str]]] | None:
        seq = defs.get((section, name), [])
        if len(seq) != 1 or any(k.startswith('__') for k in seq[0][1]):
            return None
        return seq[0]

    def resolve_addr(name: str, family: int, trail: tuple[str, ...] = ()) -> tuple[tuple[Net, ...], tuple[str, ...]] | None:
        if len(trail) >= MAX_DEPTH or name in trail:
            return None
        if name in ('all', 'all6'):
            return ((parse_net('::/0' if family == 6 else '0.0.0.0/0', family),), ())  # type: ignore[return-value]
        addr_kind = 'firewall address6' if family == 6 else 'firewall address'
        group_kind = 'firewall addrgrp6' if family == 6 else 'firewall addrgrp'
        if (addr_kind, name) in defs and (group_kind, name) in defs:
            return None
        record = one(addr_kind, name)
        if record:
            props = record[1]
            if family == 6:
                if props.get('type', ['ipprefix']) not in (['ipprefix'], ['ip6']):
                    return None
                val = props.get('ip6')
                if not val or len(val) != 1:
                    return None
                net = parse_net(val[0], family)
            else:
                if props.get('type', ['ipmask']) != ['ipmask']:
                    return None
                val = props.get('subnet')
                net = None
                if val and len(val) == 2:
                    try:
                        net = parse_net(f'{val[0]}/{val[1]}', family)
                    except ValueError:
                        pass
            return ((net,), (name,)) if net else None
        record = one(group_kind, name)
        if record:
            props = record[1]
            if props.get('exclude', ['disable']) != ['disable']:
                return None
            members = props.get('member', [])
            if not 1 <= len(members) <= MAX_MEMBERS:
                return None
            nets: list[Net] = []
            dependencies = [name]
            for member in members:
                res = resolve_addr(member, family, trail + (name,))
                if res is None:
                    return None
                nets.extend(res[0]); dependencies.extend(res[1])
                if len(nets) > MAX_NETWORKS:
                    return None
            result = _compact_networks(nets)
            return (result, tuple(dict.fromkeys(dependencies))) if result else None
        return None

    def resolve_service(name: str, trail: tuple[str, ...] = ()) -> tuple[tuple[Service, ...], tuple[str, ...]] | None:
        if len(trail) >= MAX_DEPTH or name in trail:
            return None
        if ('firewall service custom', name) in defs and ('firewall service group', name) in defs:
            return None
        record = one('firewall service custom', name)
        if record:
            props = record[1]
            allowed = {'protocol', 'tcp-portrange', 'udp-portrange', 'comment', 'category', 'color', 'visibility'}
            if any(key not in allowed for key in props):
                return None
            if props.get('protocol', ['TCP/UDP/SCTP']) not in (['TCP/UDP/SCTP'], ['TCP'], ['UDP']):
                return None
            services: list[Service] = []
            for key, protocol in (('tcp-portrange', 'tcp'), ('udp-portrange', 'udp')):
                ranges = props.get(key, [])
                if len(ranges) > MAX_PORTS:
                    return None
                for val in ranges:
                    port = parse_port(val)
                    if port is None:
                        return None
                    services.append((protocol, *port))
            if not services or len(services) > MAX_PORTS:
                return None
            if props.get('protocol') == ['TCP'] and any(x[0] != 'tcp' for x in services):
                return None
            if props.get('protocol') == ['UDP'] and any(x[0] != 'udp' for x in services):
                return None
            return (tuple(sorted(set(services))), (name,))
        record = one('firewall service group', name)
        if record:
            props = record[1]
            if any(key not in {'member', 'comment', 'color'} for key in props):
                return None
            members = props.get('member', [])
            if not 1 <= len(members) <= MAX_MEMBERS:
                return None
            aggregate: list[Service] = []
            dependencies: list[str] = [name]
            for member in members:
                result = resolve_service(member, trail + (name,))
                if result is None:
                    return None
                aggregate.extend(result[0]); dependencies.extend(result[1])
                if len(aggregate) > MAX_PORTS:
                    return None
            return (tuple(sorted(set(aggregate))), tuple(dict.fromkeys(dependencies)))
        # Built-in FortiOS service definitions not present in upload cannot be guessed.
        return None

    inventory: list[dict[str, Any]] = []
    for (category, name), seq in defs.items():
        if category in ('firewall policy', 'firewall policy6'):
            continue
        line = seq[0][0]
        result = None
        if category in ('firewall address', 'firewall addrgrp'):
            result = resolve_addr(name, 4)
        elif category in ('firewall address6', 'firewall addrgrp6'):
            result = resolve_addr(name, 6)
        elif category in ('firewall service custom', 'firewall service group'):
            result = resolve_service(name)
        inventory.append(_inventory(category.replace(' ', '_'), name, line, result[0] if result else None,
                                    'supported_expansion' if result else 'unresolved_or_unsupported'))

    policies: list[dict[str, Any]] = []
    for (category, name), seq in defs.items():
        if category not in ('firewall policy', 'firewall policy6') or len(policies) >= MAX_RULES:
            continue
        record = one(category, name)
        if record is None:
            continue
        line, props = record
        family = 6 if category == 'firewall policy6' else 4
        if props.get('status', ['enable']) != ['enable']:
            continue
        if props.get('action') not in (['accept'], ['deny']):
            continue
        if any(props.get(k) == ['enable'] for k in ('srcaddr-negate', 'dstaddr-negate', 'srcaddr6-negate', 'dstaddr6-negate', 'service-negate')):
            continue
        if props.get('internet-service', ['disable']) != ['disable'] or 'internet-service-id' in props:
            continue
        keys = ('srcaddr6', 'dstaddr6') if family == 6 else ('srcaddr', 'dstaddr')
        required = ('srcintf', 'dstintf', 'service', 'schedule', *keys)
        if any(not props.get(k) for k in required):
            continue
        if not 1 <= len(props['service']) <= MAX_MEMBERS:
            continue
        src: list[Net] = []; dst: list[Net] = []; services: list[Service] = []; dependencies: list[str] = []
        okay = True
        for prop, dstlist in ((keys[0], src), (keys[1], dst)):
            for member in props[prop]:
                resolved = resolve_addr(member, family)
                if resolved is None:
                    okay = False; break
                dstlist.extend(resolved[0]); dependencies.extend(resolved[1])
                if len(dstlist) > MAX_NETWORKS:
                    okay = False; break
            if not okay:
                break
        if not okay:
            continue
        for member in props['service']:
            res = resolve_service(member)
            if res is None:
                okay = False; break
            services.extend(res[0]); dependencies.extend(res[1])
            if len(services) > MAX_PORTS:
                okay = False; break
        if not okay:
            continue
        nsrc = _compact_networks(src); ndst = _compact_networks(dst)
        if nsrc is None or ndst is None:
            continue
        scope = ('|'.join(sorted(props['srcintf'])), '|'.join(sorted(props['dstintf'])),
                 '|'.join(sorted(props['schedule'])))
        policies.append({'line': line, 'id': name, 'family': family, 'action': props['action'][0],
                         'src': nsrc, 'dst': ndst, 'services': tuple(sorted(set(services))),
                         'scope': scope, 'dependencies': tuple(dict.fromkeys(dependencies))})
    return inventory, policies, seen_rules, limitations


def asa(lines: list[str]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], int, list[str]]:
    limitations = [
        'Cisco ASA: supports a single IPv6 host or prefix per named network object and numeric TCP/UDP destination ports in extended ACLs.',
        'ASA IPv4 objects, object groups, service groups, interface bindings, NAT and effective ACL order are outside this IPv6 review.',
        'Only candidates within the same named ACL are compared; matching ACL text does not establish actual forwarding or exposure.',
    ]
    defs: dict[str, list[tuple[int, list[str]]]] = {}
    active: str | None = None
    for line, raw in enumerate(lines, 1):
        s = raw.strip()
        if not s or s.startswith(('!', '#')):
            continue
        t = s.split()
        if len(t) == 3 and t[:2] == ['object', 'network']:
            active = t[2]
            defs.setdefault(active, []).append((line, []))
        elif active and raw[:1].isspace() and t[0] in ('host', 'subnet', 'range', 'description', 'nat', 'fqdn'):
            defs[active][-1][1].append(s)
        else:
            active = None
    if len(defs) > MAX_OBJECTS:
        return [], [], 0, limitations + ['Object cap exceeded; no ASA IPv6 comparisons made.']
    resolved: dict[str, Net] = {}
    inventory: list[dict[str, Any]] = []
    for name, seq in defs.items():
        value: Net | None = None
        if len(seq) == 1:
            entries = [x.split() for x in seq[0][1] if not x.lower().startswith('description ')]
            if len(entries) == 1:
                entry = entries[0]
                if len(entry) == 2 and entry[0] == 'host':
                    value = parse_net(entry[1] + '/128', 6)
                elif len(entry) == 2 and entry[0] == 'subnet':
                    value = parse_net(entry[1], 6)
        if value:
            resolved[name] = value
        inventory.append(_inventory('asa_ipv6_network', name, seq[0][0], (value,) if value else None,
                                    'supported_ipv6_single_network' if value else 'not_supported_or_ambiguous'))

    def read_addr(words: list[str], index: int) -> tuple[tuple[Net, ...], int, tuple[str, ...]] | None:
        if index >= len(words):
            return None
        word = words[index].lower()
        if word == 'any6':
            return ((parse_net('::/0', 6),), index + 1, ())  # type: ignore[return-value]
        if word == 'host' and index + 1 < len(words):
            value = parse_net(words[index + 1] + '/128', 6)
            return ((value,), index + 2, ()) if value else None
        if word == 'object' and index + 1 < len(words):
            name = words[index + 1]
            return ((resolved[name],), index + 2, (name,)) if name in resolved else None
        value = parse_net(words[index], 6)
        return ((value,), index + 1, ()) if value else None

    def read_ports(words: list[str], index: int) -> tuple[tuple[Service, ...], int] | None:
        if index == len(words):
            return (('tcp', 0, 65535),), index
        key = words[index].lower()
        if key not in ('eq', 'range'):
            return (('tcp', 0, 65535),), index
        need = 1 if key == 'eq' else 2
        vals = words[index + 1:index + 1 + need]
        if len(vals) != need or any(not val.isdecimal() for val in vals):
            return None
        low, high = int(vals[0]), int(vals[-1])
        return ((('tcp', low, high),), index + 1 + need) if 1 <= low <= high <= 65535 else None

    rules: list[dict[str, Any]] = []
    attempted = 0
    for lineno, raw in enumerate(lines, 1):
        t = raw.strip().split()
        if len(t) < 7 or t[0].lower() != 'access-list' or t[1].lower() == 'remark':
            continue
        attempted += 1
        if len(rules) >= MAX_RULES:
            continue
        pos = 2; order = None
        if t[pos].lower() == 'line' and len(t) > pos + 1 and t[pos + 1].isdecimal():
            order = int(t[pos + 1]); pos += 2
        if len(t) < pos + 5 or t[pos].lower() != 'extended':
            continue
        action, protocol = t[pos + 1].lower(), t[pos + 2].lower()
        if action not in ('permit', 'deny') or protocol not in ('tcp', 'udp'):
            continue
        pos += 3
        src = read_addr(t, pos)
        if src is None:
            continue
        snet, pos, srefs = src
        dst = read_addr(t, pos)
        if dst is None:
            continue
        dnet, pos, drefs = dst
        port = read_ports(t, pos)
        if port is None:
            continue
        services, pos = port
        if pos != len(t):
            continue  # extra rule options / unsupported grammar
        rules.append({'line': lineno, 'id': t[1], 'family': 6, 'action': action,
                      'src': snet, 'dst': dnet,
                      'services': ((protocol, services[0][1], services[0][2]),),
                      'scope': (t[1],), 'order': order,
                      'dependencies': tuple(dict.fromkeys(srefs + drefs))})
    return inventory, rules, attempted, limitations


def review_service_ipv6(platform: str, source: str, *, source_truncated: bool = False) -> dict[str, Any]:
    """Returns supplemental evidence; never changes prior report fields or scores."""
    if platform not in PLATFORMS:
        raise ValueError(f'Unsupported platform {platform}')
    if not isinstance(source, str):
        raise TypeError('Source must be UTF-8 text')
    original = source.splitlines()
    incomplete = source_truncated or len(original) > MAX_LINES
    lines = original[:MAX_LINES]
    if platform == 'fortios':
        inventory, rules, seen, limits = fortios(lines)
        if any('VDOM' in x or 'cap exceeded' in x for x in limits):
            incomplete = True
    elif platform == 'cisco_asa':
        inventory, rules, seen, limits = asa(lines)
    else:
        inventory, rules, seen = [], [], 0
        limits = ['IDS variable expansion and rule includes are outside this milestone; existing Snort/Suricata findings remain available in the prior report.']

    candidates: list[dict[str, Any]] = []
    pairs_skipped = 0
    # A single input may contain many policies; compare at most MAX_RULES.
    for i, left in enumerate(rules):
        for right in rules[i + 1:]:
            if left['family'] != right['family'] or left['scope'] != right['scope']:
                continue
            if not (overlap_nets(left['src'], right['src']) and overlap_nets(left['dst'], right['dst'])
                    and overlap_services(left['services'], right['services'])):
                continue
            if len(candidates) >= MAX_PAIRS:
                pairs_skipped += 1
                continue
            left_contains = (contain_nets(left['src'], right['src'])
                             and contain_nets(left['dst'], right['dst'])
                             and contain_services(left['services'], right['services']))
            right_contains = (contain_nets(right['src'], left['src'])
                              and contain_nets(right['dst'], left['dst'])
                              and contain_services(right['services'], left['services']))
            if left['action'] != right['action']:
                kind = 'opposite_action_containment' if left_contains or right_contains else 'opposite_action_overlap'
            else:
                kind = 'same_action_containment' if left_contains or right_contains else 'selector_overlap'
            explicit_order = 'not_assessed'
            if platform == 'cisco_asa' and left.get('order') is not None and right.get('order') is not None:
                if left['order'] != right['order']:
                    explicit_order = 'explicit_sequence_available'
            candidates.append({
                'reference': f'SG6-{len(candidates) + 1:03}', 'kind': kind,
                'confidence': 'resolved_selectors_conditional', 'ip_version': left['family'],
                'related_rule_id': left['id'], 'rule_id': right['id'],
                'related_line_number': left['line'], 'line_number': right['line'],
                'resolved_objects': list(dict.fromkeys(left['dependencies'] + right['dependencies']))[:24],
                'order_status': explicit_order,
                'explanation': ('Supported address networks and TCP/UDP destination-port selectors intersect. '
                                'Effective device ordering, routing, NAT, zones and runtime traffic are not verified.'),
                'recommendation': ('Review both source rules and resolved object definitions; verify effective '
                                   'policy order and bindings before changing either configuration entry.'),
            })
    definitions_resolved = sum(item['status'] == 'resolved' for item in inventory)
    truncation = (incomplete or len(rules) >= MAX_RULES and seen > len(rules) or pairs_skipped > 0)
    not_assessed = platform in ('snort', 'suricata')
    if truncation:
        limits.append('Source or processing caps were reached. Findings are partial; no absence conclusion is supported.')
    return {
        'version': '1.0', 'platform_id': platform,
        'scope': 'static_bounded_service_group_ipv6_evidence',
        'status': 'not_assessed' if not_assessed else ('limited' if truncation else 'reviewed_subset'),
        'summary': {'definitions_seen': len(inventory), 'definitions_resolved': definitions_resolved,
                    'definitions_unresolved': len(inventory) - definitions_resolved,
                    'rules_seen': seen, 'rules_eligible': len(rules),
                    'rules_not_assessed': max(0, seen - len(rules)),
                    'correlation_candidates': len(candidates), 'candidates_omitted': pairs_skipped,
                    'incomplete': truncation},
        'objects': inventory[:120], 'pairs': candidates,
        'limitations': limits,
    }
