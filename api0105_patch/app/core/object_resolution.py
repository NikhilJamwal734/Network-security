"""API-010.5: limited IPv4 object expansion for advisory policy comparison.

Security properties: no I/O, no object execution or network access, bounded complexity,
no guessed built-ins / implicit policy semantics, and no modifications to prior report.
Only explicitly supported ASA and FortiOS grammar is considered for expanded pairs.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import ipaddress
import re
import shlex
from typing import Any

MAX_LINES = 50_000
MAX_RULES = 120
MAX_DEFINITIONS = 350
MAX_PAIRS = 60
MAX_EXPORTED_OBJECTS = 70
MAX_RECURSION = 12
SUPPORTED = frozenset(('cisco_asa', 'fortios', 'snort', 'suricata'))

Net = ipaddress.IPv4Network
Port = tuple[int, int]


def _network(address: str, mask: str | None = None) -> Net | None:
    try:
        if mask is None:
            out = ipaddress.ip_network(address, strict=False)
        else:
            # IPv4Network rejects noncontiguous masks; don't reinterpret them.
            out = ipaddress.IPv4Network(f'{address}/{mask}', strict=False)
        return out if isinstance(out, ipaddress.IPv4Network) else None
    except ValueError:
        return None


def _tokens(raw: str) -> list[str]:
    try:
        return shlex.split(raw.strip(), comments=False, posix=True)
    except ValueError:
        return []


def _ports(words: list[str], i: int) -> tuple[Port, int] | None:
    if i >= len(words) or words[i].lower() not in ('eq', 'range'):
        return (0, 65535), i
    n = 1 if words[i].lower() == 'eq' else 2
    values = words[i + 1:i + 1 + n]
    if len(values) != n or not all(re.fullmatch(r'\d{1,5}', x) for x in values):
        return None
    lo, hi = int(values[0]), int(values[-1])
    if not (0 <= lo <= hi <= 65535):
        return None
    return (lo, hi), i + 1 + n


def _net_contains(left: tuple[Net, ...], right: tuple[Net, ...]) -> bool:
    return all(any(b.subnet_of(a) for a in left) for b in right)


def _net_overlaps(left: tuple[Net, ...], right: tuple[Net, ...]) -> bool:
    return any(a.overlaps(b) for a in left for b in right)


def _port_contains(left: Port, right: Port) -> bool:
    return left[0] <= right[0] and left[1] >= right[1]


def _port_overlaps(left: Port, right: Port) -> bool:
    return max(left[0], right[0]) <= min(left[1], right[1])


@dataclass(frozen=True)
class Selector:
    line: int
    identifier: str
    action: str
    protocol: str
    source: tuple[Net, ...]
    destination: tuple[Net, ...]
    source_ports: Port
    destination_ports: Port
    order: int | None = None
    scope: str = ''
    dependencies: tuple[str, ...] = ()


def _contains(a: Selector, b: Selector) -> bool:
    protocol = a.protocol == b.protocol or a.protocol == 'ip' and b.protocol in ('tcp', 'udp', 'icmp')
    return (protocol and _net_contains(a.source, b.source) and _net_contains(a.destination, b.destination)
            and _port_contains(a.source_ports, b.source_ports)
            and _port_contains(a.destination_ports, b.destination_ports))


def _overlaps(a: Selector, b: Selector) -> bool:
    protocol = a.protocol == b.protocol or 'ip' in (a.protocol, b.protocol)
    return (protocol and _net_overlaps(a.source, b.source) and _net_overlaps(a.destination, b.destination)
            and _port_overlaps(a.source_ports, b.source_ports)
            and _port_overlaps(a.destination_ports, b.destination_ports))


def _pair(a: Selector, b: Selector, platform: str) -> dict[str, Any]:
    forward = a.order is not None and b.order is not None and a.order < b.order
    backward = a.order is not None and b.order is not None and a.order > b.order
    if a.action == b.action and _contains(a, b):
        kind = 'redundancy_candidate'
    elif a.action != b.action and _contains(a, b):
        kind = 'shadowing_candidate' if platform == 'cisco_asa' else 'opposite_action_containment'
    elif a.action != b.action:
        kind = 'opposite_action_overlap'
    else:
        kind = 'selector_overlap'
    order = 'explicit_sequence_supports_order' if forward else ('explicit_sequence_reverses_order' if backward else 'unverified')
    return {
        'kind': kind, 'confidence': 'resolved_selectors_conditional',
        'order_status': order if platform == 'cisco_asa' else 'unverified',
        'explanation': ('Explicit supported IPv4 selectors overlap after named-object expansion. '
                        'Effective ordering, policy attachment and actual network behavior are not established.'),
        'recommendation': 'Verify effective policy order, bindings, object scope and intended access before editing either rule.',
        'evidence': {'related_line_number': a.line, 'line_number': b.line,
                     'related_rule_id': a.identifier, 'rule_id': b.identifier},
        'resolved_object_references': list(dict.fromkeys(a.dependencies + b.dependencies))[:16],
    }


def _asa(lines: list[str]) -> tuple[list[dict[str, Any]], list[Selector], int, int, list[str]]:
    rawdefs: dict[str, list[tuple[int, list[str]]]] = {}
    active: str | None = None
    # Only definitions from a single `object network NAME` block are trusted.
    for i, raw in enumerate(lines, 1):
        s = raw.strip()
        if not s or s.startswith(('!', '#')):
            continue
        t = s.split()
        if len(t) == 3 and t[0:2] == ['object', 'network']:
            active = t[2]
            rawdefs.setdefault(active, []).append((i, []))
        elif active and (raw[:1].isspace() and t[0] in ('host', 'subnet', 'range', 'fqdn', 'description', 'nat')):
            rawdefs[active][-1][1].append(s)
        else:
            active = None
    records: dict[str, tuple[Net, int] | None] = {}
    objects: list[dict[str, Any]] = []
    for name, definitions in list(rawdefs.items())[:MAX_DEFINITIONS]:
        line = definitions[0][0]
        value: tuple[Net, int] | None = None
        reason = 'unsupported_or_ambiguous_definition'
        if len(definitions) == 1:
            entries = [x.split() for x in definitions[0][1] if not x.lower().startswith('description ')]
            if len(entries) == 1:
                row = entries[0]
                net: Net | None = None
                if len(row) == 2 and row[0] == 'host':
                    net = _network(row[1] + '/32')
                elif len(row) == 3 and row[0] == 'subnet':
                    net = _network(row[1], row[2])
                if net is not None:
                    value = (net, line)
                    reason = 'resolved_single_ipv4_network'
        records[name] = value
        objects.append({'name': name[:100], 'kind': 'asa_network', 'line_number': line,
                        'status': 'resolved' if value else 'unresolved', 'reason': reason,
                        'value': str(value[0]) if value else None})
    def read_net(words: list[str], i: int) -> tuple[tuple[Net, ...], int, tuple[str, ...]] | None:
        if i >= len(words): return None
        word = words[i].lower()
        if word in ('any', 'any4'):
            return (_network('0.0.0.0/0'),), i + 1, ()  # type: ignore[return-value]
        if word == 'host' and i + 1 < len(words):
            net = _network(words[i + 1] + '/32')
            return ((net,), i + 2, ()) if net else None
        if word == 'object' and i + 1 < len(words):
            label = words[i + 1]
            value = records.get(label)
            return ((value[0],), i + 2, (label,)) if value else None
        if i + 1 < len(words):
            net = _network(words[i], words[i + 1])
            return ((net,), i + 2, ()) if net else None
        return None
    rules: list[Selector] = []
    attempted = 0
    for line, raw in enumerate(lines, 1):
        words = raw.strip().split()
        if len(words) < 7 or words[0].lower() != 'access-list' or words[1].lower() == 'remark':
            continue
        attempted += 1
        if len(rules) >= MAX_RULES: continue
        name = words[1]
        index = 2
        order = None
        if len(words) > index + 1 and words[index].lower() == 'line':
            if not re.fullmatch(r'\d{1,6}', words[index + 1]): continue
            order = int(words[index + 1]); index += 2
        if len(words) <= index + 2 or words[index].lower() != 'extended': continue
        action, protocol = words[index + 1].lower(), words[index + 2].lower()
        if action not in ('permit', 'deny') or protocol not in ('ip', 'tcp', 'udp', 'icmp'): continue
        index += 3
        src = read_net(words, index)
        if src is None: continue
        src_net, index, deps_a = src
        src_port = (0, 65535)
        if protocol in ('tcp', 'udp'):
            port = _ports(words, index)
            if port is None: continue
            src_port, index = port
        dst = read_net(words, index)
        if dst is None: continue
        dst_net, index, deps_b = dst
        dst_port = (0, 65535)
        if protocol in ('tcp', 'udp'):
            port = _ports(words, index)
            if port is None: continue
            dst_port, index = port
        rem = [w.lower() for w in words[index:]]
        if rem and (rem[0] != 'log' or rem[1:] not in ([], ['disable'], ['default'], ['informational'], ['warnings'])):
            continue
        rules.append(Selector(line, name, action, protocol, src_net, dst_net, src_port, dst_port,
                              order, name, deps_a + deps_b))
    return objects, rules, attempted, len(rawdefs), [
        'ASA: only a single host/subnet IPv4 entry per named network object is expanded; ranges, groups, NAT and service aliases are excluded.',
        'ASA object definitions and ACL declarations must be in the uploaded file; live effective device state is not inferred.',
    ]


def _fortios(lines: list[str]) -> tuple[list[dict[str, Any]], list[Selector], int, int, list[str]]:
    # Conservative: nested config, VDOMs and duplicate definitions are not silently joined.
    if any(re.match(r'^\s*config\s+vdom\b', line, re.I) for line in lines):
        return [], [], 0, 0, ['FortiOS VDOM blocks are not resolved by API-010.5; supply a scoped configuration and verify VDOM context.']
    sections = {'firewall address', 'firewall addrgrp', 'firewall service custom',
                'firewall service group', 'firewall policy'}
    definitions: dict[tuple[str, str], list[tuple[int, dict[str, list[str]]]]] = {}
    section: str | None = None
    current: tuple[str, int, dict[str, list[str]]] | None = None
    attempted = 0
    for line_no, raw in enumerate(lines, 1):
        words = _tokens(raw)
        if not words or words[0].startswith('#'): continue
        key = words[0].lower()
        if key == 'config':
            if current is not None:
                # Nested sections (e.g. dynamic mappings) invalidate containing record.
                current[2]['__unsupported_nested__'] = ['yes']
            section = ' '.join(word.lower() for word in words[1:])
            if section not in sections: section = None
            current = None
        elif key == 'edit' and len(words) == 2 and section:
            current = (words[1], line_no, {})
            definitions.setdefault((section, words[1]), []).append((line_no, current[2]))
            if section == 'firewall policy': attempted += 1
        elif key == 'set' and len(words) >= 3 and current is not None:
            current[2][words[1].lower()] = words[2:]
        elif key in ('unset', 'append', 'delete') and current is not None:
            current[2]['__unsupported_mutation__'] = ['yes']
        elif key == 'next':
            current = None
        elif key == 'end':
            current = None
            section = None
    inventory: list[dict[str, Any]] = []
    flattened: dict[str, dict[str, tuple[tuple[Net, ...], tuple[str, ...]] | None]] = {'address': {}, 'addrgrp': {}}
    a_defs = {k[1]: v for k, v in definitions.items() if k[0] == 'firewall address'}
    g_defs = {k[1]: v for k, v in definitions.items() if k[0] == 'firewall addrgrp'}
    service_defs = {k[1]: v for k, v in definitions.items() if k[0] == 'firewall service custom'}
    service_groups = {k[1]: v for k, v in definitions.items() if k[0] == 'firewall service group'}
    # Duplicate object definitions treated as unresolved rather than applying unknown edit semantics.
    def resolve_addr(name: str, chain: tuple[str, ...] = ()) -> tuple[tuple[Net, ...], tuple[str, ...]] | None:
        if name == 'all':
            net = _network('0.0.0.0/0')
            return ((net,), ()) if net else None
        if name in chain or len(chain) >= MAX_RECURSION: return None
        if name in a_defs and name in g_defs: return None  # Ambiguous namespace; do not guess.
        if name in a_defs:
            seq = a_defs[name]
            if len(seq) != 1: return None
            props = seq[0][1]
            if any(key.startswith('__') for key in props): return None
            if props.get('type', ['ipmask']) != ['ipmask']: return None
            subnet = props.get('subnet')
            if not subnet or len(subnet) != 2: return None
            net = _network(subnet[0], subnet[1])
            return ((net,), (name,)) if net else None
        if name in g_defs:
            seq = g_defs[name]
            if len(seq) != 1 or any(k.startswith('__') for k in seq[0][1]): return None
            props = seq[0][1]
            if props.get('exclude', ['disable']) != ['disable']: return None
            members = props.get('member', [])
            if not members or len(members) > 35: return None
            nets: list[Net] = []
            dependencies: list[str] = [name]
            for member in members:
                resolved = resolve_addr(member, chain + (name,))
                if resolved is None: return None
                nets.extend(resolved[0])
                dependencies.extend(resolved[1])
                if len(nets) > 128: return None
            return tuple(ipaddress.collapse_addresses(nets)), tuple(dict.fromkeys(dependencies))
        return None
    def parse_port(value: str) -> Port | None:
        if not re.fullmatch(r'\d{1,5}(?:-\d{1,5})?', value): return None
        parts = [int(x) for x in value.split('-')]
        lo, hi = parts[0], parts[-1]
        return (lo, hi) if 1 <= lo <= hi <= 65535 else None
    def resolve_service(name: str) -> tuple[str, Port, tuple[str, ...]] | None:
        if name in service_groups: return None  # protocol/set semantics intentionally not modeled
        seq = service_defs.get(name)
        if not seq or len(seq) != 1: return None
        props = seq[0][1]
        if any(k.startswith('__') for k in props): return None
        # Limit to a single TCP destination range, no custom source-port constraints.
        if props.get('protocol', ['TCP/UDP/SCTP']) not in (['TCP/UDP/SCTP'], ['TCP']): return None
        if 'udp-portrange' in props or 'sctp-portrange' in props: return None
        spec = props.get('tcp-portrange')
        if not spec or len(spec) != 1: return None
        port = parse_port(spec[0])
        return ('tcp', port, (name,)) if port is not None else None
    # Export bounded definitions with ground-truth statuses and source lines.
    for (category, name), seq in list(definitions.items())[:MAX_DEFINITIONS]:
        if category not in ('firewall address', 'firewall addrgrp', 'firewall service custom', 'firewall service group'):
            continue
        if category in ('firewall address', 'firewall addrgrp'):
            resolved = resolve_addr(name)
            value = ', '.join(str(x) for x in resolved[0][:5]) if resolved else None
        else:
            service = resolve_service(name) if category == 'firewall service custom' else None
            resolved = service
            value = f'{service[0]}:{service[1][0]}-{service[1][1]}' if service else None
        inventory.append({'name': name[:100], 'kind': category.replace(' ', '_'),
                          'line_number': seq[0][0], 'status': 'resolved' if resolved else 'unresolved',
                          'reason': 'supported_subset' if resolved else 'unsupported_or_ambiguous_definition',
                          'value': value})
    rules: list[Selector] = []
    for (category, name), seq in definitions.items():
        if category != 'firewall policy' or len(seq) != 1 or len(rules) >= MAX_RULES: continue
        line, props = seq[0]
        if any(k.startswith('__') for k in props): continue
        if props.get('status', ['enable']) != ['enable']: continue
        action = props.get('action', [])
        if len(action) != 1 or action[0] not in ('accept', 'deny'): continue
        required = ('srcintf', 'dstintf', 'srcaddr', 'dstaddr', 'service', 'schedule')
        if any(not props.get(k) for k in required): continue
        # Reject negated selectors, invalid IP family and unsupported selector modifiers.
        if any(props.get(k) == ['enable'] for k in ('srcaddr-negate', 'dstaddr-negate', 'service-negate')): continue
        if 'internet-service' in props or 'internet-service-id' in props: continue
        if props.get('internet-service', ['disable']) != ['disable']: continue
        if len(props['service']) != 1: continue
        s = resolve_service(props['service'][0])
        if s is None: continue
        src: list[Net] = []; dst: list[Net] = []; names: list[str] = list(s[2]); ok = True
        for key, target in (('srcaddr', src), ('dstaddr', dst)):
            for ref in props[key]:
                val = resolve_addr(ref)
                if val is None: ok = False; break
                target.extend(val[0]); names.extend(val[1])
                if len(target) > 128: ok = False; break
            if not ok: break
        if not ok or not src or not dst: continue
        # Record conservative comparison context; no conversion of named interfaces to interface roles.
        scope = (','.join(sorted(props['srcintf'])) + '->' + ','.join(sorted(props['dstintf']))
                 + '|' + ','.join(sorted(props['schedule'])))
        rules.append(Selector(line, name, action[0], s[0],
                              tuple(ipaddress.collapse_addresses(src)), tuple(ipaddress.collapse_addresses(dst)),
                              (0, 65535), s[1], None, scope, tuple(dict.fromkeys(names))))
    return inventory, rules, attempted, len(definitions), [
        'FortiOS: supports explicit IPv4 subnet address objects, non-exclusion address groups and simple TCP-only custom services.',
        'VDOMs, VIPs, NAT, address exclusion, IP pools, FQDN/geography, nested configuration edits and service groups are not resolved.',
        'Policy comparisons require equal explicit interfaces/schedules. Effective FortiOS policy priority/order and session processing are unverified.',
    ]


def resolve_and_compare(platform: str, source: str, *, source_truncated: bool = False) -> dict[str, Any]:
    """Standalone additive API-010.5 report; never alters or upgrades prior findings."""
    if platform not in SUPPORTED: raise ValueError('Unsupported platform')
    if not isinstance(source, str): raise TypeError('Source must be text')
    original = source.splitlines()
    capped_lines = len(original) > MAX_LINES
    lines = original[:MAX_LINES]
    if platform == 'cisco_asa':
        inventory, selectors, attempted, definition_count, limits = _asa(lines)
    elif platform == 'fortios':
        inventory, selectors, attempted, definition_count, limits = _fortios(lines)
    else:
        inventory, selectors, attempted, definition_count = [], [], 0, 0
        limits = [f'{platform.capitalize()}: IDS variables, include files, rule options and engine behavior are not resolved by this network-object analysis.',
                  'The existing API-010.3 IDS header correlation remains advisory.']
    pairs: list[dict[str, Any]] = []
    for later_idx, b in enumerate(selectors):
        for a in selectors[:later_idx]:
            if platform == 'cisco_asa' and (a.scope != b.scope or not (a.dependencies or b.dependencies)): continue
            if platform == 'fortios' and a.scope != b.scope: continue
            if not _overlaps(a, b): continue
            result = _pair(a, b, platform)
            result['correlation_id'] = f'OR-{len(pairs)+1:03}'
            pairs.append(result)
            if len(pairs) >= MAX_PAIRS: break
        if len(pairs) >= MAX_PAIRS: break
    counts = Counter(item['status'] for item in inventory)
    truncated = bool(source_truncated or capped_lines or definition_count > MAX_DEFINITIONS
                     or attempted > MAX_RULES or len(pairs) >= MAX_PAIRS)
    summary = {'definitions_seen': definition_count, 'definitions_resolved': counts['resolved'],
               'definitions_unresolved': counts['unresolved'], 'rules_seen': attempted,
               'rules_with_resolved_selectors': len(selectors), 'rules_not_resolved': max(0, attempted-len(selectors)),
               'candidate_pairs': len(pairs), 'truncated': truncated}
    not_assessed = platform in ('snort', 'suricata') or (platform == 'fortios' and bool(limits) and 'VDOM blocks' in limits[0])
    review_status = ('not_assessed' if not_assessed else
                     'limited' if truncated or summary['rules_not_resolved'] or counts['unresolved'] else 'reviewed_subset')
    return {'version': '1.0', 'platform_id': platform, 'scope': 'bounded_static_ipv4_object_resolution',
            'status': review_status,
            'summary': summary, 'objects': inventory[:MAX_EXPORTED_OBJECTS], 'pairs': pairs,
            'limitations': limits + [
                'Resolved means the limited syntax was parsed, not that effective firewall reachability is verified.',
                'No changes to security findings, risk scores, correlations from earlier milestones, or uploaded configuration.',
                'Results are advisory and must be verified against the deployed device before remediation.',
            ] + (['Processing or output limit reached; assessment is incomplete.'] if truncated else [])}
