"""API-010.8: conservative, bounded NAT / route / interface evidence review.

Operates exclusively on submitted configuration text. NO active probes; never
reports a configured permit or route as proof of live reachability.
"""
from __future__ import annotations
import ipaddress
import re
import shlex
from typing import Any

SUPPORTED = frozenset({'cisco_asa', 'fortios', 'snort', 'suricata'})
MAX_LINES = 40_000
MAX_ITEMS = 400
MAX_POLICIES = 100
MAX_EVIDENCE = 100
Net = ipaddress.IPv4Network | ipaddress.IPv6Network


def toks(line: str) -> list[str]:
    try:
        return shlex.split(line.strip(), comments=True, posix=True)
    except ValueError:
        return []


def network(ip: str, mask: str | None = None) -> Net | None:
    try:
        return ipaddress.ip_network(f'{ip}/{mask}' if mask else ip, strict=False)
    except ValueError:
        return None


def host(ip: str) -> Net | None:
    try:
        addr = ipaddress.ip_address(ip)
        return ipaddress.ip_network(f'{addr}/{addr.max_prefixlen}', strict=False)
    except ValueError:
        return None


def emit(store: list[dict[str, Any]], kind: str, line: int, title: str,
         *, policy: str | None = None, route_line: int | None = None,
         destination: str | None = None, ingress: str | None = None,
         egress: str | None = None, mapped: str | None = None,
         explanation: str, recommendation: str) -> bool:
    if len(store) == MAX_EVIDENCE:
        return False
    store.append({
        'reference': f'NRR-{len(store) + 1:03d}', 'kind': kind,
        'line_number': line, 'policy_id': policy, 'route_line_number': route_line,
        'title': title, 'destination': destination, 'ingress_interface': ingress,
        'egress_interface': egress, 'mapped_destination': mapped,
        'confidence': 'configured_candidate_only',
        'explanation': explanation, 'recommendation': recommendation,
    })
    return True


def route_for(target: Net, routes: list[dict[str, Any]]) -> tuple[dict[str, Any] | None, str]:
    """Abstain unless one route dominates *the entire* target prefix."""
    candidates = [r for r in routes if target.version == r['network'].version
                  and target.subnet_of(r['network'])]
    if not candidates:
        return None, 'no_supported_route_match'
    longest = max(r['network'].prefixlen for r in candidates)
    best = [r for r in candidates if r['network'].prefixlen == longest]
    if len(best) != 1:
        return None, 'equal_prefix_candidates'
    chosen = best[0]
    # A more specific route may govern only part of target. Never imply a unique path.
    if any(r['network'].version == target.version
           and r['network'].prefixlen > longest and r['network'].overlaps(target)
           for r in routes):
        return None, 'specific_routes_split_destination'
    return chosen, 'supported_lpm_prefix_candidate'


def _read_asa(lines: list[str]):
    routes: list[dict[str, Any]] = []
    nats: list[dict[str, Any]] = []
    policies: list[dict[str, Any]] = []
    binds: dict[str, list[str]] = {}
    objects: dict[str, list[dict[str, Any]]] = {}
    current: dict[str, Any] | None = None
    summary = {'routes_seen': 0, 'routes_resolved': 0, 'nat_seen': 0,
               'nat_resolved': 0, 'policies_seen': 0, 'policies_eligible': 0}
    omissions = 0
    for ln, raw in enumerate(lines, 1):
        t = toks(raw)
        if not t or raw.lstrip().startswith('!'):
            continue
        cmd = t[0].lower()
        if cmd == 'object' and len(t) == 3 and t[1].lower() == 'network':
            current = {'name': t[2], 'line': ln, 'addr': None, 'bad': False}
            objects.setdefault(t[2], []).append(current)
            continue
        if cmd in ('host', 'subnet', 'nat') and current is not None and raw[:1].isspace():
            if cmd in ('host', 'subnet'):
                value = host(t[1]) if cmd == 'host' and len(t) == 2 else (
                    network(t[1], t[2]) if cmd == 'subnet' and len(t) == 3 else None)
                if current['addr'] is not None or value is None:
                    current['bad'] = True
                else:
                    current['addr'] = value
            else:
                summary['nat_seen'] += 1
                matched = (len(t) == 4 and t[2].lower() == 'static'
                           and re.fullmatch(r'\([\w.-]+,[\w.-]+\)', t[1]))
                mapped = host(t[3]) if matched else None
                if matched and mapped and current['addr'] and current['addr'].prefixlen == current['addr'].max_prefixlen and not current['bad'] and mapped.version == current['addr'].version:
                    ingress, egress = t[1][1:-1].split(',')
                    nats.append({'line': ln, 'orig': current['addr'], 'mapped': mapped,
                                 'in': ingress, 'out': egress, 'name': current['name']})
                    summary['nat_resolved'] += 1
                else:
                    omissions += 1
            continue
        # ASA's top-level statements are unindented. A nested statement from
        # another ASA block cannot inherit a preceding network object.
        if not raw[:1].isspace():
            current = None
        if cmd == 'route':
            summary['routes_seen'] += 1
            valid = len(t) in (5, 6) and (len(t) == 5 or t[5].isdigit())
            net = network(t[2], t[3]) if valid else None
            gateway = host(t[4]) if valid else None
            if net and gateway and net.version == 4 and gateway.version == 4:
                routes.append({'line': ln, 'network': net, 'interface': t[1], 'gateway': t[4]})
                summary['routes_resolved'] += 1
            else:
                omissions += 1
        elif cmd == 'ipv6' and len(t) >= 2 and t[1].lower() == 'route':
            summary['routes_seen'] += 1
            net = network(t[3]) if len(t) in (5, 6) else None
            gateway = host(t[4]) if len(t) in (5, 6) else None
            if net and gateway and net.version == 6 and gateway.version == 6 and (len(t) == 5 or t[5].isdigit()):
                routes.append({'line': ln, 'network': net, 'interface': t[2], 'gateway': t[4]})
                summary['routes_resolved'] += 1
            else:
                omissions += 1
        elif cmd == 'access-group':
            if len(t) == 5 and t[2:4] == ['in', 'interface']:
                binds.setdefault(t[1], []).append(t[4])
            else:
                omissions += 1
        elif cmd == 'access-list':
            summary['policies_seen'] += 1
            policy = _asa_policy(t, ln, objects)
            if policy:
                policies.append(policy)
                summary['policies_eligible'] += 1
            else:
                omissions += 1
    # A later duplicate object definition invalidates an earlier NAT record too.
    # Never choose a declaration based on its position in the upload.
    valid_nats = [n for n in nats if len(objects.get(n['name'], [])) == 1
                  and not objects[n['name']][0]['bad']]
    invalid_nats = len(nats) - len(valid_nats)
    summary['nat_resolved'] -= invalid_nats
    omissions += invalid_nats
    nats = valid_nats
    if summary['routes_seen'] + summary['nat_seen'] + summary['policies_seen'] > MAX_ITEMS:
        return [], [], [], {}, summary, omissions, True
    return routes, nats, policies[:MAX_POLICIES], binds, summary, omissions, len(policies) > MAX_POLICIES


def _asa_policy(t: list[str], ln: int, objects: dict[str, list[dict[str, Any]]]) -> dict[str, Any] | None:
    if len(t) < 6:
        return None
    name = t[1]
    pos = 2
    if pos < len(t) and t[pos] == 'line':
        if pos + 1 >= len(t) or not t[pos + 1].isdigit():
            return None
        pos += 2
    if t[pos:pos + 1] != ['extended'] or t[pos + 1:pos + 2] not in (['permit'], ['deny']):
        return None
    action = t[pos + 1]
    protocol = t[pos + 2:pos + 3]
    if protocol not in (['tcp'], ['udp'], ['ip']):
        return None
    pos += 3

    def read_addr(at: int):
        if at >= len(t):
            return None
        if t[at] in ('any', 'any4'):
            return network('0.0.0.0/0'), at + 1
        if t[at] == 'any6':
            return network('::/0'), at + 1
        if t[at] == 'host' and at + 1 < len(t):
            n = host(t[at + 1]); return (n, at + 2) if n else None
        if t[at] == 'object' and at + 1 < len(t):
            obj = objects.get(t[at + 1], [])
            if len(obj) == 1 and obj[0]['addr'] is not None and not obj[0]['bad']:
                return obj[0]['addr'], at + 2
            return None
        if at + 1 < len(t):
            n = network(t[at], t[at + 1])
            return (n, at + 2) if n else None
        return None

    src = read_addr(pos)
    if not src:
        return None
    dst = read_addr(src[1])
    if not dst or src[0].version != dst[0].version:
        return None
    pos = dst[1]
    if protocol != ['ip']:
        if t[pos:pos + 1] != ['eq'] or pos + 1 >= len(t):
            return None
        if not t[pos + 1].isdigit() or not 1 <= int(t[pos + 1]) <= 65535:
            return None
        pos += 2
    if pos != len(t):
        return None
    return {'line': ln, 'id': name, 'destination': dst[0], 'action': action}


def _forti_defs(lines: list[str]):
    allowed = {'router static', 'firewall vip', 'firewall address', 'firewall policy'}
    rows: dict[str, dict[str, list[tuple[int, dict[str, Any]]]]] = {k: {} for k in allowed}
    section = None
    current = None
    has_vdom = False
    unsupported_structure = False
    for ln, raw in enumerate(lines, 1):
        t = toks(raw)
        if not t:
            continue
        key = t[0].lower()
        if key == 'config':
            path = ' '.join(x.lower() for x in t[1:])
            if path == 'vdom':
                has_vdom = True
            if current is not None:
                current['bad'] = True
            section = path if path in allowed else None
            current = None
        elif key == 'edit' and len(t) == 2 and section:
            current = {'line': ln, 'props': {}, 'prop_lines': {}, 'bad': False}
            rows[section].setdefault(t[1], []).append((ln, current))
        elif key == 'set' and current is not None and len(t) >= 3:
            attr = t[1].lower()
            if attr in current['props']:
                current['bad'] = True
            current['props'][attr] = t[2:]
            current['prop_lines'][attr] = ln
        elif key in ('append', 'unset', 'delete', 'rename', 'move', 'clone') and current is not None:
            current['bad'] = True
        elif key == 'next':
            current = None
        elif key == 'end':
            section = None
            current = None
        elif current is not None:
            current['bad'] = True
        elif section is not None:
            unsupported_structure = True
    return rows, has_vdom, unsupported_structure


def _read_forti(lines: list[str]):
    defs, has_vdom, structure_unknown = _forti_defs(lines)
    stats = {'routes_seen': len(defs['router static']), 'routes_resolved': 0,
             'nat_seen': len(defs['firewall vip']), 'nat_resolved': 0,
             'policies_seen': len(defs['firewall policy']), 'policies_eligible': 0}
    omissions = 0
    if has_vdom or sum(map(len, (defs[x] for x in defs))) > MAX_ITEMS:
        return [], [], [], {}, stats, omissions, True
    routes = []
    nats = []
    policies = []
    for key, records in defs['router static'].items():
        if len(records) != 1:
            omissions += 1; continue
        line, record = records[0]
        p = record['props']
        if record['bad'] or p.get('status', ['enable']) != ['enable']:
            omissions += 1; continue
        if any(k not in {'dst', 'gateway', 'device', 'distance', 'priority', 'comment', 'status'} for k in p):
            omissions += 1; continue
        dest = p.get('dst', ['0.0.0.0', '0.0.0.0'])
        net = network(dest[0], dest[1]) if len(dest) == 2 else None
        gw = p.get('gateway', [])
        dev = p.get('device', [])
        if net and net.version == 4 and len(gw) == 1 and host(gw[0]) and len(dev) == 1:
            routes.append({'line': line, 'network': net, 'interface': dev[0], 'gateway': gw[0]})
            stats['routes_resolved'] += 1
        else:
            omissions += 1
    for name, records in defs['firewall vip'].items():
        if len(records) != 1:
            omissions += 1; continue
        line, record = records[0]
        p = record['props']
        if record['bad'] or any(k not in {'extip', 'mappedip', 'extintf', 'comment', 'color', 'status', 'type'} for k in p):
            omissions += 1; continue
        if p.get('status', ['enable']) != ['enable'] or p.get('type', ['static-nat']) != ['static-nat']:
            omissions += 1; continue
        ext = p.get('extip', [])
        mapped = p.get('mappedip', [])
        intf = p.get('extintf', [])
        if len(ext) == len(mapped) == len(intf) == 1:
            e, m = host(ext[0]), host(mapped[0])
            if e and m and e.version == m.version == 4:
                nats.append({'line': line, 'orig': e, 'mapped': m,
                             'in': intf[0], 'out': None, 'name': name})
                stats['nat_resolved'] += 1
                continue
        omissions += 1
    for name, records in defs['firewall policy'].items():
        if len(records) != 1:
            omissions += 1; continue
        line, record = records[0]
        p = record['props']
        if record['bad'] or p.get('status', ['enable']) != ['enable']:
            omissions += 1; continue
        # Exclusion/negation and internet-service policies have different
        # destination semantics from a simple address selector.
        if any(k.endswith('-negate') or k.startswith('internet-service') or
               k in {'match-vip', 'dstaddr6', 'srcaddr6', 'policy-route'}
               for k in p):
            omissions += 1; continue
        srcintf, dstintf, dstaddr = p.get('srcintf', []), p.get('dstintf', []), p.get('dstaddr', [])
        if len(srcintf) != 1 or len(dstintf) != 1 or len(dstaddr) != 1:
            omissions += 1; continue
        dest = None
        vip = None
        if dstaddr[0] == 'all':
            dest = network('0.0.0.0/0')
        elif dstaddr[0] in defs['firewall vip']:
            candidates = [n for n in nats if n['name'] == dstaddr[0]]
            if len(candidates) == 1:
                vip = candidates[0]
                dest = vip['mapped']
        else:
            objs = defs['firewall address'].get(dstaddr[0], [])
            if len(objs) == 1 and not objs[0][1]['bad']:
                addr_props = objs[0][1]['props']
                subnet = addr_props.get('subnet', [])
                allowed_addr_props = {'subnet', 'type', 'comment', 'color', 'visibility'}
                if (set(addr_props).issubset(allowed_addr_props)
                    and addr_props.get('type', ['ipmask']) == ['ipmask'] and len(subnet) == 2):
                    dest = network(subnet[0], subnet[1])
        if dest is None or dest.version != 4:
            omissions += 1; continue
        # Policies are recorded for correlation, NOT treated as permits.
        policies.append({'line': line, 'id': name, 'destination': dest, 'action': (p.get('action') or ['deny'])[0],
                         'ingress': srcintf[0], 'egress': dstintf[0], 'vip': vip,
                         'snat': p.get('nat', ['disable']) == ['enable'],
                         'snat_line': record['prop_lines'].get('nat', line),
                         'pool': p.get('ippool', ['disable']) == ['enable']})
        stats['policies_eligible'] += 1
    return routes, nats, policies[:MAX_POLICIES], {}, stats, omissions, structure_unknown or len(policies) > MAX_POLICIES


def review_nat_route_reachability(platform: str, source: str, *, source_truncated: bool = False) -> dict[str, Any]:
    if platform not in SUPPORTED:
        raise ValueError('Unsupported platform')
    if not isinstance(source, str):
        raise TypeError('source must be UTF-8 text')
    source_lines = source.splitlines()
    capped = source_truncated or len(source_lines) > MAX_LINES
    lines = source_lines[:MAX_LINES]
    limits = [
        'Static upload-only assessment, not a forwarding simulation or a device-state audit; running routes, ARP, SD-WAN/PBR, zones, VPNs, anti-spoofing and sessions are unknown.',
        'Configured matching route and ACL/policy selectors are candidates, not proof of actual allowed traffic or exposure.',
        'No evidence of a route in this supported subset is NOT proof that a destination is unreachable.',
        'NAT mappings are reviewed as written; evaluation order, rule direction, overlapping policies, translations and platform-specific NAT precedence are not resolved.',
    ]
    if platform in ('snort', 'suricata'):
        return {'version': '1.0', 'platform_id': platform,
                'scope': 'static_bounded_nat_route_reachability_evidence',
                'status': 'not_assessed',
                'summary': {'routes_seen': 0, 'routes_resolved': 0, 'routes_unresolved': 0,
                            'nat_seen': 0, 'nat_resolved': 0, 'nat_unresolved': 0,
                            'policies_seen': 0, 'policies_eligible': 0,
                            'evidence_items': 0, 'items_omitted': 0, 'incomplete': False},
                'evidence': [], 'limitations': ['NAT, firewall forwarding and device routing are not evaluated for Snort or Suricata IDS configurations.']}
    if platform == 'cisco_asa':
        routes, nats, policies, binds, stats, omitted, unsafe = _read_asa(lines)
        limits.append('Cisco ASA: explicit routes, simple network-object host static NAT, and a narrow unmodified extended ACL subset only. Access-group bindings must be explicitly present.')
    else:
        routes, nats, policies, binds, stats, omitted, unsafe = _read_forti(lines)
        limits.append('FortiOS: single-VDOM static IPv4 routes, simple one-to-one VIPs, explicit policy interface selectors and simple destination objects only; SNAT is indicative, not translated to a concrete address.')
        if any(re.match(r'^\s*config\s+vdom\b', s, re.I) for s in lines):
            limits.append('VDOM found: FortiOS NAT/routing correlation is not assessed.')
    evidence: list[dict[str, Any]] = []
    if not unsafe and not capped:
        # Report supported NAT relationships with no assertion of deployed action.
        for nat in nats:
            ok = emit(evidence, 'configured_static_nat_candidate', nat['line'], 'Static address translation configured',
                      destination=str(nat['orig']), mapped=str(nat['mapped']), ingress=nat['in'], egress=nat['out'],
                      explanation=f"Explicit translation selector: {nat['orig']} to {nat['mapped']}. Activation, NAT precedence and packet direction are unverified.",
                      recommendation='Confirm NAT ordering, interface binding, route adjacency and actual translated traffic on the device.')
            if not ok: omitted += 1
        for p in policies:
            # SNAT enablement is an explicit policy setting, but neither the
            # actual source translation nor the egress path is established.
            if platform == 'fortios' and p.get('snat'):
                ok = emit(evidence, 'policy_snat_indicator', p['snat_line'],
                          'Policy contains SNAT enablement', policy=p['id'],
                          ingress=p['ingress'], egress=p['egress'],
                          explanation=('SNAT is explicitly enabled on this configuration policy. '
                                       'Translated source address, pool selection, actual rule match and NAT order are not established.'),
                          recommendation='Check the effective source NAT policy, address pool, rule order and packet logs on the firewall.')
                if not ok: omitted += 1
            ingress = p.get('ingress')
            if platform == 'cisco_asa':
                b = binds.get(p['id'], [])
                ingress = b[0] if len(b) == 1 else None
                if ingress is None:
                    # No access-group binding; do NOT correlate as an active policy.
                    omitted += 1
                    continue
            target = p['destination']
            if platform == 'fortios' and p.get('vip') and p['vip']['in'] not in ('any', p['ingress']):
                # Explicit VIP external interface cannot be joined to a
                # different policy ingress in a bounded static review.
                omitted += 1
                continue
            route, status = route_for(target, routes)
            if not route:
                # No route / route split / equal prefix => no finding, just PDF limitations.
                omitted += 1
                continue
            # FortiOS DNAT VIP mappings select a *mapped* destination. Explicitly
            # label this as an analytic hypothesis; never as actual NAT order.
            kind = 'route_policy_candidate'
            why = f"Destination {target} falls within configured route {route['network']} via {route['interface']} (gateway {route['gateway']}). Only explicit config prefixes were compared."
            if platform == 'fortios' and p['egress'] != route['interface']:
                kind = 'potential_egress_discrepancy'
                why += f" Policy egress {p['egress']} differs from static-route interface {route['interface']}; dynamic/PBR routing may explain this."
            if platform == 'fortios' and p.get('vip'):
                why += f" Policy references VIP {p['vip']['name']}; route check uses its declared mapped address, not proof of effective DNAT."
            if platform == 'fortios' and p.get('snat'):
                why += ' SNAT is configured; no concrete translated source address is established.'
            if platform == 'fortios' and p.get('pool'):
                why += ' IP-pool translation is unmodeled.'
            ok = emit(evidence, kind, p['line'], 'Potential policy and static-route relationship',
                      policy=p['id'], route_line=route['line'], destination=str(target),
                      ingress=ingress, egress=route['interface'],
                      mapped=str(p['vip']['mapped']) if p.get('vip') else None,
                      explanation=why, recommendation='Verify effective policy placement, NAT application, interface routing table and runtime counters before modifying rules.')
            if not ok: omitted += 1
    else:
        limits.append('Untrusted scope cap or unsupported nested/VDOM structure; no NAT-route relationship was inferred.')
    if unsafe or capped or omitted:
        limits.append('Unsupported/ambiguous, truncated or output-limited records were excluded; absence of candidates is not an all-clear result.')
    incomplete = unsafe or capped or omitted > 0 or stats['routes_seen'] > stats['routes_resolved'] or stats['nat_seen'] > stats['nat_resolved'] or stats['policies_seen'] > stats['policies_eligible']
    return {
        'version': '1.0', 'platform_id': platform,
        'scope': 'static_bounded_nat_route_reachability_evidence',
        'status': 'limited' if incomplete else 'reviewed_subset',
        'summary': {**stats,
                    'routes_unresolved': stats['routes_seen'] - stats['routes_resolved'],
                    'nat_unresolved': stats['nat_seen'] - stats['nat_resolved'],
                    'evidence_items': len(evidence), 'items_omitted': omitted,
                    'incomplete': incomplete},
        'evidence': evidence, 'limitations': limits,
    }
