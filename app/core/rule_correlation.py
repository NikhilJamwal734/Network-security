"""API-010.3: bounded, evidence-first rule correlation (not packet simulation).

Reads text supplied by the existing validated upload path. No external file access,
command execution, rule expansion, network lookups, or topology assumptions.
All matches are advisory and excluded from existing scores and security findings.
"""
from __future__ import annotations

from dataclasses import dataclass
from collections import Counter
import ipaddress
import re
from typing import Any

from app.parsers.firewalls.fortios import FortiOSParser
from app.parsers.ids.snort import SnortParser
from app.parsers.ids.suricata import SuricataParser

MAX_CANDIDATES = 250
MAX_PAIRS = 70
MAX_INPUT_LINES = 50000
_SUPPORTED = frozenset(('cisco_asa', 'fortios', 'snort', 'suricata'))


@dataclass(frozen=True)
class _Ace:
    line: int
    name: str
    action: str
    protocol: str
    source: ipaddress.IPv4Network
    destination: ipaddress.IPv4Network
    src_ports: tuple[int, int]
    dst_ports: tuple[int, int]
    explicit_order: int | None


def _network(tokens: list[str], index: int) -> tuple[ipaddress.IPv4Network, int] | None:
    if index >= len(tokens):
        return None
    word = tokens[index].lower()
    if word in ('any', 'any4'):
        return ipaddress.ip_network('0.0.0.0/0'), index + 1
    if word == 'host' and index + 1 < len(tokens):
        try:
            address = ipaddress.IPv4Address(tokens[index + 1])
        except ipaddress.AddressValueError:
            return None
        return ipaddress.ip_network(f'{address}/32'), index + 2
    if index + 1 >= len(tokens):
        return None
    try:
        address = ipaddress.IPv4Address(tokens[index])
        netmask = ipaddress.IPv4Address(tokens[index + 1])
        network = ipaddress.IPv4Network(f'{address}/{netmask}', strict=False)
        # Do not reinterpret non-contiguous netmasks or wildcard masks.
        return network, index + 2
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError):
        return None


def _port(tokens: list[str], index: int) -> tuple[tuple[int, int], int] | None:
    if index >= len(tokens) or tokens[index].lower() not in ('eq', 'range'):
        return ((0, 65535), index)
    mode = tokens[index].lower()
    needed = 1 if mode == 'eq' else 2
    numbers = tokens[index + 1:index + 1 + needed]
    if len(numbers) != needed or not all(re.fullmatch(r'[0-9]{1,5}', x) for x in numbers):
        return None
    start = int(numbers[0]); end = int(numbers[-1])
    if not (0 <= start <= end <= 65535):
        return None
    return (start, end), index + 1 + needed


def _asa_ace(raw: str, line: int) -> _Ace | None:
    tokens = raw.strip().split()
    if len(tokens) < 7 or tokens[0].lower() != 'access-list':
        return None
    name = tokens[1]
    index = 2
    order: int | None = None
    if len(tokens) > index + 1 and tokens[index].lower() == 'line':
        if not re.fullmatch(r'[0-9]{1,6}', tokens[index + 1]):
            return None
        order = int(tokens[index + 1]); index += 2
    if len(tokens) <= index + 2 or tokens[index].lower() != 'extended':
        return None
    action = tokens[index + 1].lower()
    protocol = tokens[index + 2].lower()
    if action not in ('permit', 'deny') or protocol not in ('ip', 'tcp', 'udp', 'icmp'):
        return None
    index += 3
    source = _network(tokens, index)
    if source is None:
        return None
    src_net, index = source
    src_ports = (0, 65535)
    if protocol in ('tcp', 'udp'):
        parsed = _port(tokens, index)
        if parsed is None:
            return None
        src_ports, index = parsed
    destination = _network(tokens, index)
    if destination is None:
        return None
    dst_net, index = destination
    dst_ports = (0, 65535)
    if protocol in ('tcp', 'udp'):
        parsed = _port(tokens, index)
        if parsed is None:
            return None
        dst_ports, index = parsed
    # Only harmless ACE logging suffixes are accepted. Options affecting
    # match or enablement (inactive, time-range, object-group, etc.) abstain.
    remainder = [x.lower() for x in tokens[index:]]
    if remainder and (remainder[0] != 'log' or remainder[1:] not in ([], ['disable'], ['default'], ['informational'], ['warnings'])):
        return None
    return _Ace(line, name, action, protocol, src_net, dst_net, src_ports, dst_ports, order)


def _contains(left: _Ace, right: _Ace) -> bool:
    protocol_includes = left.protocol == right.protocol or (
        left.protocol == 'ip' and right.protocol in ('tcp', 'udp', 'icmp')
    )
    return (protocol_includes and right.source.subnet_of(left.source)
            and right.destination.subnet_of(left.destination)
            and left.src_ports[0] <= right.src_ports[0]
            and left.src_ports[1] >= right.src_ports[1]
            and left.dst_ports[0] <= right.dst_ports[0]
            and left.dst_ports[1] >= right.dst_ports[1])


def _overlap(left: _Ace, right: _Ace) -> bool:
    protocol = left.protocol == right.protocol or 'ip' in (left.protocol, right.protocol)
    return (protocol and left.source.overlaps(right.source)
            and left.destination.overlaps(right.destination)
            and max(left.src_ports[0], right.src_ports[0]) <= min(left.src_ports[1], right.src_ports[1])
            and max(left.dst_ports[0], right.dst_ports[0]) <= min(left.dst_ports[1], right.dst_ports[1]))


def _finding(kind: str, confidence: str, title: str, detail: str, suggestion: str,
             first_line: int, second_line: int, first_id: str, second_id: str,
             scope: str) -> dict[str, Any]:
    return dict(kind=kind, confidence=confidence, title=title, detail=detail,
                recommendation=suggestion, scope=scope,
                evidence=dict(line_number=second_line, related_line_number=first_line,
                              rule_id=second_id, related_rule_id=first_id))


def _asa(lines: list[str]) -> tuple[list[dict[str, Any]], int, int, list[str]]:
    rules: list[_Ace] = []
    attempted = 0
    for number, raw in enumerate(lines, 1):
        if raw.lstrip().lower().startswith('access-list ') and not raw.lstrip().lower().startswith('access-list remark'):
            attempted += 1
            if len(rules) < MAX_CANDIDATES:
                parsed = _asa_ace(raw, number)
                if parsed is not None:
                    rules.append(parsed)
    results: list[dict[str, Any]] = []
    for j, later in enumerate(rules):
        for earlier in rules[:j]:
            if earlier.name != later.name or not _overlap(earlier, later):
                continue
            same = earlier.action == later.action
            if _contains(earlier, later):
                kind = 'redundant_candidate' if same else 'shadowed_candidate'
                title = ('Potential redundant ASA ACE' if same else 'Potential shadowed ASA ACE')
                detail = ('Earlier ACE covers the later ACE match selectors in the same ACL. '
                          'Actual ACL ordering and bindings must be verified.' if same else
                          'An earlier opposite-action ACE covers the later ACE selectors within the same ACL. '
                          'If earlier-first ordering applies, the later ACE is unreachable for this traffic.')
            else:
                kind = 'overlap_candidate' if same else 'action_conflict_candidate'
                title = ('Overlapping ASA ACEs' if same else 'Overlapping opposite-action ASA ACEs')
                detail = ('The two ACE match domains intersect under the supported IPv4/protocol/port subset. '
                          'Determine whether this is intentional; interface binding and runtime order are unverified.')
            results.append(_finding(kind, 'conditional', title, detail,
                'Verify effective ACL order, interface binding, object expansion, and business intent before making changes.',
                earlier.line, later.line, earlier.name, later.name, f'ASA ACL {earlier.name}'))
            if len(results) >= MAX_PAIRS:
                break
        if len(results) >= MAX_PAIRS:
            break
    limits = [
        'ASA: only explicit extended IPv4 ACEs using any/host/address-mask and numeric eq/range ports are correlated.',
        'ASA ACL order, line numbering, interface bindings, object groups, NAT, time ranges, inactive flags and effective device state are not established.',
        'Shadowing and redundancy are candidates conditional on effective ordered evaluation; no configuration changes are applied.',
    ]
    return results, len(rules), attempted, limits


def _fortios(lines: list[str]) -> tuple[list[dict[str, Any]], int, int, list[str]]:
    parsed = FortiOSParser().parse(lines)
    id_counts = Counter(policy.identifier for policy in parsed.policies)
    required = ('srcintf', 'dstintf', 'srcaddr', 'dstaddr', 'service', 'schedule')
    eligible = []
    for policy in parsed.policies:
        if id_counts[policy.identifier] != 1:
            continue
        if any(not policy.get(x) for x in required):
            continue
        if len(policy.get('action')) != 1 or policy.get('action')[0].lower() not in ('accept', 'deny'):
            continue
        if 'disable' in (x.lower() for x in policy.get('status')):
            continue
        if len(eligible) >= MAX_CANDIDATES:
            break
        eligible.append(policy)
    results: list[dict[str, Any]] = []
    for j, later in enumerate(eligible):
        for earlier in eligible[:j]:
            # Names may resolve differently in a VDOM. Only exact explicit
            # token sets for all 6 selectors are compared; no group expansion.
            if not all(set(earlier.get(field)) == set(later.get(field)) for field in required):
                continue
            same = earlier.get('action')[0].lower() == later.get('action')[0].lower()
            results.append(_finding(
                'redundant_candidate' if same else 'action_conflict_candidate',
                'conditional',
                'FortiOS policies with identical explicit selectors' if same else
                'FortiOS policies with identical selectors and opposite actions',
                'Policies share the same six explicit selector token sets. '
                'Policy order, object membership, VDOM scope and effective rule activation are not resolved.',
                'Verify effective policy order, referenced objects and intent before consolidating policies.',
                earlier.line_number, later.line_number, earlier.identifier, later.identifier,
                'FortiOS firewall policy'))
            if len(results) >= MAX_PAIRS:
                break
        if len(results) >= MAX_PAIRS:
            break
    return results, len(eligible), len(parsed.policies), [
        'FortiOS: only unique enabled policy edit IDs with explicit action and six selectors are compared.',
        'Identical named selectors do not prove identical effective traffic: VDOM, address/service objects, policy order and group expansion are unresolved.',
        'Partial edits, disabled policies, implicit defaults, VIPs, central NAT and routing are not modeled.',
    ]


def _ids(platform: str, lines: list[str]) -> tuple[list[dict[str, Any]], int, int, list[str]]:
    config = SnortParser().parse(lines) if platform == 'snort' else SuricataParser().parse(lines)
    rules = [r for r in config.rules if r.enabled]
    candidates = rules[:MAX_CANDIDATES]
    results: list[dict[str, Any]] = []
    for j, later in enumerate(candidates):
        for earlier in candidates[:j]:
            # Only identical headers, not option or variable semantics, are known.
            # Suricata dataclass has no 'direction' field; parse the actual
            # arrow safely from the source header, rather than assuming ->.
            fields = ('protocol', 'source', 'source_port', 'destination', 'destination_port')
            if any(getattr(earlier, field) != getattr(later, field) for field in fields):
                continue
            if platform == 'snort':
                if earlier.direction != later.direction:
                    continue
            else:
                def arrow(rule: Any) -> str | None:
                    raw = lines[rule.line_number - 1]
                    head = raw.partition('(')[0].split()
                    return head[4] if len(head) >= 5 and head[4] in ('->', '<>') else None
                if arrow(earlier) is None or arrow(earlier) != arrow(later):
                    continue
            # Duplicate identity is already handled in precision review.
            if earlier.sid is not None and earlier.sid == later.sid:
                if platform == 'suricata' and earlier.gid != later.gid:
                    pass
                else:
                    continue
            same = earlier.action == later.action
            results.append(_finding(
                'header_overlap' if same else 'action_interaction_candidate', 'informational',
                'Two enabled IDS rules share a traffic header' if same else
                'Different IDS actions share a traffic header',
                'Traffic headers match textually; rule options, content patterns, variable expansion, action ordering, IPS mode and actual events were not evaluated.',
                'Compare full rule bodies and deployed engine behavior before removing or reordering rules.',
                earlier.line_number, later.line_number,
                str(earlier.sid) if earlier.sid is not None else f'line:{earlier.line_number}',
                str(later.sid) if later.sid is not None else f'line:{later.line_number}',
                f'{platform.capitalize()} uploaded rules'))
            if len(results) >= MAX_PAIRS:
                break
        if len(results) >= MAX_PAIRS:
            break
    return results, len(candidates), len(rules) + len(config.malformed_rule_lines), [
        f'{platform.capitalize()}: only parsed enabled one-line rule headers are compared; equal headers do not imply equivalent rule behavior.',
        'Rule options, content, flowbits, Lua/YAML configuration, includes, linked rule files, variables, engine action precedence and running mode are not correlated.',
        'Malformed rules and commented-out rules are not correlation candidates.',
    ]


def correlate_rules(platform: str, source_text: str, *, source_truncated: bool = False) -> dict[str, Any]:
    """Return bounded, opt-in advisory correlations; no existing report mutation."""
    if platform not in _SUPPORTED:
        raise ValueError('Unsupported platform for API-010.3 rule correlation')
    if not isinstance(source_text, str):
        raise TypeError('source_text must be a string')
    lines = source_text.splitlines()
    too_many_lines = len(lines) > MAX_INPUT_LINES
    lines = lines[:MAX_INPUT_LINES]
    if platform == 'cisco_asa':
        pairs, parsed, relevant, limitations = _asa(lines)
    elif platform == 'fortios':
        pairs, parsed, relevant, limitations = _fortios(lines)
    else:
        pairs, parsed, relevant, limitations = _ids(platform, lines)
    unassessed = max(0, relevant - parsed)
    capped = bool(source_truncated or too_many_lines or parsed >= MAX_CANDIDATES or len(pairs) >= MAX_PAIRS)
    summary = dict(eligible_rules=parsed, relevant_rules_seen=relevant, rules_not_correlated=unassessed,
                   candidate_pairs=len(pairs), by_kind=dict(sorted(Counter(x['kind'] for x in pairs).items())),
                   truncated=capped)
    return dict(version='1.0', platform_id=platform, scope='static_rule_correlation_advisory',
                status='limited' if capped or unassessed else 'reviewed_subset',
                summary=summary, pairs=[dict(correlation_id=f'RC-{i:03d}', **entry)
                                       for i, entry in enumerate(pairs, 1)],
                limitations=limitations + [
                    'Correlation results are advisory, not additional security findings or a verified reachability/traffic simulation.',
                    'Existing risk level, findings, severity totals and provisional score are not changed.',
                ] + (['Input or rule-count limits reached; results may be incomplete.'] if capped else []))
