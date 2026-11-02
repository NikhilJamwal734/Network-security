"""API-010.6: conservative dependency/integrity diagnostics for uploaded policy objects.

Advisory checks only. A missing *definition in this upload* does not prove a
broken effective device configuration; policy references may be defined by
builtins, live config state, omitted contexts, or separate files.
"""
from __future__ import annotations

from collections import Counter, defaultdict
import re
import shlex
from typing import Any

SUPPORTED = frozenset({'cisco_asa', 'fortios', 'snort', 'suricata'})
MAX_LINES = 50_000
MAX_REFERENCES = 5_000
MAX_DIAGNOSTICS = 100
MAX_DEFINITIONS = 2_000
MAX_DEPTH = 12
MAX_TOKEN = 120


def _tokens(source: str) -> list[str]:
    try:
        return shlex.split(source, comments=False)
    except ValueError:
        return []


def review_dependencies(platform: str, source: str, *, source_truncated: bool = False,
                        object_resolution: dict[str, Any] | None = None) -> dict[str, Any]:
    if platform not in SUPPORTED:
        raise ValueError('Unsupported platform')
    if not isinstance(source, str):
        raise TypeError('Source must be text')

    source_lines = source.splitlines()
    line_limited = len(source_lines) > MAX_LINES
    lines = source_lines[:MAX_LINES]
    upstream_limited = bool((object_resolution or {}).get('summary', {}).get('truncated'))
    incomplete = bool(source_truncated or line_limited or upstream_limited)
    issues: list[dict[str, Any]] = []
    ref_count = 0
    suppressed = 0
    counts: Counter[str] = Counter()

    def add(kind: str, name: str, line: int, explanation: str, advice: str,
            related: tuple[int, ...] = ()) -> None:
        nonlocal suppressed
        counts[kind] += 1
        if len(issues) >= MAX_DIAGNOSTICS:
            suppressed += 1
            return
        issues.append({
            'reference': f'OA-{len(issues) + 1:03d}', 'kind': kind,
            'status': 'review_needed', 'object_name': name[:MAX_TOKEN],
            'line_number': line, 'related_line_numbers': list(related[:8]),
            'explanation': explanation, 'recommendation': advice,
        })

    limitations = [
        'This is a static cross-reference check, not validation of the live effective firewall or IDS/IPS configuration.',
        'Definitions missing from this upload may exist in external files, built-ins, VDOMs or live device state.',
        'Object observations do not change existing findings, severities, scores, or correlation candidates.',
    ]
    if platform in ('snort', 'suricata'):
        limitations.insert(0, 'IDS variables, rule includes, runtime expansion, and action semantics are not resolved in this milestone.')
        return {
            'version': '1.0', 'platform_id': platform, 'scope': 'uploaded_object_dependency_evidence',
            'status': 'not_assessed', 'summary': {
                'definitions_seen': 0, 'references_checked': 0, 'observations': 0,
                'missing_in_upload': 0, 'cycles': 0, 'repeated_definitions': 0,
                'incomplete': incomplete, 'observations_omitted': 0,
            }, 'observations': [], 'limitations': limitations,
        }

    if platform == 'cisco_asa':
        definitions: dict[str, list[int]] = defaultdict(list)
        refs: list[tuple[str, int, str]] = []
        for line_number, raw in enumerate(lines, 1):
            stripped = raw.strip()
            if not stripped or stripped.startswith(('!', '#')):
                continue
            words = stripped.split()
            if len(words) == 3 and words[:2] == ['object', 'network']:
                definitions[words[2]].append(line_number)
            elif len(words) >= 5 and words[0].lower() == 'access-list' and words[1].lower() != 'remark':
                # Deliberately limit to ASA supported extended ACL source/dest object selectors.
                try:
                    pos = next(i for i, token in enumerate(words) if token.lower() == 'extended')
                except StopIteration:
                    continue
                if len(words) <= pos + 2 or words[pos + 1].lower() not in ('permit', 'deny'):
                    continue
                protocol = words[pos + 2].lower()
                if protocol not in ('ip', 'tcp', 'udp', 'icmp'):
                    continue
                cursor = pos + 3
                local_refs: list[str] = []

                def read_address(index: int) -> int | None:
                    if index >= len(words):
                        return None
                    token = words[index].lower()
                    if token in ('any', 'any4'):
                        return index + 1
                    if token in ('host', 'object') and index + 1 < len(words):
                        if token == 'object':
                            local_refs.append(words[index + 1])
                        return index + 2
                    if re.fullmatch(r'\d+\.\d+\.\d+\.\d+', words[index]) and index + 1 < len(words):
                        return index + 2
                    return None

                def read_ports(index: int) -> int | None:
                    if index >= len(words) or words[index].lower() not in ('eq', 'range'):
                        return index
                    width = 2 if words[index].lower() == 'eq' else 3
                    if len(words) < index + width:
                        return None
                    return index + width

                cursor = read_address(cursor)
                if cursor is None:
                    continue
                if protocol in ('tcp', 'udp'):
                    cursor = read_ports(cursor)
                if cursor is None:
                    continue
                cursor = read_address(cursor)
                if cursor is None:
                    continue
                refs.extend((name, line_number, 'network object reference in an extended ACE') for name in local_refs)
        if len(definitions) > MAX_DEFINITIONS:
            incomplete = True
        for name, positions in list(definitions.items())[:MAX_DEFINITIONS]:
            if len(positions) > 1:
                add('repeated_definition', name, positions[-1],
                    'This network object name is declared more than once in the uploaded source; effective edit semantics are not inferred.',
                    'Review the referenced object in the active device configuration before relying on object-based comparisons.',
                    tuple(positions[:-1]))
        if len(refs) > MAX_REFERENCES:
            incomplete = True
        for name, line, _ in refs[:MAX_REFERENCES]:
            ref_count += 1
            if name not in definitions:
                category = 'not_visible_in_excerpt' if incomplete else 'not_defined_in_upload'
                add(category, name, line,
                    'The named network object referenced by this ACE is not defined in the analyzed upload' + (' excerpt.' if incomplete else '.'),
                    'Confirm the named object in the complete effective ASA configuration; do not assume the ACL is invalid.')
        if len(refs) > MAX_REFERENCES:
            incomplete = True
        def_count = sum(len(entries) for entries in definitions.values())
        limitations.append('ASA: only explicit object network declarations and object references in extended ACEs are cross-referenced; object-groups and service aliases are excluded.')

    else:  # FortiOS
        # Restrict to scoped config tables only; refuse VDOM guesses outright.
        if any(re.match(r'^\s*config\s+vdom\b', line, re.I) for line in lines):
            limitations.insert(0, 'FortiOS VDOM context detected; cross-VDOM object references cannot safely be inferred.')
            return {'version': '1.0', 'platform_id': platform,
                    'scope': 'uploaded_object_dependency_evidence', 'status': 'not_assessed',
                    'summary': {'definitions_seen': 0, 'references_checked': 0, 'observations': 0,
                                'missing_in_upload': 0, 'cycles': 0, 'repeated_definitions': 0,
                                'incomplete': True, 'observations_omitted': 0},
                    'observations': [], 'limitations': limitations}

        tables = ('firewall address', 'firewall addrgrp', 'firewall service custom',
                  'firewall service group', 'firewall policy')
        definitions: dict[tuple[str, str], list[int]] = defaultdict(list)
        group_members: dict[str, tuple[int, tuple[str, ...]]] = {}
        group_entries: dict[str, list[int]] = defaultdict(list)
        refs: list[tuple[str, int, str]] = []
        current_table: str | None = None
        current: tuple[str, int] | None = None
        for line_number, raw in enumerate(lines, 1):
            words = _tokens(raw.strip())
            if not words or words[0].startswith('#'):
                continue
            cmd = words[0].lower()
            if cmd == 'config':
                if current is not None:
                    incomplete = True  # nested configuration cannot be scoped faithfully
                table = ' '.join(part.lower() for part in words[1:])
                current_table = table if table in tables else None
                current = None
            elif cmd == 'edit' and len(words) == 2 and current_table:
                current = words[1], line_number
                definitions[(current_table, words[1])].append(line_number)
                if current_table == 'firewall addrgrp':
                    group_entries[words[1]].append(line_number)
            elif cmd == 'set' and len(words) >= 3 and current and current_table:
                name = current[0]
                attr = words[1].lower()
                if current_table == 'firewall addrgrp' and attr == 'member':
                    group_members[name] = line_number, tuple(words[2:])
                elif current_table == 'firewall policy' and attr in ('srcaddr', 'dstaddr', 'service'):
                    for referenced in words[2:]:
                        refs.append((referenced, line_number, attr))
            elif cmd in ('unset', 'append', 'delete') and current:
                # Mutation semantics are not modeled; cross-reference results become limited.
                incomplete = True
            elif cmd == 'next':
                current = None
            elif cmd == 'end':
                current = None
                current_table = None

        for name, (line_number, members) in group_members.items():
            for member in members:
                refs.append((member, line_number, 'member'))
        if len(definitions) > MAX_DEFINITIONS:
            incomplete = True
        for (kind, name), positions in list(definitions.items())[:MAX_DEFINITIONS]:
            if len(positions) > 1:
                add('repeated_definition', name, positions[-1],
                    f'The same {kind} entry appears more than once in the uploaded source; device edit semantics are not reconstructed.',
                    'Verify the final effective definition and its context before changing policy.', tuple(positions[:-1]))

        address_names = {name for (kind, name) in definitions if kind in ('firewall address', 'firewall addrgrp')}
        service_names = {name for (kind, name) in definitions if kind in ('firewall service custom', 'firewall service group')}
        if len(refs) > MAX_REFERENCES:
            incomplete = True
        for name, line, attr in refs[:MAX_REFERENCES]:
            ref_count += 1
            if attr in ('srcaddr', 'dstaddr', 'member'):
                if name in address_names or name in ('all', 'all6'):
                    continue
                kind = 'not_visible_in_excerpt' if incomplete else 'not_defined_in_upload'
                add(kind, name, line,
                    f'Address reference ({attr}) does not have a matching address/group definition in this uploaded configuration.',
                    'Check the complete configuration and correct VDOM before treating the reference as invalid.')
            elif attr == 'service' and name not in service_names:
                # Unrecognized service could be a built-in; do NOT claim it is undefined.
                if name not in ('ALL', 'all'):
                    add('service_definition_not_visible', name, line,
                        'No custom service/service-group definition appears in this upload; the name may be a FortiOS built-in service.',
                        'Verify the service identity against the FortiOS built-in catalog and active configuration.')
        if len(refs) > MAX_REFERENCES:
            incomplete = True
        graph = {name: members for name, (line, members) in group_members.items() if len(group_entries[name]) == 1}
        recorded_cycles: set[tuple[str, ...]] = set()
        checked_nodes: set[str] = set()

        def visit(name: str, active: tuple[str, ...]) -> None:
            if name in active:
                cycle = active[active.index(name):]
                canonical = min(tuple(cycle[i:] + cycle[:i]) for i in range(len(cycle)))
                if canonical not in recorded_cycles:
                    recorded_cycles.add(canonical)
                    start = group_members[name][0]
                    related = tuple(group_members[v][0] for v in cycle if v in group_members)
                    add('dependency_cycle', name, start,
                        'Address groups refer to one another in a cycle; membership cannot be expanded by this static resolver.',
                        'Inspect the complete group definitions and break unintended cyclic dependencies.', related)
                return
            if name in checked_nodes or len(active) >= MAX_DEPTH:
                return
            for member in graph.get(name, ()):
                if member in graph:
                    visit(member, active + (name,))
            checked_nodes.add(name)

        for name in sorted(graph):
            visit(name, ())
        def_count = sum(len(rows) for rows in definitions.values())
        limitations.append('FortiOS: static reference checks cover uploaded address/groups, custom services/groups and policy selectors; built-in services and effective policy order are not inferred.')

    if incomplete:
        limitations.append('Partial source, unsupported mutations, or processing caps prevent definitive absence conclusions.')
    if suppressed:
        limitations.append('Diagnostic output was capped; review the full source for additional observations.')
    return {
        'version': '1.0', 'platform_id': platform,
        'scope': 'uploaded_object_dependency_evidence',
        'status': 'limited' if incomplete else 'reviewed_subset',
        'summary': {
            'definitions_seen': def_count, 'references_checked': ref_count,
            'observations': len(issues),
            'missing_in_upload': counts['not_defined_in_upload'] + counts['not_visible_in_excerpt'],
            'cycles': counts['dependency_cycle'],
            'repeated_definitions': counts['repeated_definition'],
            'incomplete': incomplete or bool(suppressed), 'observations_omitted': suppressed,
        },
        'observations': issues,
        'limitations': limitations,
    }
