"""API 010.9: bounded, conservative Snort / Suricata configuration observations.

Configuration-only: never opens rule paths, resolves YAML includes, runs Lua, or claims
traffic detection/alert delivery. All results are advisory and PDF-first.
"""
from __future__ import annotations

import re
from typing import Any

MAX_LINES = 40000
MAX_ITEMS = 80
MAX_RULES = 2000
MAX_LINE_LENGTH = 8192


def _new_review(platform: str) -> dict[str, Any]:
    return {
        'version': '1.0', 'platform_id': platform,
        'scope': 'bounded_static_ids_configuration_evidence',
        'status': 'reviewed_subset',
        'summary': {
            'rules_inspected': 0, 'duplicate_rule_ids': 0,
            'external_references': 0, 'outputs_explicitly_enabled': 0,
            'outputs_explicitly_disabled': 0, 'outputs_declared': 0, 'interfaces_declared': 0,
            'evidence_items': 0, 'items_omitted': 0, 'incomplete': False,
        },
        'evidence': [],
        'limitations': [
            'Static text inspection only; no runtime sensor health, packet capture, active rules, decoded traffic, alerts or forwarding behavior was verified.',
            'Only the submitted configuration text is inspected. External rule files, includes, command-line overrides and deployed configuration are not loaded.',
            'These advisory observations do not alter the normalized security findings, severities or scores.',
        ],
    }


class _Collector:
    def __init__(self, report: dict[str, Any]):
        self.r = report
        self.incomplete = False
        self.omitted = 0

    def add(self, kind: str, line: int, title: str, *, setting: str = '',
            observation: str, implication: str, recommendation: str,
            confidence: str = 'explicit_configuration_text') -> None:
        if len(self.r['evidence']) >= MAX_ITEMS:
            self.omitted += 1
            self.incomplete = True
            return
        self.r['evidence'].append({
            'reference': f"IDS-{len(self.r['evidence'])+1:03d}",
            'kind': kind, 'line_number': max(1, int(line)),
            'title': title, 'setting': setting,
            'observation': observation, 'implication': implication,
            'recommendation': recommendation, 'confidence': confidence,
        })

    def partial(self, msg: str, amount: int = 0) -> None:
        self.incomplete = True
        self.omitted += amount
        if msg not in self.r['limitations']:
            self.r['limitations'].append(msg)


def _nonempty_str(v: Any) -> str | None:
    return v.strip() if isinstance(v, str) and v.strip() else None


def _scan_suricata(text: str, c: _Collector) -> None:
    try:
        import yaml
        from yaml.events import AliasEvent
        from yaml.nodes import MappingNode, ScalarNode, SequenceNode
    except ImportError:
        c.partial('PyYAML is not installed. The Suricata YAML review is unavailable; install PyYAML in the backend virtual environment.')
        return

    class StrictLoader(yaml.SafeLoader):
        # Reject aliases and duplicate keys instead of silently making unsafe
        # conclusions about which duplicated setting the runtime would use.
        def compose_node(self, parent, index):
            if self.check_event(AliasEvent):
                raise ValueError('YAML aliases are not analyzed by this bounded reviewer')
            return super().compose_node(parent, index)

        def construct_mapping(self, node, deep=False):
            if not isinstance(node, MappingNode):
                raise ValueError('Expected a mapping node')
            seen: set[Any] = set()
            for key_node, _ in node.value:
                key = self.construct_object(key_node, deep=deep)
                if not isinstance(key, (str, int, bool)) or key in seen:
                    raise ValueError(f'Duplicate or unsupported YAML mapping key at line {key_node.start_mark.line + 1}')
                seen.add(key)
            return super().construct_mapping(node, deep=deep)

    try:
        doc = yaml.load(text, Loader=StrictLoader)
        if not isinstance(doc, dict):
            raise ValueError('Suricata YAML root is not a mapping')
        node = yaml.compose(text, Loader=StrictLoader)
    except (yaml.YAMLError, ValueError, RecursionError, TypeError, OverflowError) as exc:
        c.partial(f'YAML could not be safely and unambiguously parsed: {str(exc)[:180]}. No configuration settings were inferred.')
        return

    locations: dict[tuple, int] = {}

    def walk(n, p: tuple = (), depth: int = 0) -> None:
        if depth > 32:
            raise ValueError('YAML nesting exceeds the 32-level review limit')
        locations[p] = n.start_mark.line + 1
        if isinstance(n, MappingNode):
            for k, v in n.value:
                if isinstance(k, ScalarNode):
                    walk(v, p + (k.value,), depth + 1)
        elif isinstance(n, SequenceNode):
            for i, v in enumerate(n.value):
                walk(v, p + (i,), depth + 1)

    try:
        if node is not None:
            walk(node)
    except (ValueError, RecursionError) as exc:
        c.partial(f'YAML source-location mapping failed: {exc}.')
        return

    def line(*path) -> int:
        return locations.get(path, locations.get(path[:-1], 1))

    s = c.r['summary']
    addr = doc.get('vars')
    addr = addr.get('address-groups') if isinstance(addr, dict) else None
    if isinstance(addr, dict):
        home = addr.get('HOME_NET')
        if isinstance(home, str) and home.strip().lower() == 'any':
            c.add('broad_home_net_selector', line('vars', 'address-groups', 'HOME_NET'),
                  'HOME_NET explicitly covers any address', setting='vars.address-groups.HOME_NET',
                  observation='The uploaded YAML explicitly sets HOME_NET to any.',
                  implication='Network address classification may be broader than intended; the effective runtime variable value is not verified.',
                  recommendation='Confirm the protected networks, resolved variables and actual rule requirements before narrowing HOME_NET.')

    output_blocks = doc.get('outputs')
    if output_blocks is not None and not isinstance(output_blocks, list):
        c.partial('Suricata outputs is not a supported YAML sequence; output status was not inferred.')
    if isinstance(output_blocks, list):
        for i, out in enumerate(output_blocks[:100]):
            if not isinstance(out, dict) or len(out) != 1:
                c.partial('An outputs entry is not a simple one-plugin mapping; this output entry was not assessed.', 1)
                continue
            name, spec = next(iter(out.items()))
            if not isinstance(name, str) or not isinstance(spec, dict):
                c.partial('Unsupported output plugin structure; this entry was excluded.', 1)
                continue
            enabled = spec.get('enabled')
            if type(enabled) is bool:
                setting = f'outputs[{i}].{name}.enabled'
                if enabled:
                    s['outputs_explicitly_enabled'] += 1
                else:
                    s['outputs_explicitly_disabled'] += 1
                    if name in ('eve-log', 'fast', 'alert-debug', 'syslog', 'unified2-alert'):
                        c.add('explicit_alert_output_disabled', line('outputs', i, name, 'enabled'),
                              f'{name} output explicitly disabled', setting=setting,
                              observation=f'The {name} block has enabled: false in this upload.',
                              implication='That specific configured output is disabled; other outputs, external pipelines, and runtime overrides have not been assessed.',
                              recommendation='Confirm the intended alert pipeline and enable the required output only after checking operational deployment.')
            elif enabled is not None:
                c.partial(f'Unsupported enabled value in {name} output; active status was not inferred.', 1)
        if len(output_blocks) > 100:
            c.partial('Output list exceeds the first 100 entries; remaining entries not reviewed.', len(output_blocks) - 100)

    declared = []
    for mode in ('af-packet', 'pcap', 'netmap'):
        entries = doc.get(mode)
        if entries is None:
            continue
        if not isinstance(entries, list):
            c.partial(f'{mode} capture settings are not in the supported list form.', 1)
            continue
        for i, item in enumerate(entries[:100]):
            if not isinstance(item, dict):
                c.partial(f'{mode} capture entry is not a mapping.', 1)
                continue
            iface = _nonempty_str(item.get('interface'))
            if iface and iface != 'default':
                declared.append((mode, iface))
                s['interfaces_declared'] += 1
            if mode == 'af-packet' and _nonempty_str(item.get('copy-mode')) == 'ips':
                copy_iface = _nonempty_str(item.get('copy-iface'))
                if not copy_iface:
                    c.add('inline_pair_dependency', line('af-packet', i, 'copy-mode'),
                          'AF_PACKET IPS mode lacks an explicit copy-iface',
                          setting=f'af-packet[{i}].copy-mode',
                          observation=f'An af-packet entry sets copy-mode: ips; its copy-iface is not specified in the same entry.',
                          implication='A local inline-pair setting may be incomplete. Includes, runtime configuration and deployment have not been verified.',
                          recommendation='Review the full AF_PACKET inline interface pair and validate the running IPS configuration before making changes.')
        if len(entries) > 100:
            c.partial(f'{mode} capture entries exceeded 100; remaining entries skipped.', len(entries)-100)
    if declared:
        c.add('capture_interface_declarations', line(declared[0][0]),
              'Capture interfaces declared in YAML', setting=', '.join(f'{m}:{i}' for m, i in declared[:12]),
              observation=f'{len(declared)} explicit capture interface declaration(s) were found in supported blocks.',
              implication='This does not establish that those interfaces exist, are up, or are actually used by the running service.',
              recommendation='Confirm the live Suricata launch options and active capture interfaces.')

    files = doc.get('rule-files')
    if isinstance(files, list):
        if not files:
            c.add('no_explicit_rule_file_entries', line('rule-files'),
                  'No rule files explicitly listed', setting='rule-files',
                  observation='rule-files is an explicitly empty list in the uploaded YAML.',
                  implication='Rules might still come from runtime arguments or an external management process; no effective rule count can be inferred.',
                  recommendation='Inspect the deployed rule sources and confirm loaded signatures using the running engine.')
        else:
            count = sum(isinstance(f, str) and bool(f.strip()) for f in files)
            s['external_references'] += count
            if count != len(files):
                c.partial('Some rule-files entries are not nonempty strings; omitted from rule-file reference count.', len(files)-count)
            c.add('external_rule_files_unverified', line('rule-files'),
                  'Referenced rule files are external to this upload', setting='rule-files',
                  observation=f'{count} explicit rule file reference(s) were declared.',
                  implication='Their contents, existence, loading order and signature coverage cannot be inspected from this YAML alone.',
                  recommendation='Validate the rule directory, included files, loaded signature counts, and rule-update workflow on the target sensor.')
    elif files is not None:
        c.partial('rule-files is not a supported list; no rule-file conclusions were drawn.', 1)
    c.r['limitations'].append('Suricata review covers selected top-level settings in one safely parsed YAML document. YAML aliases, duplicate keys, custom constructors, output-specific semantics, runtime overrides and included rule contents are not assessed.')


_RULE = re.compile(r'^\s*(alert|drop|reject|pass|log|sdrop)\s+(tcp|udp|icmp|ip)\s+.+\(.*\)\s*$', re.I)
_SID = re.compile(r'(?<![a-z])sid\s*:\s*(\d+)\s*(?:;|\))', re.I)
_GID = re.compile(r'(?<![a-z])gid\s*:\s*(\d+)\s*(?:;|\))', re.I)
_HOME = re.compile(r'^\s*(?:ipvar|var)\s+HOME_NET\s+any\s*(?:#.*)?$', re.I)
_LUA_HOME = re.compile(r'^\s*HOME_NET\s*=\s*[\'\"]any[\'\"]\s*,?\s*(?:--.*)?$', re.I)
_INCLUDE = re.compile(r'^\s*include\s+(.+?)\s*$', re.I)
_OUTPUT = re.compile(r'^\s*output\s+(\S+)', re.I)


def _scan_snort(lines: list[str], c: _Collector) -> None:
    s = c.r['summary']
    seen_ids: dict[tuple[int, int], int] = {}
    lua_comment_closer: str | None = None
    for ln, raw in enumerate(lines, 1):
        # Snort 3 Lua multi-line comments are not executable rules.
        if lua_comment_closer is not None:
            if lua_comment_closer in raw:
                lua_comment_closer = None
            continue
        block_start = re.search(r'--\[(=*)\[', raw)
        if block_start:
            marker = ']' + block_start.group(1) + ']'
            if marker not in raw[block_start.end():]:
                lua_comment_closer = marker
            continue
        v = raw.strip()
        if not v or v.startswith(('#', '--', '//')):
            continue
        if _HOME.fullmatch(raw) or _LUA_HOME.fullmatch(raw):
            c.add('broad_home_net_selector', ln, 'HOME_NET explicitly set to any',
                  setting='HOME_NET', observation='The uploaded text explicitly sets HOME_NET to any in a recognized single-line declaration.',
                  implication='That selector may widen the protected address scope; variable expansion, includes and running configuration are not assessed.',
                  recommendation='Confirm the intended local subnet scope and rule dependencies before changing HOME_NET.')
        inc = _INCLUDE.match(raw)
        if inc:
            s['external_references'] += 1
            c.add('external_include_unverified', ln, 'External Snort include is not inspected',
                      setting=inc.group(1)[:150], observation='An include directive references content outside this upload.',
                      implication='Rules/settings defined in the referenced file might alter the effective configuration; the file was not opened.',
                      recommendation='Review the resolved include path and deployed rule loading order.')
        out = _OUTPUT.match(raw)
        if out:
            s['outputs_declared'] += 1
            c.add('output_directive_declared', ln, 'Snort output directive present',
                      setting=out.group(1)[:80], observation='An output directive is explicitly present in the supplied configuration text.',
                      implication='This indicates configuration intent, not successful output plugin startup or alert delivery.',
                      recommendation='Confirm output module/plugin loading and test end-to-end alert delivery on the sensor.')
        # A Snort 3 Lua table is not executed or deeply parsed. Report only
        # unambiguously single-line, balanced-looking rule syntax.
        if not _RULE.fullmatch(raw):
            continue
        if s['rules_inspected'] >= MAX_RULES:
            c.partial('More than 2000 inline rule lines found; remaining rules were excluded.', 1)
            continue
        sid = _SID.search(raw)
        if not sid:
            c.partial('A supported inline rule lacked an explicit numeric sid; it was not used for duplicate-SID analysis.', 1)
            continue
        gid = _GID.search(raw)
        rid = (int(gid.group(1)) if gid else 1, int(sid.group(1)))
        s['rules_inspected'] += 1
        if rid in seen_ids:
            s['duplicate_rule_ids'] += 1
            c.add('duplicate_inline_rule_identifier', ln, 'Repeated GID/SID in inspected inline rules',
                  setting=f'gid:{rid[0]}, sid:{rid[1]}',
                  observation=f'The same GID/SID appears on source lines {seen_ids[rid]} and {ln} among recognized single-line inline rules.',
                  implication='Repeated identifiers can cause ambiguity or rule-loading problems; rule overrides and actual engine behavior are not established.',
                  recommendation='Confirm the intended unique identifiers, rule revisions and deployed rule loader behavior before editing signatures.')
        else:
            seen_ids[rid] = ln
    if s['rules_inspected'] == 0:
        c.r['limitations'].append('No supported single-line inline Snort rules with explicit SID were inspected; included or separately loaded rules may still exist.')
    c.r['limitations'].append('Snort 2 conf and Snort 3 Lua are not fully parsed. Only standalone include/output/HOME_NET declarations and single-line inline rules with SIDs are inspected. Multiline signatures, Lua evaluation, runtime rule inclusion and policy precedence are excluded.')


def review_ids_configuration(platform_id: str, source: str, *, source_truncated: bool = False) -> dict[str, Any]:
    """Return conservative, versioned advisory evidence; caller retains all prior report keys."""
    if platform_id not in ('cisco_asa', 'fortios', 'snort', 'suricata'):
        raise ValueError(f'Unsupported normalized platform: {platform_id}')
    report = _new_review(platform_id)
    if platform_id in ('cisco_asa', 'fortios'):
        report['status'] = 'not_applicable'
        report['limitations'] = ['IDS Snort/Suricata configuration review does not apply to a firewall configuration upload.']
        return report
    c = _Collector(report)
    if not isinstance(source, str):
        raise TypeError('source must be a string')
    lines = source.splitlines()
    if len(lines) > MAX_LINES:
        c.partial(f'Input contains more than {MAX_LINES} lines. Only the first {MAX_LINES} lines are considered.', len(lines)-MAX_LINES)
        lines = lines[:MAX_LINES]
    if any(len(line) > MAX_LINE_LENGTH for line in lines):
        c.partial('Input includes an overlong line; review halted rather than silently dropping configuration content.')
        lines = []
    if source_truncated:
        c.partial('Uploaded file exceeded 2 MiB or contained invalid UTF-8; full configuration was not inspected.')
    if lines:
        if platform_id == 'suricata':
            _scan_suricata('\n'.join(lines), c)
        else:
            _scan_snort(lines, c)
    else:
        c.partial('Empty or unsupported source text: no valid configuration review was possible.')
    report['status'] = 'limited' if c.incomplete else 'reviewed_subset'
    report['summary']['evidence_items'] = len(report['evidence'])
    report['summary']['items_omitted'] = c.omitted
    report['summary']['incomplete'] = c.incomplete
    return report
