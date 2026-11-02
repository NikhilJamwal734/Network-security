"""API-010.2.1: conservative precision-review extensions.

Only called by the opt-in /precision-review endpoint. No scoring, severity
counts, normalized findings, legacy endpoints, or external files are changed.
Untrusted uploaded text is parsed as data; no config commands are executed.
"""
from __future__ import annotations

from collections import defaultdict, Counter
import ipaddress
from typing import Any

from app.parsers.firewalls.fortios import FortiOSParser
from app.parsers.ids.snort import SnortParser, _split_options
from app.parsers.ids.suricata import SuricataParser

MAX_RESULTS = 40
MAX_EVIDENCE_LINES = 6


def _check(code: str, severity: str, title: str, detail: str,
           recommendation: str, line_number: int | None,
           rule_id: str | int | None = None) -> dict[str, Any]:
    return dict(code=code, severity=severity, title=title, detail=detail,
                recommendation=recommendation, line_number=line_number, rule_id=rule_id)


def _identity(check: dict[str, Any]) -> tuple[Any, Any, Any]:
    return check.get('code'), check.get('line_number'), check.get('rule_id')


def _asa(lines: list[str]) -> list[dict[str, Any]]:
    ssh_version: tuple[str, int] | None = None
    http_enabled: bool | None = None
    active_http: dict[tuple[str, str, str], int | None] = {}
    for number, raw in enumerate(lines, 1):
        line = raw.strip().lower()
        if not line or line.startswith(('#', '!')):
            continue
        parts = line.split()
        if len(parts) == 3 and parts[:2] == ['ssh', 'version'] and parts[2] in ('1', '2'):
            ssh_version = (parts[2], number)
        elif parts == ['no', 'ssh', 'version', '1']:
            ssh_version = None
        elif parts == ['http', 'server', 'enable']:
            http_enabled = True
        elif parts == ['no', 'http', 'server', 'enable']:
            http_enabled = False
        else:
            negate = parts[:1] == ['no']
            args = parts[1:] if negate else parts
            if len(args) != 4 or args[0] != 'http':
                continue
            try:
                source = ipaddress.IPv4Address(args[1])
                mask = ipaddress.IPv4Address(args[2])
            except ipaddress.AddressValueError:
                continue
            if int(source) != 0 or int(mask) != 0:
                continue
            key = (args[1], args[2], args[3])
            active_http[key] = None if negate else number
    checks: list[dict[str, Any]] = []
    if ssh_version is not None and ssh_version[0] == '1':
        checks.append(_check('ASA-PREC2-001', 'HIGH', 'SSHv1 explicitly selected',
            'The last visible SSH version selection requests version 1. Device support and effective state are not verified.',
            'Use an approved modern SSH version and confirm the deployed device supports it.', ssh_version[1]))
    if http_enabled is True:
        for (_, _, iface), line in active_http.items():
            if line is not None:
                checks.append(_check('ASA-PREC2-002', 'MEDIUM', 'Broad ASA ASDM/HTTPS management selector',
                    f'An active http management selector accepts all IPv4 source addresses on interface {iface}. '
                    'The http selector can control ASDM/HTTPS management; it is not evidence of cleartext HTTP or Internet exposure.',
                    'Limit ASDM management sources and verify interface ACL, routing, and administrator access.', line))
    return checks


def _fortios(lines: list[str]) -> list[dict[str, Any]]:
    conf = FortiOSParser().parse(lines)
    repeated = {id for id, count in Counter(p.identifier for p in conf.policies).items() if count > 1}
    checks: list[dict[str, Any]] = []
    for policy in conf.policies:
        if policy.identifier in repeated:
            continue  # Multiple partial edits: effective setting is not established.
        action = {x.lower() for x in policy.get('action')}
        status = {x.lower() for x in policy.get('status')}
        utm = {x.lower() for x in policy.get('utm-status')}
        if 'accept' in action and 'disable' not in status and 'disable' in utm:
            checks.append(_check('FORTIOS-PREC2-001', 'LOW', 'UTM explicitly disabled on accept policy',
                'An accept policy explicitly sets utm-status to disable. This does not establish that traffic lacks '
                'other protections or that this policy can be reached.',
                'Check whether this specific policy requires UTM security profiles and validate its effective policy path.',
                policy.line_number, policy.identifier))
    return checks


def _snort_rule_gid(lines: list[str], rule: Any) -> int | None:
    """Default GID=1; unknown/malformed explicit generator IDs are not compared."""
    if 'gid' not in rule.option_names:
        return 1
    if not 1 <= rule.line_number <= len(lines):
        return None
    raw = lines[rule.line_number - 1]
    # The supported parser only admits one-line rule syntax.
    head, sep, remainder = raw.partition('(')
    if not sep or ')' not in remainder:
        return None
    options = remainder.rsplit(')', 1)[0]
    try:
        values = [part.partition(':')[2].strip() for part in _split_options(options)
                  if part.partition(':')[0].strip().lower() == 'gid']
    except ValueError:
        return None
    if len(values) != 1 or not values[0].isascii() or not values[0].isdigit() or len(values[0]) > 12:
        return None
    gid = int(values[0])
    return gid if gid > 0 else None


def _ids_duplicate_checks(platform: str, lines: list[str]) -> list[dict[str, Any]]:
    if platform == 'snort':
        rules = SnortParser().parse(lines).rules
    else:
        rules = SuricataParser().parse(lines).rules
    by_identity: dict[tuple[int, int], list[int]] = defaultdict(list)
    for rule in rules:
        if not rule.enabled or rule.sid is None:
            continue
        gid = _snort_rule_gid(lines, rule) if platform == 'snort' else rule.gid
        if gid is None:
            continue
        by_identity[(gid, rule.sid)].append(rule.line_number)
    checks: list[dict[str, Any]] = []
    for (gid, sid), positions in by_identity.items():
        if len(positions) < 2:
            continue
        evidence = ', '.join(str(n) for n in positions[:MAX_EVIDENCE_LINES])
        if len(positions) > MAX_EVIDENCE_LINES:
            evidence += ', ...'
        name = 'Snort' if platform == 'snort' else 'Suricata'
        code = 'SNORT-PREC-001' if platform == 'snort' else 'SURICATA-PREC-001'
        checks.append(_check(code, 'MEDIUM', f'Duplicate enabled {name} GID/SID',
            f'{len(positions)} enabled parsed rules declare GID/SID {gid}:{sid}; source lines: {evidence}. '
            'Only the uploaded file was inspected; included rules, processing order, and effective activation are unknown.',
            'Review and de-duplicate identifiers in the complete deployed rule inventory.',
            positions[1], f'{gid}:{sid}'))
    return checks


def augment_precision_review(platform: str, lines: list[str], report: dict[str, Any]) -> dict[str, Any]:
    """Add narrowly grounded observations and improve duplicate-ID evidence.

    Never mutates its input, and never modifies findings, scoring or risk.
    Existing precision review metadata remains available for older frontend code.
    """
    if platform not in ('cisco_asa', 'fortios', 'snort', 'suricata'):
        raise ValueError('Unsupported platform')
    existing = list(report.get('checks', []))
    if platform in ('snort', 'suricata'):
        duplicate_code = 'SNORT-PREC-001' if platform == 'snort' else 'SURICATA-PREC-001'
        existing = [item for item in existing if item.get('code') != duplicate_code]
        added = _ids_duplicate_checks(platform, lines)
    elif platform == 'cisco_asa':
        added = _asa(lines)
    else:
        added = _fortios(lines)

    unique: dict[tuple[Any, Any, Any], dict[str, Any]] = {}
    for entry in [*existing, *added]:
        unique.setdefault(_identity(entry), entry)
    checks = list(unique.values())
    precision = dict(report.get('precision') or {})
    old_keys = {_identity(c) for c in report.get('checks', [])}
    new_keys = set(unique)
    precision['suppressed_preliminary_checks'] = int(precision.get('suppressed_preliminary_checks', 0)) + len(old_keys - new_keys)
    precision['additional_evidence_checks'] = int(precision.get('additional_evidence_checks', 0)) + len(new_keys - old_keys)
    precision['enhanced_version'] = '1.1'
    precision['source_line_references'] = sum(isinstance(c.get('line_number'), int) and c['line_number'] > 0 for c in checks[:MAX_RESULTS])
    precision['note'] = (
        str(precision.get('note', '')).strip() + ' '
        'Enhanced review: findings cite uploaded source lines when known. '
        'Coverage remains partial; configuration observations are not proof of effective exposure.'
    ).strip()
    updated = dict(report)
    updated['checks'] = checks[:MAX_RESULTS]
    updated['suppressed_checks'] = int(report.get('suppressed_checks', 0)) + max(0, len(checks) - MAX_RESULTS)
    updated['limitations'] = list(report.get('limitations', [])) + [
        'This enhancement assesses explicit supported settings only; it cannot resolve effective vendor defaults, complete deployment, includes, or runtime policy.',
        'Snort duplicate rule identity uses GID/SID when generator ID is valid; malformed generator IDs are excluded, not guessed.',
    ]
    updated['precision'] = precision
    return updated
