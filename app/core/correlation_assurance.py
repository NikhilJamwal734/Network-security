"""API-010.4: bounded post-correlation evidence/order audit.

Advisory only; does not parse arbitrary vendor grammars, simulate traffic, execute
uploaded configurations, or alter existing findings/scores. Evidence verification
means only that the referenced line is present and resembles the expected syntax.
"""
from __future__ import annotations

from collections import Counter
import re
from typing import Any

MAX_ASSURANCE_LINES = 50_000
MAX_ASSURANCE_ITEMS = 70
_ASA_SEQUENCE = re.compile(r'^\s*access-list\s+(?P<name>\S+)\s+line\s+(?P<sequence>\d{1,6})\s+extended\b', re.I)
_ASA_ENTRY = re.compile(r'^\s*access-list\s+\S+\s+(?:line\s+\d{1,6}\s+)?extended\s+', re.I)
_IDS_RULE = re.compile(r'^\s*(?:alert|log|pass|drop|reject|rejectsrc|rejectdst|rejectboth|sdrop|activate|dynamic)\s+', re.I)
_SUPPORTED = frozenset(('cisco_asa', 'fortios', 'snort', 'suricata'))


def _line(lines: list[str], number: Any) -> str | None:
    """Retrieve a real source line without interpreting or disclosing its text."""
    if type(number) is not int or not (1 <= number <= len(lines)):
        return None
    return lines[number - 1]


def _reference_matches(platform: str, raw: str | None) -> bool:
    if raw is None:
        return False
    if platform == 'cisco_asa':
        return bool(_ASA_ENTRY.match(raw))
    if platform == 'fortios':
        return bool(re.match(r'^\s*edit\s+\S+', raw, re.I))
    return bool(_IDS_RULE.match(raw))  # commented-out IDS rules do NOT count


def _sequence(raw: str) -> tuple[str, int] | None:
    match = _ASA_SEQUENCE.match(raw)
    return (match.group('name'), int(match.group('sequence'))) if match else None


def verify_correlations(platform: str, source: str, correlation: dict[str, Any], *,
                        source_truncated: bool = False) -> dict[str, Any]:
    """Classify confidence limits in API-010.3 pairs without changing those pairs.

    Pair references are validated for syntactic source presence only. No checks
    assert object expansion, policy binding, effective firewall order or IDS
    option behavior. Call only after the original upload security checks pass.
    """
    if platform not in _SUPPORTED:
        raise ValueError('Unsupported platform for API-010.4 assurance')
    if not isinstance(source, str) or not isinstance(correlation, dict):
        raise TypeError('Invalid correlation assurance input')
    original_lines = source.splitlines()
    line_limit = len(original_lines) > MAX_ASSURANCE_LINES
    lines = original_lines[:MAX_ASSURANCE_LINES]
    pairs = correlation.get('pairs', [])
    if not isinstance(pairs, list):
        raise ValueError('Correlation pairs must be a list')
    items: list[dict[str, Any]] = []
    for pair in pairs[:MAX_ASSURANCE_ITEMS]:
        if not isinstance(pair, dict):
            continue
        evidence = pair.get('evidence', {})
        if not isinstance(evidence, dict):
            evidence = {}
        first_number = evidence.get('related_line_number')
        second_number = evidence.get('line_number')
        first = _line(lines, first_number)
        second = _line(lines, second_number)
        valid = (_reference_matches(platform, first) and _reference_matches(platform, second)
                 and first_number != second_number)
        if not valid:
            status = 'evidence_unavailable'
            explanation = 'One or both referenced rules could not be confirmed at the reported source lines.'
            next_action = 'Inspect the original configuration and verify both source references.'
        elif platform == 'cisco_asa':
            a = _sequence(first or '')
            b = _sequence(second or '')
            if a and b and a[0] == b[0] and a[1] > b[1]:
                status = 'ordering_contradicted'
                explanation = (f'The first cited ACE has explicit line {a[1]}, while the second has line {b[1]}. '
                               'Their explicit sequence contradicts source-file ordering; an earlier-first shadowing claim is not justified.')
                next_action = 'Verify actual ASA ACL sequence on the device. Do not remove either ACE based on this candidate.'
            elif a and b and a[0] == b[0] and a[1] < b[1]:
                status = 'order_supported_candidate'
                explanation = (f'Explicit ASA ACL line labels ({a[1]} then {b[1]}) agree with the candidate order. '
                               'The overlap remains conditional on binding, objects and actual device state.')
                next_action = 'Confirm interface/direction binding and effective ACL entries before changing policy.'
            else:
                status = 'order_unverified'
                explanation = 'Both ACEs are present, but explicit comparative ACL sequence is not established.'
                next_action = 'Check the effective ACL sequence and interface bindings on the target ASA.'
        elif platform == 'fortios':
            status = 'object_resolution_required'
            explanation = ('Both policy edit locations are present, but named addresses/services, VDOM scope, '
                           'effective policy order, and enabled state are not independently verified here.')
            next_action = 'Resolve referenced objects and confirm policy ordering in the correct VDOM.'
        else:
            status = 'ids_options_unverified'
            explanation = ('Both enabled-looking IDS rule headers are present. Matching headers do not establish '
                           'matching rule options, content predicates, action precedence, or IPS runtime effects.')
            next_action = 'Compare full rule options and test engine behavior in an isolated validation environment.'
        items.append(dict(
            correlation_id=str(pair.get('correlation_id', ''))[:48],
            status=status,
            evidence_present=bool(valid),
            related_line_number=first_number if type(first_number) is int else None,
            line_number=second_number if type(second_number) is int else None,
            explanation=explanation,
            next_action=next_action,
        ))
    counts = Counter(item['status'] for item in items)
    truncated = bool(source_truncated or line_limit or len(pairs) > MAX_ASSURANCE_ITEMS
                     or correlation.get('summary', {}).get('truncated', False))
    return dict(
        version='1.0', platform_id=platform,
        scope='correlation_evidence_and_order_advisory',
        status='limited' if truncated or counts['evidence_unavailable'] else 'reviewed_subset',
        summary=dict(pairs_reviewed=len(items), evidence_present=sum(i['evidence_present'] for i in items),
                     evidence_unavailable=counts['evidence_unavailable'],
                     ordering_contradictions=counts['ordering_contradicted'],
                     by_status=dict(sorted(counts.items())), truncated=truncated),
        items=items,
        limitations=[
            'Presence at a source line validates citation integrity only; it does not validate real-world network security.',
            'No rule or configuration is executed, modified or automatically remediated.',
            'Existing findings, severity counts, provisional scores and API-010.3 pairs are preserved.',
            'ASA explicit ACL line numbers are reviewed only when present on both ACEs in the same named ACL.',
            'FortiOS referenced objects/VDOM/rule order and IDS rule options/runtime behavior are not resolved.',
        ] + (['Processing or input limits reached; results are incomplete.'] if truncated else []),
    )
