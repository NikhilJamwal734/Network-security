"""API-011.0: bounded, read-only consolidation of previous analysis evidence.

This module does NOT deduplicate, alter, or re-score security findings. It
catalogues known review sections, flags internal metadata inconsistencies, and
links strictly matching advisory signals for analyst triage. One upload
represents one platform, not a multi-device deployment.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any

PLATFORMS = frozenset({'cisco_asa', 'fortios', 'snort', 'suricata'})
# Known keys only: unknown stages are never guessed from arbitrary report fields.
REGISTRY = (
    ('normalized_findings', 'findings', 'all'),
    ('object_resolution', 'object_resolution', 'firewall'),
    ('object_assurance', 'object_assurance', 'firewall'),
    ('service_ipv6', 'service_ipv6', 'firewall'),
    ('nat_route_reachability', 'nat_route_reachability', 'firewall'),
    ('ids_deep_review', 'ids_deep_review', 'ids'),
)
LIMIT_PER_SOURCE = 400
MAX_EXAMINED = 1500
MAX_ISSUES = 36
MAX_LINKS = 24
MAX_STR = 180


def _short(value: Any, limit: int = MAX_STR) -> str:
    return value.strip()[:limit] if isinstance(value, str) else ''


def _int(value: Any) -> int | None:
    return value if type(value) is int and value >= 0 else None


def _line(item: dict[str, Any]) -> int | None:
    return _int(item.get('line_number'))


def _entries(value: Any, name: str) -> tuple[list[tuple[str, dict[str, Any]]], bool]:
    """Return observed bounded entries without trusting unknown data shapes."""
    if name == 'normalized_findings':
        return [(str(i), x) for i, x in enumerate(value[:LIMIT_PER_SOURCE]) if isinstance(x, dict)], len(value) > LIMIT_PER_SOURCE
    result: list[tuple[str, dict[str, Any]]] = []
    limited = False
    for field in ('evidence', 'pairs', 'candidates'):
        val = value.get(field)
        if not isinstance(val, list):
            continue
        budget = LIMIT_PER_SOURCE - len(result)
        for i, item in enumerate(val[:max(0, budget)]):
            if isinstance(item, dict):
                result.append((f'{field}[{i}]', item))
        if len(val) > max(0, budget):
            limited = True
        if len(result) >= LIMIT_PER_SOURCE:
            break
    return result, limited


def consolidate_report(report: dict[str, Any]) -> dict[str, Any]:
    """Summarize cross-review evidence with explicit provenance and abstention.

    No source strings are used as Python paths, regex, executables, or fetched.
    The supplied `report` is never mutated. Large collections are capped.
    """
    if not isinstance(report, dict):
        raise ValueError('Expected a normalized response mapping')
    platform_obj = report.get('platform')
    platform = _short(platform_obj.get('platform_id'), 64) if isinstance(platform_obj, dict) else ''
    if platform not in PLATFORMS:
        raise ValueError('Missing or unsupported normalized platform_id')
    applicable = 'ids' if platform in {'snort', 'suricata'} else 'firewall'
    sections: list[dict[str, Any]] = []
    issues: list[dict[str, Any]] = []
    links: list[dict[str, Any]] = []
    # Keyed on exact same source line AND code/kind AND title, AND different
    # named review sections. A line match alone is never evidence of duplication.
    by_signature: dict[tuple[int, str, str], list[dict[str, Any]]] = defaultdict(list)
    summary = {
        'sections_present': 0, 'sections_unavailable': 0,
        'advisory_items_examined': 0, 'candidate_links': 0,
        'quality_observations': 0, 'limited_sections': 0,
        'items_omitted': 0, 'incomplete': False,
    }
    limitations = [
        'Only one uploaded device/sensor configuration is considered at a time; no cross-device rule matching or estate-wide reachability is inferred.',
        'An advisory cross-review link is not a confirmed duplicate, false positive, vulnerability or safely removable finding.',
        'Previous findings, severities, scores and all other response fields are preserved without alteration.',
        'Unavailable, partial and unsupported analysis do not imply that the configuration is safe.',
    ]

    def issue(kind: str, section: str, observation: str, recommendation: str,
              line: int | None = None) -> None:
        summary['quality_observations'] += 1
        if len(issues) >= MAX_ISSUES:
            summary['items_omitted'] += 1
            summary['incomplete'] = True
            return
        issues.append({
            'reference': f'CON-{len(issues) + 1:03d}', 'kind': kind,
            'section': section, 'source_line': line,
            'observation': observation[:500], 'recommendation': recommendation[:500],
            'confidence': 'report_metadata_only',
        })

    for name, key, family in REGISTRY:
        expected = family == 'all' or family == applicable
        raw = report.get(key)
        if raw is None:
            if expected:
                summary['sections_unavailable'] += 1
            sections.append({'name': name, 'availability': 'not_returned', 'status': 'unavailable',
                             'items_examined': 0, 'items_omitted': 0, 'applicable': expected})
            continue
        if (name == 'normalized_findings' and not isinstance(raw, list)) or (name != 'normalized_findings' and not isinstance(raw, dict)):
            summary['sections_unavailable'] += int(expected)
            sections.append({'name': name, 'availability': 'invalid_shape', 'status': 'limited',
                             'items_examined': 0, 'items_omitted': 0, 'applicable': expected})
            if expected:
                issue('invalid_review_shape', name, 'Review response has an unexpected data shape.',
                      'Validate the API response schema before interpreting the review.')
            continue
        status = _short(raw.get('status'), 64) if isinstance(raw, dict) else 'reported'
        meta = raw.get('summary') if isinstance(raw, dict) else None
        meta = meta if isinstance(meta, dict) else {}
        declared_incomplete = meta.get('incomplete') is True
        # Status may use not_assessed or not_applicable across old stages.
        limited_status = status in ('limited', 'not_assessed', 'not_applicable', 'unavailable')
        explicit_limited = declared_incomplete or (limited_status and expected)
        if explicit_limited:
            summary['limited_sections'] += 1
        review_platform = raw.get('platform_id') if isinstance(raw, dict) else None
        if review_platform is not None and review_platform != platform and not limited_status:
            issue('platform_context_mismatch', name,
                  f'Review platform does not match normalized platform ({platform}).',
                  'Check platform routing and identify the actual uploaded configuration.')
        entries, capped = _entries(raw, name)
        available_budget = max(0, MAX_EXAMINED - summary['advisory_items_examined'])
        omitted = int(meta.get('items_omitted') or 0) if _int(meta.get('items_omitted')) is not None else 0
        omitted += int(meta.get('candidates_omitted') or 0) if _int(meta.get('candidates_omitted')) is not None else 0
        if capped:
            omitted += 1  # minimum known unexamined items, not fabricated exact count
        if len(entries) > available_budget:
            omitted += len(entries) - available_budget
            entries = entries[:available_budget]
        if omitted or declared_incomplete:
            summary['incomplete'] = True
            summary['items_omitted'] += omitted
        summary['advisory_items_examined'] += len(entries)
        summary['sections_present'] += 1
        sections.append({'name': name, 'availability': 'returned', 'status': status or 'unspecified',
                         'items_examined': len(entries), 'items_omitted': omitted,
                         'applicable': expected})
        declared_count = _int(meta.get('evidence_items'))
        if declared_count is not None and isinstance(raw, dict) and isinstance(raw.get('evidence'), list) and declared_count != len(raw['evidence']):
            issue('reported_count_mismatch', name,
                  'Reported evidence_items does not match returned evidence array length.',
                  'Compare backend review serialization and its item-limit policy.')
        if not expected or limited_status:
            # No cross-review link inference from stages marked non-applicable.
            continue
        for locator, entry in entries:
            line = _line(entry)
            # Each item's source line may refer to upload or normalized rule data.
            if line is None or line < 1:
                continue
            identifier = _short(entry.get('code') or entry.get('kind'), 96).casefold()
            title = _short(entry.get('title'), 120).casefold()
            if not identifier or not title:
                continue
            # Never collapse multiple observations from a single review.
            by_signature[(line, identifier, title)].append({
                'section': name, 'locator': locator,
                'reference': _short(entry.get('reference') or entry.get('code') or entry.get('rule_id'), 96),
                'source_line': line,
            })
    if summary['items_omitted'] > 0 or summary['advisory_items_examined'] >= MAX_EXAMINED:
        summary['incomplete'] = True
    for (line, identifier, title), refs in sorted(by_signature.items()):
        distinct = {r['section'] for r in refs}
        if len(distinct) < 2:
            continue
        if len(links) >= MAX_LINKS:
            summary['items_omitted'] += 1
            summary['incomplete'] = True
            continue
        links.append({
            'reference': f'LINK-{len(links) + 1:03d}',
            'kind': 'possible_same_source_signal',
            'source_line': line, 'signal': identifier,
            'title': title,
            'related': refs[:8],
            'reason': 'The same line, signal identifier and title appear in distinct review sections.',
            'recommendation': 'Manually inspect the two contexts before deciding whether either observation is redundant.',
            'confidence': 'exact_metadata_match_not_semantic_equivalence',
        })
    summary['candidate_links'] = len(links)
    if summary['items_omitted']:
        limitations.append('An explicit bounded processing limit was reached; omitted items were not evaluated for links or quality observations.')
    if summary['sections_unavailable'] or summary['limited_sections']:
        limitations.append('Some expected review sections are missing, limited or not assessed; this inventory is not a completeness certification.')
    return {
        'version': '1.0', 'platform_id': platform,
        'scope': 'cross_review_evidence_consistency_single_upload',
        'status': 'limited' if summary['incomplete'] or summary['sections_unavailable'] or summary['limited_sections'] else 'reviewed_subset',
        'summary': summary, 'sections': sections, 'issues': issues,
        'links': links, 'limitations': limitations,
    }
