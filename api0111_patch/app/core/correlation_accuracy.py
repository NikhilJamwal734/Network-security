"""API 011.1: bounded, explainable verification of single-upload advisory correlations.

No mutation, severity adjustment, finding removal, external I/O, or claim that
an alert, route, vulnerability or duplicate has been verified operationally.
All output is explicitly report-metadata-only and PDF-first.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any

SUPPORTED = frozenset({'cisco_asa', 'fortios', 'snort', 'suricata'})
REVIEW_FAMILY = {
    'normalized_findings': 'all',
    'object_resolution': 'firewall', 'object_assurance': 'firewall',
    'service_ipv6': 'firewall', 'nat_route_reachability': 'firewall',
    'ids_deep_review': 'ids',
}
MAX_FINDINGS = 600
MAX_LINKS = 160
MAX_ENTRIES_PER_SECTION = 500
MAX_DECISIONS = 80
MAX_OBSERVATIONS = 80
MAX_TEXT = 160


def _text(value: Any, limit: int = MAX_TEXT) -> str:
    return value.strip()[:limit] if isinstance(value, str) else ''


def _line(value: Any) -> int | None:
    return value if type(value) is int and value > 0 else None


def _is_applicable(platform: str, section: str) -> bool:
    family = REVIEW_FAMILY.get(section)
    return family == 'all' or family == ('ids' if platform in ('snort', 'suricata') else 'firewall')


def _get_entries(report: dict[str, Any], section: str) -> tuple[list[tuple[str, dict[str, Any]]], int, bool]:
    """Canonical locators match 11.0 consolidation's bounded source shape."""
    raw = report.get('findings') if section == 'normalized_findings' else report.get(section)
    if section == 'normalized_findings':
        if not isinstance(raw, list):
            return [], 0, False
        cap = min(len(raw), MAX_ENTRIES_PER_SECTION)
        return [(str(i), x) for i, x in enumerate(raw[:cap]) if isinstance(x, dict)], max(0, len(raw)-cap), True
    if not isinstance(raw, dict):
        return [], 0, False
    if raw.get('status') in ('limited', 'unavailable', 'not_assessed', 'not_applicable'):
        return [], 0, False  # Never infer a link from explicitly uncertain sections.
    result: list[tuple[str, dict[str, Any]]] = []
    omitted = 0
    for key in ('evidence', 'pairs', 'candidates'):
        items = raw.get(key)
        if not isinstance(items, list):
            continue
        slots = max(0, MAX_ENTRIES_PER_SECTION - len(result))
        result.extend((f'{key}[{i}]', item) for i, item in enumerate(items[:slots]) if isinstance(item, dict))
        omitted += max(0, len(items) - slots)
    if isinstance(raw.get('summary'), dict) and raw['summary'].get('incomplete') is True:
        # Observations in incomplete review can be inspected, but not used to
        # affirm a possible overlap when the broader source may be missing.
        return result, omitted, False
    return result, omitted, True


def _signature(entry: dict[str, Any]) -> tuple[int, str, str] | None:
    line = _line(entry.get('line_number'))
    code = _text(entry.get('code') or entry.get('kind'), 96).casefold()
    title = _text(entry.get('title'), 120).casefold()
    return (line, code, title) if line and code and title else None


def review_correlation_accuracy(report: dict[str, Any]) -> dict[str, Any]:
    """Reassess supplied 11.0 candidate links using the source report, never edit it.

    Not a calibrated false-positive detector. A rejected link means its supplied
    provenance cannot be established, not that any underlying security finding
    is itself a false positive.
    """
    if not isinstance(report, dict):
        raise ValueError('Expected normalized response dictionary')
    platform_data = report.get('platform')
    platform = _text(platform_data.get('platform_id'), 64) if isinstance(platform_data, dict) else ''
    if platform not in SUPPORTED:
        raise ValueError('Missing or unsupported normalized platform_id')
    source = report.get('consolidation_review')
    if not isinstance(source, dict):
        raise ValueError('API-011.0 consolidation_review is required before API-011.1')
    if source.get('platform_id') != platform:
        raise ValueError('Consolidation platform differs from report platform')

    summary: dict[str, int | bool] = {
        'links_checked': 0, 'plausible_links': 0, 'unsupported_links': 0,
        'uncertain_links': 0, 'finding_metadata_pairs': 0,
        'severity_conflicts': 0, 'findings_without_line': 0,
        'items_omitted': 0, 'incomplete': False,
    }
    decisions: list[dict[str, Any]] = []
    observations: list[dict[str, Any]] = []
    limitations = [
        'Static single-upload metadata only. This assessment is not a measured false-positive rate, runtime verification, or proof that findings are duplicates.',
        'No security findings, scores, severities or existing review sections have been modified, filtered, hidden or removed.',
        'An unsupported correlation link is NOT evidence that either underlying security finding is false.',
        'Source line and matching text cannot establish equivalent semantics, effective enforcement, network reachability or alert delivery.',
        'External rule files, included objects, dynamic configurations, traffic flows and device state are outside this review.',
    ]

    def observe(kind: str, line: int | None, reason: str, action: str) -> None:
        if len(observations) >= MAX_OBSERVATIONS:
            summary['items_omitted'] += 1
            summary['incomplete'] = True
            return
        observations.append({
            'reference': f'ACC-{len(observations)+1:03d}', 'kind': kind,
            'source_line': line, 'reason': reason[:350], 'recommendation': action[:350],
            'confidence': 'metadata_only',
        })

    raw_findings = report.get('findings')
    if not isinstance(raw_findings, list):
        observe('normalized_findings_missing', None, 'Normalized finding list is missing or invalid.',
                'Check normalized report construction before evaluating possible duplicates.')
        summary['incomplete'] = True
        raw_findings = []
    if len(raw_findings) > MAX_FINDINGS:
        summary['items_omitted'] += len(raw_findings) - MAX_FINDINGS
        summary['incomplete'] = True
    seen: dict[tuple[int, str, str, str], dict[str, Any]] = {}
    # Exact reported identity is only an advisory potential overlap; rule_id
    # narrows collisions, but still does not prove duplicates.
    for finding in raw_findings[:MAX_FINDINGS]:
        if not isinstance(finding, dict):
            continue
        line = _line(finding.get('line_number'))
        if line is None:
            summary['findings_without_line'] += 1
            continue
        code = _text(finding.get('code'), 96).casefold()
        title = _text(finding.get('title'), 120).casefold()
        if not code or not title:
            continue
        rule_id = str(finding.get('rule_id'))[:64] if finding.get('rule_id') is not None else ''
        sig = (line, code, title, rule_id)
        earlier = seen.get(sig)
        if earlier is not None:
            summary['finding_metadata_pairs'] += 1
            sev1, sev2 = _text(earlier.get('severity')).upper(), _text(finding.get('severity')).upper()
            if sev1 and sev2 and sev1 != sev2:
                summary['severity_conflicts'] += 1
                observe('severity_disagreement', line,
                        'Entries with matching identifiers, title, source line and rule reference have different reported severities.',
                        'Inspect the underlying normalized finding sources; do not auto-reclassify either entry.')
            elif summary['finding_metadata_pairs'] <= 10:
                observe('possible_repeated_finding_metadata', line,
                        'Two normalized findings share code, title, line and rule reference; this does not prove identical root causes.',
                        'Verify each finding against the original configuration and analyzer rule before considering deduplication.')
        else:
            seen[sig] = finding

    links = source.get('links')
    if not isinstance(links, list):
        observe('link_list_unavailable', None, 'Consolidation link list is missing or invalid.',
                'Validate the API-011.0 report structure.')
        summary['incomplete'] = True
        links = []
    if len(links) > MAX_LINKS:
        summary['items_omitted'] += len(links)-MAX_LINKS
        summary['incomplete'] = True
    cached: dict[str, tuple[dict[str, dict[str, Any]], bool]] = {}

    def section_data(name: str):
        if name not in cached:
            entries, omitted, complete = _get_entries(report, name)
            summary['items_omitted'] += omitted
            if omitted:
                summary['incomplete'] = True
            cached[name] = (dict(entries), complete and omitted == 0)
        return cached[name]

    for i, link in enumerate(links[:MAX_LINKS]):
        summary['links_checked'] += 1
        reason, outcome = '', 'unsupported_metadata_link'
        ref = _text(link.get('reference'), 64) if isinstance(link, dict) else ''
        line = _line(link.get('source_line')) if isinstance(link, dict) else None
        related = link.get('related') if isinstance(link, dict) else None
        if not isinstance(related, list) or len(related) < 2 or len(related) > 16 or not line:
            reason = 'Missing or invalid cross-review source references.'
        else:
            actual: list[tuple[str, tuple[int, str, str]]] = []
            distinct: set[str] = set()
            complete = True
            for relation in related:
                if not isinstance(relation, dict):
                    reason = 'Malformed source reference.'; break
                name, locator = relation.get('section'), relation.get('locator')
                if not isinstance(name, str) or name not in REVIEW_FAMILY or not _is_applicable(platform, name):
                    reason = 'Unknown or non-applicable source review.'; break
                if not isinstance(locator, str) or len(locator) > 80:
                    reason = 'Invalid source locator.'; break
                entries, section_complete = section_data(name)
                if not section_complete:
                    complete = False
                original = entries.get(locator)
                if original is None:
                    reason = 'Referenced source entry is not available in the inspected subset.'; break
                signature = _signature(original)
                if signature is None or signature[0] != line:
                    reason = 'Source line, code or title cannot be revalidated.'; break
                if _line(relation.get('source_line')) != line:
                    reason = 'Cross-review source-line metadata disagrees.'; break
                actual.append((name, signature))
                distinct.add(name)
            if not reason:
                if len(distinct) < 2:
                    reason = 'References do not span distinct review sections.'
                elif len({s for _, s in actual}) != 1:
                    reason = 'Referenced source entries have different signal identifiers, titles or lines.'
                elif any(s[1] != _text(link.get('signal'), 96).casefold() or s[2] != _text(link.get('title'), 120).casefold() for _, s in actual):
                    reason = 'Consolidation link label differs from source evidence.'
                elif not complete or source.get('status') == 'limited' or (isinstance(source.get('summary'), dict) and source['summary'].get('incomplete') is True):
                    outcome = 'context_incomplete'
                    reason = 'Metadata matches, but the upstream review is partial or limited.'
                else:
                    outcome = 'plausible_metadata_overlap'
                    reason = 'Exact same-line signal and title confirmed across distinct, applicable reviewed sections; semantic equivalence is not established.'
        if outcome == 'plausible_metadata_overlap':
            summary['plausible_links'] += 1
        elif outcome == 'context_incomplete':
            summary['uncertain_links'] += 1
        else:
            summary['unsupported_links'] += 1
        if len(decisions) < MAX_DECISIONS:
            decisions.append({
                'reference': f'ACCL-{i+1:03d}', 'upstream_reference': ref,
                'source_line': line, 'classification': outcome, 'reason': reason,
                'recommended_action': (
                    'Review the original source and analyzer semantics before any manual consolidation.'
                    if outcome == 'plausible_metadata_overlap' else
                    'Retrieve missing review context and verify original source entries before drawing a conclusion.'
                    if outcome == 'context_incomplete' else
                    'Do not treat this link as an established correlation; re-check source provenance.'
                ), 'confidence': 'static_report_metadata_only',
            })
        else:
            summary['items_omitted'] += 1
            summary['incomplete'] = True
    if source.get('status') == 'limited' or (isinstance(source.get('summary'), dict) and source['summary'].get('incomplete') is True):
        summary['incomplete'] = True
    if summary['items_omitted']:
        limitations.append('The scan reached an explicit input, output or source entry limit; omitted records were not verified.')
    if summary['incomplete']:
        limitations.append('Upstream or local coverage is incomplete; an unlisted issue is not evidence of absence.')
    return {
        'version': '1.0', 'platform_id': platform,
        'scope': 'single_upload_advisory_link_validation',
        'status': 'limited' if summary['incomplete'] else 'reviewed_subset',
        'summary': summary, 'decisions': decisions,
        'quality_observations': observations, 'limitations': limitations,
    }
