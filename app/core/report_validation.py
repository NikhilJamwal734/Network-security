"""API-011.2: deterministic, bounded validation of the normalized report contract.

Advisory static preflight only, never claims PDF byte/render verification. Does
not modify upstream report, scores or findings. Does not access original files.
"""
from __future__ import annotations
from typing import Any

SUPPORTED = frozenset({'cisco_asa', 'fortios', 'snort', 'suricata'})
MAX_CHECKS = 90
MAX_FINDINGS = 10000
MAX_REVIEW_ENTRIES = 5000
KNOWN_REVIEWS = (
    'object_resolution', 'object_assurance', 'service_ipv6',
    'nat_route_reachability', 'ids_deep_review', 'consolidation_review',
    'correlation_accuracy_review',
)


def _count(value: Any) -> int | None:
    return value if type(value) is int and 0 <= value <= 10**9 else None


def validate_report_contract(report: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(report, dict):
        raise ValueError('Expected a normalized report mapping')
    platform = report.get('platform')
    platform_id = platform.get('platform_id') if isinstance(platform, dict) else None
    if platform_id not in SUPPORTED:
        raise ValueError('Unknown or absent normalized platform identifier')

    checks: list[dict[str, Any]] = []
    summary: dict[str, int | bool] = {
        'checks_performed': 0, 'passed_checks': 0, 'discrepancies': 0,
        'warnings': 0, 'reviews_examined': 0, 'items_omitted': 0,
        'incomplete': False,
    }

    def add(section: str, kind: str, result: str, observed: str, expected: str,
            explanation: str, action: str) -> None:
        summary['checks_performed'] += 1
        if result == 'pass':
            summary['passed_checks'] += 1
        elif result == 'discrepancy':
            summary['discrepancies'] += 1
        else:
            summary['warnings'] += 1
            summary['incomplete'] = True
        if len(checks) >= MAX_CHECKS:
            summary['items_omitted'] += 1
            summary['incomplete'] = True
            return
        # No original config text, IPs or rule bodies ever go in this preflight.
        checks.append({
            'reference': f'RPT-{summary["checks_performed"]:03d}',
            'section': section, 'check': kind, 'result': result,
            'observed': observed[:150], 'expected': expected[:150],
            'explanation': explanation[:300], 'recommended_action': action[:300],
            'confidence': 'static_report_contract_only',
        })

    findings = report.get('findings')
    if not isinstance(findings, list):
        add('findings', 'finding_list', 'discrepancy', 'invalid/missing', 'list',
            'The PDF cannot reliably enumerate normalized findings.',
            'Check normalization and report serialization.')
        findings = []
    else:
        add('findings', 'finding_list', 'pass', 'list', 'list',
            'Normalized finding array is available.', 'No action needed.')
    if len(findings) > MAX_FINDINGS:
        summary['items_omitted'] += len(findings)-MAX_FINDINGS
        add('findings', 'bounded_review', 'warning', 'over input cap', f'<= {MAX_FINDINGS}',
            'The preflight did not validate all finding entries.',
            'Inspect the complete report and reduce the input if feasible.')
    malformed = sum(not isinstance(item, dict) for item in findings[:MAX_FINDINGS])
    add('findings', 'finding_item_shape', 'discrepancy' if malformed else 'pass',
        str(malformed), '0', 'Non-object finding entries cannot be rendered consistently.',
        'Inspect normalized finding serialization.')

    top_summary = report.get('summary')
    if isinstance(top_summary, dict) and 'total_findings' in top_summary:
        declared = _count(top_summary['total_findings'])
        bad = declared is None or declared != len(findings)
        add('summary', 'finding_total', 'discrepancy' if bad else 'pass',
            str(declared) if declared is not None else 'invalid', str(len(findings)),
            'Headline total and normalized finding array were compared.',
            'Reconcile report counters with the findings array before distributing the PDF.' if bad else 'No action needed.')
    else:
        add('summary', 'finding_total', 'warning', 'not declared', 'total_findings',
            'Cannot cross-check the headline finding count.',
            'Include a total_findings field if supported by this platform.')

    for name in KNOWN_REVIEWS:
        review = report.get(name)
        required = name in ('consolidation_review', 'correlation_accuracy_review')
        if review is None:
            if required:
                add(name, 'review_present', 'discrepancy', 'missing', 'review object',
                    'A prerequisite review is absent from the report.',
                    'Confirm API-011.1 produced its expected normalized sidecars.')
            continue
        summary['reviews_examined'] += 1
        if not isinstance(review, dict):
            add(name, 'review_shape', 'discrepancy', 'invalid', 'object',
                'The review shape prevents reliable PDF evidence rendering.',
                'Correct review schema before exporting.')
            continue
        add(name, 'review_platform', 'pass' if review.get('platform_id') == platform_id else 'discrepancy',
            'matches' if review.get('platform_id') == platform_id else 'mismatch', 'matching platform',
            'Review device/sensor identity must match the normalized report.',
            'Check platform routing and report assembly.')
        status = review.get('status')
        meta = review.get('summary')
        if not isinstance(meta, dict):
            add(name, 'summary_shape', 'discrepancy', 'invalid', 'object',
                'Review counters cannot be reconciled.', 'Correct review summary structure.')
            meta = {}
        partial = status in ('limited', 'not_assessed', 'unavailable') or meta.get('incomplete') is True
        omitted = _count(meta.get('items_omitted')) or 0
        if partial or omitted:
            add(name, 'coverage', 'warning', 'limited or omitted', 'reviewed subset',
                'Partial coverage cannot be treated as a clean report.',
                'Preserve limitations and disclose unassessed evidence in the PDF.')
        if status not in ('reviewed_subset', 'limited', 'consistent_subset', 'inconsistent'):
            add(name, 'review_status', 'warning', 'nonstandard', 'documented status',
                'Review status may be vendor-specific or unsupported.',
                'Check the documented review status before interpretation.')
        for field, declared_field in (('evidence', 'evidence_items'),):
            arr = review.get(field)
            if not isinstance(arr, list) or declared_field not in meta:
                continue
            if len(arr) > MAX_REVIEW_ENTRIES:
                add(name, 'bounded_evidence', 'warning', 'over cap', f'<= {MAX_REVIEW_ENTRIES}',
                    'Full evidence content was not enumerated by this preflight.',
                    'Inspect the detailed PDF and use a bounded analysis window.')
            declared = _count(meta.get(declared_field))
            matches = declared is not None and declared == len(arr)
            result = 'pass' if matches else ('warning' if omitted or partial else 'discrepancy')
            add(name, 'evidence_count', result, 'matches' if matches else 'differs', 'match',
                'Declared evidence count should correspond to returned evidence array unless explicitly truncated.',
                'Reconcile evidence serialization and bounded omissions.')

    consolidation = report.get('consolidation_review')
    accuracy = report.get('correlation_accuracy_review')
    if isinstance(consolidation, dict):
        csum = consolidation.get('summary')
        secs, links, issues = consolidation.get('sections'), consolidation.get('links'), consolidation.get('issues')
        if not all(isinstance(x, list) for x in (secs, links, issues)):
            add('consolidation_review', 'pdf_evidence_arrays', 'discrepancy', 'invalid',
                'sections/links/issues lists', 'The PDF requires structured review evidence.',
                'Repair the consolidation response schema.')
        elif isinstance(csum, dict):
            for counter, actual in (
                ('sections_present', sum(isinstance(s, dict) and s.get('availability') == 'returned' for s in secs)),
                ('candidate_links', len(links)),
            ):
                declared = _count(csum.get(counter))
                matches = declared is not None and declared == actual
                add('consolidation_review', counter, 'pass' if matches else 'discrepancy',
                    'matches' if matches else 'differs', 'match',
                    'A declared consolidation count was checked against emitted records.',
                    'Check summary calculation and bounded record accounting.')
    if isinstance(accuracy, dict):
        asum = accuracy.get('summary')
        decisions, quality = accuracy.get('decisions'), accuracy.get('quality_observations')
        if not isinstance(decisions, list) or not isinstance(quality, list):
            add('correlation_accuracy_review', 'pdf_evidence_arrays', 'discrepancy',
                'invalid', 'decisions and quality_observations lists',
                'The PDF requires structured correlation evidence.',
                'Repair the accuracy review serialization.')
        if isinstance(asum, dict):
            checked = _count(asum.get('links_checked'))
            values = [_count(asum.get(k)) for k in ('plausible_links','unsupported_links','uncertain_links')]
            valid = checked is not None and all(v is not None for v in values) and checked == sum(values)
            add('correlation_accuracy_review', 'classification_partition',
                'pass' if valid else 'discrepancy', 'matches' if valid else 'differs', 'match',
                'Link classifications must partition the checked link count.',
                'Review link classification and summary accounting.')
            if isinstance(consolidation, dict) and isinstance(consolidation.get('links'), list) and checked is not None:
                total_links = len(consolidation['links'])
                omitted = _count(asum.get('items_omitted')) or 0
                matches = checked == total_links
                add('correlation_accuracy_review', 'upstream_link_count',
                    'pass' if matches else ('warning' if omitted or asum.get('incomplete') else 'discrepancy'),
                    'matches' if matches else 'differs', 'match unless explicitly capped',
                    'The count of checked links is compared against 11.0 emitted links.',
                    'Review input caps or lost correlation links.')

    if summary['discrepancies']:
        status = 'inconsistent'
    elif summary['incomplete']:
        status = 'limited'
    else:
        status = 'consistent_subset'
    return {
        'version': '1.0', 'platform_id': platform_id,
        'scope': 'single_upload_report_contract_preflight',
        'status': status, 'summary': summary, 'checks': checks,
        'limitations': [
            'Static normalized-response checks only; successful PDF creation, fonts, pagination, download and visual integrity are NOT verified.',
            'Counts and matching platform labels cannot establish correctness of individual security findings, enforcement or alert delivery.',
            'This check does not alter source findings, severity, risk scoring, previous reviews or configuration content.',
            'A limited, inconsistent or unassessed review must never be presented as an all-clear.',
            'Bounded output can omit detailed checks; totals report all checks performed within the explicitly described inspected subset.',
        ],
    }
