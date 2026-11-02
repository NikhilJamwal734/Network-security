"""API-011.3 bounded pre-export checks (not PDF byte or visual verification).

Pure function: reads the normalized response without mutating upstream findings.
"""
from __future__ import annotations
from typing import Any

MAX_EVIDENCE = 60
MAX_FINDINGS_RENDERED = 300
MAX_OBSERVATIONS_RENDERED = 80
PLATFORMS = {'cisco_asa', 'fortios', 'snort', 'suricata'}


def assess_pdf_readiness(report: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(report, dict):
        raise ValueError('Normalized report must be an object')
    platform = report.get('platform')
    platform_id = platform.get('platform_id') if isinstance(platform, dict) else None
    if platform_id not in PLATFORMS:
        raise ValueError('Unsupported or missing normalized platform identifier')

    observations: list[dict[str, str]] = []
    totals = {'checks': 0, 'passed': 0, 'warnings': 0, 'blockers': 0, 'omitted': 0}

    def add(kind: str, result: str, statement: str, action: str) -> None:
        totals['checks'] += 1
        if result == 'pass': totals['passed'] += 1
        elif result == 'blocker': totals['blockers'] += 1
        else: totals['warnings'] += 1
        if result == 'pass': return
        if len(observations) < MAX_EVIDENCE:
            observations.append({
                'reference': f'PDF-{totals["checks"]:03d}',
                'kind': kind, 'result': result,
                'observation': statement[:350], 'recommendation': action[:350],
            })
        else:
            totals['omitted'] += 1

    schema = report.get('schema_version')
    add('schema', 'pass' if isinstance(schema, str) and bool(schema.strip()) else 'warning',
        'Normalized schema version is missing or invalid.', 'Confirm the upstream normalized schema contract.')
    findings = report.get('findings')
    if not isinstance(findings, list):
        add('findings_shape', 'blocker', 'Findings collection is not a list.',
            'Fix the upstream analyzer response before exporting the PDF.')
        findings = []
    else:
        add('findings_shape', 'pass', '', '')
    if len(findings) > MAX_FINDINGS_RENDERED:
        add('findings_truncation', 'warning',
            f'PDF renderer includes only the first {MAX_FINDINGS_RENDERED} of {len(findings)} normalized findings.',
            'Use the normalized JSON export to retain the complete finding list.')
    else:
        add('findings_truncation', 'pass', '', '')
    if any(not isinstance(item, dict) for item in findings[:MAX_FINDINGS_RENDERED]):
        add('finding_entry_shape', 'blocker', 'One or more PDF-visible findings are not objects.',
            'Repair the normalized findings before PDF rendering.')
    else:
        add('finding_entry_shape', 'pass', '', '')

    summary = report.get('summary')
    if isinstance(summary, dict):
        declared = summary.get('total_findings')
        if type(declared) is int and declared >= 0:
            add('findings_count', 'pass' if declared == len(findings) else 'warning',
                'Declared total findings differs from the normalized findings list.',
                'Investigate count mismatch before distributing the PDF.')
        else:
            add('findings_count', 'warning', 'Finding total is unavailable for reconciliation.',
                'Check the report summary schema and counters.')
    else:
        add('summary_shape', 'blocker', 'Normalized report summary is missing or invalid.',
            'Fix report normalization before generating PDF.')
    coverage = report.get('coverage')
    if not isinstance(coverage, dict) or not isinstance(coverage.get('domains'), list) or not isinstance(coverage.get('limitations'), list):
        add('coverage_shape', 'blocker', 'PDF assessment coverage structure is unavailable.',
            'Include coverage domains and limitations in the normalized response.')
    else:
        add('coverage_shape', 'pass', '', '')

    for key in ('consolidation_review', 'correlation_accuracy_review', 'report_validation_review'):
        value = report.get(key)
        add(key, 'pass' if isinstance(value, dict) else 'warning',
            f'{key} not returned as a structured review.',
            'Confirm the preceding API stage and include the limitation in the report.')
        if isinstance(value, dict):
            inner = value.get('summary')
            if (value.get('status') in ('limited', 'inconsistent') or
                    (isinstance(inner, dict) and inner.get('incomplete') is True)):
                add(key+'_partial', 'warning', 'Upstream review has limited or inconsistent coverage.',
                    'Preserve review limitations in the PDF; do not report an all-clear.')
    for key in ('object_assurance', 'object_resolution'):
        value = report.get(key)
        if not isinstance(value, dict): continue
        entries = value.get('observations')
        if isinstance(entries, list) and len(entries) > MAX_OBSERVATIONS_RENDERED:
            add(key+'_bounded_output', 'warning',
                f'{key}: PDF may omit entries beyond its bounded output limits.',
                'Use the normalized JSON export for full evidence and inspect report-specific limits.')

    status = 'blocked' if totals['blockers'] else 'limited' if totals['warnings'] else 'preflight_pass'
    return {
        'version': '1.0', 'platform_id': platform_id,
        'scope': 'static_single_upload_pdf_export_preflight',
        'status': status, 'summary': totals, 'observations': observations,
        'limitations': [
            'This preflight checks report structure, not the rendered PDF bytes, page layout, fonts or appearance.',
            'Browser export validates basic PDF byte structure and page count before download; this is not independent PDF parsing.',
            'Browser permission and completed file saving cannot be proven by a web application.',
            'Visual inspection and independent saved-file parsing are recommended before distributing an assessment.',
            'Findings, scores, risk ratings and preceding reviews are not modified by this stage.',
        ],
    }
