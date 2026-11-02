"""API-011.4: report-side integration contract validation.

Validates a response AFTER the established single-upload chain has completed.
Does not simulate actual browser PDF export or modify the findings/score.
"""
from __future__ import annotations
from typing import Any

PLATFORMS = frozenset({'cisco_asa', 'fortios', 'snort', 'suricata'})
REVIEW_KEYS = (
    ('consolidation_review', 'cross_review_consolidation'),
    ('correlation_accuracy_review', 'correlation_accuracy'),
    ('report_validation_review', 'report_consistency'),
    ('pdf_export_review', 'pdf_export_preflight'),
)


def inspect_pipeline(report: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(report, dict):
        raise ValueError('Upstream response is not an object')
    platform = report.get('platform')
    platform_id = platform.get('platform_id') if isinstance(platform, dict) else None
    if platform_id not in PLATFORMS:
        raise ValueError('Unsupported or absent upstream platform_id')

    stages: list[dict[str, str]] = []
    stats = {'checks': 0, 'passed': 0, 'warnings': 0, 'blockers': 0, 'manual_required': 0}

    def stage(name: str, result: str, observation: str, action: str, basis: str):
        stats['checks'] += 1
        if result == 'pass': stats['passed'] += 1
        elif result == 'blocker': stats['blockers'] += 1
        elif result == 'manual_required': stats['manual_required'] += 1
        else: stats['warnings'] += 1
        stages.append({
            'reference': f'E2E-{stats["checks"]:03d}', 'stage': name, 'result': result,
            'observation': observation[:320], 'recommendation': action[:320],
            'evidence_basis': basis,
        })

    # Reaching this function shows the upstream endpoint returned an object;
    # it does NOT independently prove that ingestion was safe or complete.
    stage('upstream_response', 'pass',
          'Upstream analyzer chain returned a mapping for this request.',
          'No action for this contract check.', 'in_process_upstream_result')
    stage('platform_identity', 'pass',
          f'Normalized report identifies supported platform: {platform_id}.',
          'Confirm the detected vendor against the source file when reviewing results.',
          'normalized_platform_id')

    findings = report.get('findings')
    if not isinstance(findings, list):
        stage('normalized_findings', 'blocker',
              'Normalized findings is not an array.',
              'Repair normalization and avoid distributing the resulting report.', 'report.findings')
    elif any(not isinstance(f, dict) for f in findings[:10000]):
        stage('normalized_findings', 'blocker',
              'At least one inspected finding has an invalid structure.',
              'Repair finding serialization; inspect all entries beyond the check limit.', 'report.findings')
    elif len(findings) > 10000:
        stage('normalized_findings', 'warning',
              'The findings array exceeded the bounded inspection limit.',
              'Run full schema validation on all findings before release.', 'report.findings')
    else:
        stage('normalized_findings', 'pass',
              'Normalized finding entries have the expected object structure.',
              'No action for this structure check.', 'report.findings')

    total = report.get('summary', {}).get('total_findings') if isinstance(report.get('summary'), dict) else None
    if not isinstance(findings, list) or type(total) is not int or total < 0:
        stage('finding_count', 'warning',
              'Cannot reconcile finding count to a valid headline total.',
              'Inspect normalized report summary and findings array.', 'report.summary')
    elif total != len(findings):
        stage('finding_count', 'blocker',
              'Declared finding count disagrees with normalized findings.',
              'Fix the source report count before approving the PDF.', 'report.summary')
    else:
        stage('finding_count', 'pass', 'Reported total matches the normalized finding count.',
              'No action for this consistency check.', 'report.summary')

    for key, name in REVIEW_KEYS:
        value = report.get(key)
        if not isinstance(value, dict):
            stage(name, 'blocker', f'Missing or malformed prerequisite: {key}.',
                  'Ensure earlier API stages are installed and registered in order.', key)
            continue
        if value.get('platform_id') != platform_id:
            stage(name, 'blocker', f'{key} platform does not match the normalized platform.',
                  'Inspect upstream routing and report assembly.', key)
            continue
        summary = value.get('summary')
        if not isinstance(summary, dict):
            stage(name, 'warning', f'{key} has no structured summary.',
                  'Review upstream summary contract and limitations.', key)
            continue
        status = value.get('status')
        if status in ('blocked', 'inconsistent') or summary.get('blockers', 0) not in (0, None):
            stage(name, 'blocker', f'{key} declares a blocking or inconsistent state.',
                  'Resolve the recorded upstream evidence before approving the report.', key)
        elif status in ('limited', 'not_assessed', 'unavailable') or summary.get('incomplete') is True or summary.get('warnings', 0) not in (0, None):
            stage(name, 'warning', f'{key} includes limited or incomplete evidence.',
                  'Consult that review\'s detailed PDF evidence and limitations.', key)
        else:
            stage(name, 'pass', f'{key} is structurally present; no limitation marker was recognized.',
                  'This structural check is not an independent correctness assessment.', key)

    stage('browser_pdf_export', 'manual_required',
          'Server-side response cannot establish that the browser rendered and saved a valid PDF.',
          'Generate a PDF in the frontend, run the saved-file audit, and visually inspect representative pages.',
          'not_observable_from_server')
    status = 'blocked' if stats['blockers'] else 'limited' if stats['warnings'] else 'server_checks_passed'
    return {
        'version': '1.0', 'platform_id': platform_id,
        'scope': 'single_upload_server_response_contract_and_manual_export_checklist',
        'status': status, 'summary': stats, 'stages': stages,
        'limitations': [
            'The upload is processed by the existing endpoint; this sidecar does not reread the original file.',
            'Stages marked pass are structural/contract checks, not proof that the security analysis is correct.',
            'Browser PDF creation, download completion, visual pagination and saved-file integrity require independent verification.',
            'This review does not change findings, risk ratings, severity, scores, PDF limits or earlier review contents.',
        ],
    }
