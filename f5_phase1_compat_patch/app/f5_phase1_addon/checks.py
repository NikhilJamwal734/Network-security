"""F5 phase-1 configuration checks: advisory static evidence, no live TLS testing."""
from __future__ import annotations
from typing import Any
from app.f5_phase1_addon.parser import ConfigObject, list_option, nested_body, top_level_value
from app.f5_phase1_addon.profiles import canonical, profile_attachments


def _finding(code: str, title: str, *, severity: str, confidence: str,
             obj: ConfigObject, setting: str, observed: str, line: int,
             explanation: str, recommendation: str, virtuals: list[str]) -> dict[str, Any]:
    return {
        'code': code,
        'title': title,
        'severity': severity,
        'confidence': confidence,
        'affected_object': obj.name,
        'object_type': obj.kind,
        'line_number': line,
        'evidence': {'setting': setting, 'observed': observed, 'line_number': line},
        'associated_virtual_servers': sorted(set(virtuals)),
        'description': explanation,
        'recommendation': recommendation,
        'limitations': 'Static export only; inheritance, device version, cipher expansion, deployment and runtime behavior are not verified.',
    }


def analyze(objects: tuple[ConfigObject, ...]) -> dict[str, Any]:
    attachments = profile_attachments(objects)
    findings: list[dict[str, Any]] = []
    observations: list[dict[str, Any]] = []
    for obj in objects:
        virtuals = attachments.get(canonical(obj.name), [])
        if obj.kind == 'client_ssl':
            line = list_option(obj.body, 'options', 'no-tlsv1.3')
            if line is not None:
                findings.append(_finding(
                    'F5-001', 'TLS 1.3 explicitly disabled in Client SSL profile',
                    severity='MEDIUM', confidence='explicit_setting', obj=obj,
                    setting='options', observed='no-tlsv1.3', line=line,
                    explanation='This exported profile explicitly disables TLS 1.3. Whether that is an unacceptable risk depends on device support and the organization\'s protocol baseline.',
                    recommendation='Review device version, cipher-group support and client compatibility; enable TLS 1.3 when supported and required by policy.',
                    virtuals=virtuals))
        elif obj.kind == 'server_ssl':
            ciphers = top_level_value(obj.body, 'ciphers')
            cipher_group = top_level_value(obj.body, 'cipher-group')
            if ciphers and ciphers[0].upper() == 'DEFAULT' and (not cipher_group or cipher_group[0].lower() in ('none', '')):
                observations.append(_finding(
                    'F5-002', 'Backend SSL profile explicitly uses DEFAULT cipher selection',
                    severity='INFO', confidence='policy_review_required', obj=obj,
                    setting='ciphers', observed='DEFAULT', line=ciphers[1],
                    explanation='DEFAULT is a platform-defined cipher expression, not proof of weak encryption. Cipher-group behavior and BIG-IP version require confirmation.',
                    recommendation='Check the resolved cipher suites against the organization\'s cryptographic baseline before changing the profile.', virtuals=virtuals))
            peer = top_level_value(obj.body, 'peer-cert-mode')
            ca = top_level_value(obj.body, 'ca-file')
            if peer and peer[0].lower() == 'ignore':
                findings.append(_finding(
                    'F5-003', 'Server SSL profile explicitly ignores peer certificates',
                    severity='MEDIUM', confidence='explicit_setting', obj=obj,
                    setting='peer-cert-mode', observed='ignore', line=peer[1],
                    explanation='The exported setting specifies that the server peer certificate is not required for authentication; a complete assessment needs effective profile and backend context.',
                    recommendation='Review server trust and identity validation requirements; use required certificate validation and appropriate CA trust where supported.', virtuals=virtuals))
            elif not peer or (peer[0].lower() == 'require' and (not ca or ca[0].lower() == 'none')):
                observations.append(_finding(
                    'F5-003', 'Backend certificate-validation evidence is incomplete',
                    severity='INFO', confidence='insufficient_evidence', obj=obj,
                    setting='peer-cert-mode / ca-file', observed='not fully demonstrated in uploaded profile', line=obj.line,
                    explanation='The local excerpt does not prove complete server certificate identity and trust validation. Inherited settings and appliance version may change effective behavior.',
                    recommendation='Export the resolved Server SSL profile with all properties; verify peer-cert-mode, ca-file, certificate identity, and backend TLS policy.', virtuals=virtuals))
        elif obj.kind == 'http':
            hsts = nested_body(obj.body, 'hsts')
            if hsts is not None:
                mode = top_level_value(hsts, 'mode')
                if mode and mode[0].lower() in ('disabled', 'disable'):
                    findings.append(_finding(
                        'F5-007', 'HSTS explicitly disabled in HTTP profile',
                        severity='LOW', confidence='explicit_setting_context_required', obj=obj,
                        setting='hsts.mode', observed=mode[0], line=mode[1],
                        explanation='This HTTP profile has HSTS mode disabled; impact depends on whether it serves an HTTPS-only public application and any other HSTS enforcement layers.',
                        recommendation='For suitable HTTPS-only applications, evaluate enabling HSTS after validating subdomain and client compatibility.', virtuals=virtuals))
    counts = {level: sum(x['severity'] == level for x in findings) for level in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')}
    return {
        'platform': {'platform_id': 'f5_bigip', 'name': 'F5 BIG-IP LTM / Advanced WAF (Phase 1 static subset)'},
        'schema_version': 'f5-phase1-1.0',
        'summary': {'total_findings': len(findings), 'total_review_observations': len(observations),
                    'total_profiles': sum(x.kind in ('client_ssl', 'server_ssl', 'http') for x in objects),
                    'total_virtual_servers': sum(x.kind == 'virtual' for x in objects),
                    **{level.lower() + '_findings': count for level, count in counts.items()},
                    'risk_level': 'NOT_SCORED', 'security_score': None},
        'findings': findings,
        'review_observations': observations,
        'coverage': {'status': 'reviewed_subset', 'supported_checks': ['F5-001', 'F5-002', 'F5-003', 'F5-007'],
                     'limitations': [
                         'Only explicit supported tmsh configuration entries are reviewed.',
                         'Missing settings are not treated as verified inherited defaults.',
                         'Virtual-server profile references are advisory; partition inheritance and runtime profile mappings are not fully resolved.',
                         'The uploaded file is not executed and no live TLS connection is attempted.',
                         'No PDF/frontend integration or F5-004 through F5-008 coverage in this phase.',
                     ]},
    }
