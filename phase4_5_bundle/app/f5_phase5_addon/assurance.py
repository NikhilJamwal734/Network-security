"""Additive evidence-quality assessment for the existing eight F5 checks.

No claims of runtime verification, cryptographic suitability or WAF bypass.
No device access, Tcl execution, archive processing or credentials.
"""
from __future__ import annotations
from collections import Counter
from typing import Any
from app.f5_phase1_addon.parser import ConfigObject, top_level_value, nested_body
from app.f5_phase1_addon.profiles import canonical, profile_attachments
from app.f5_phase2_addon.review import _list_names, _top_objects

MAX_ASSURANCE_ITEMS = 300


def _reference(name: str, default_partition: str) -> str:
    return canonical(name, default_partition=default_partition)


def _partition(name: str) -> str:
    if name.startswith('/') and name.count('/') >= 2:
        return '/' + name.split('/')[1]
    return '/Common'


def build_assurance(objects: tuple[ConfigObject, ...], source: str,
                    report: dict[str, Any]) -> dict[str, Any]:
    """Compute bounded, non-scoring confidence notes from existing parsed data.

    This is a SUPPLEMENT to F5-001..008, not a new vulnerability finding.
    It does not modify existing findings, counts or observations.
    """
    included = {o.name: o for o in objects if o.kind in {'client_ssl', 'server_ssl', 'http'}}
    virtuals = [o for o in objects if o.kind == 'virtual']
    attached = profile_attachments(objects)
    unresolved_refs = []
    used_profiles = set()
    for virtual in virtuals:
        section = _list_names(virtual.body, 'profiles')
        if section is None:
            continue
        for name, _ in section:
            full = _reference(name, _partition(virtual.name))
            if full in included:
                used_profiles.add(full)
            elif name.lower() not in ('none', 'default'):
                unresolved_refs.append({'virtual_server': virtual.name,
                                        'profile': full,
                                        'status': 'not_present_in_uploaded_subset'})
            if len(unresolved_refs) >= MAX_ASSURANCE_ITEMS:
                break
        if len(unresolved_refs) >= MAX_ASSURANCE_ITEMS:
            break
    inherited = []
    tls = []
    for obj in included.values():
        parent = top_level_value(obj.body, 'defaults-from')
        if parent and len(inherited) < MAX_ASSURANCE_ITEMS:
            reference = _reference(parent[0], _partition(obj.name))
            inherited.append({'profile': obj.name,
                              'parent': reference,
                              'parent_in_uploaded_subset': reference in included,
                              'effective_inheritance_verified': False})
        if obj.kind in ('client_ssl', 'server_ssl') and len(tls) < MAX_ASSURANCE_ITEMS:
            c = top_level_value(obj.body, 'ciphers')
            g = top_level_value(obj.body, 'cipher-group')
            peer = top_level_value(obj.body, 'peer-cert-mode') if obj.kind == 'server_ssl' else None
            ca = top_level_value(obj.body, 'ca-file') if obj.kind == 'server_ssl' else None
            tls.append({'profile': obj.name, 'kind': obj.kind,
                        'associated_virtual_servers': attached.get(obj.name, [])[:30],
                        'explicit_cipher_expression': c[0][:160] if c else None,
                        'explicit_cipher_group': g[0][:160] if g else None,
                        'resolved_cipher_suites': None,
                        'explicit_peer_cert_mode': peer[0][:80] if peer else None,
                        'explicit_ca_file': ca[0][:160] if ca else None,
                        'backend_chain_hostname_validated': False,
                        'runtime_tls_tested': False})
    irules = _top_objects(source, {('ltm', 'rule'): 'irule'})
    rule_events = []
    for obj in irules[:MAX_ASSURANCE_ITEMS]:
        indicators = [t for t in obj.body if t.value in ('ASM::disable', 'ACCESS::disable', 'HTTP::disable', 'eval', 'exec')]
        if not indicators:
            continue
        rule_events.append({'rule': obj.name,
                            'indicators': [{'token': t.value, 'line': t.line} for t in indicators[:20]],
                            'tcl_control_flow_verified': False,
                            'live_waf_bypass_proven': False})
    findings = report.get('findings', [])
    observations = report.get('review_observations', [])
    by_confidence = Counter(str(item.get('confidence', 'unknown')) for item in [*findings, *observations])
    evidence_covered = {str(x.get('code')) for x in [*findings, *observations]}
    return {
        'assessment_type': 'static_evidence_quality_review',
        'schema_version': 'f5-assurance-1.0',
        'device_version': {'status': 'not_verified', 'value': None,
                           'note': 'A configuration export is not an authenticated appliance version record.'},
        'coverage': {'implemented_check_codes': sorted(evidence_covered),
                     'runtime_verification': 'not_performed',
                     'cipher_suite_expansion': 'not_performed',
                     'UCS_archive_opened': False,
                     'signature_package_verified': False,
                     'logging_delivery_verified': False,
                     'HTTP_HSTS_header_verified': False},
        'confidence_counts': dict(sorted(by_confidence.items())),
        'profile_inheritance': inherited,
        'unresolved_profile_references': unresolved_refs,
        'profile_tls_evidence': tls,
        'irule_control_flow_review': rule_events,
        'limitations': [
            'Evidence labels do not establish effective device security.',
            'Only uploaded objects are resolved; system defaults and inherited runtime settings are unknown.',
            'DEFAULT and cipher-group names are not converted to actual suites without an authoritative version-matched cipher inventory.',
            'Backend certificate trust and hostname checks require independent runtime or authenticated device evidence.',
            'UCS backup and signature status remain operator-supplied and unverified.',
            'iRule tokens are not interpreted as Tcl control flow or proof of WAF bypass.'
        ],
    }
