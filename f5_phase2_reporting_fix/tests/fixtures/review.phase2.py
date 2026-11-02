"""Bounded, non-executing BIG-IP configuration review: F5-004/005/006/008.

Only the submitted tmsh text and optional operator-supplied metadata are reviewed.
No live F5 connection, UCS extraction, Tcl execution, or automatic remediation.
"""
from __future__ import annotations

import json
import re
from datetime import date
from typing import Any

from app.f5_phase1_addon.parser import (
    ConfigObject, Token, tokenize, close_index, nested_body, top_level_value,
)
from app.f5_phase1_addon.profiles import canonical

MAX_EVIDENCE_BYTES = 16_384
MAX_BACKUPS = 30
MAX_REVIEW_ITEMS = 1200
MAX_OBSERVATION_PER_GROUP = 250
SAFE_NAME = re.compile(r'^[a-zA-Z0-9_.\-/]{1,128}$')
ALLOWED_STATUS = {'current', 'unknown', 'failed', 'disabled', 'manual', 'scheduled', 'outdated'}
SUSPICIOUS_IRULE_COMMANDS = {'ASM::disable', 'ACCESS::disable', 'HTTP::disable', 'eval', 'exec'}


class EvidenceError(ValueError):
    pass


def parse_evidence(value: str | None) -> dict[str, Any]:
    """Explicit operator assertions; never accept arbitrary paths, passwords or configuration snippets."""
    if value is None or not value.strip():
        return {}
    if len(value.encode('utf-8')) > MAX_EVIDENCE_BYTES:
        raise EvidenceError('Evidence JSON exceeds 16 KiB')
    try:
        data = json.loads(value)
    except (ValueError, TypeError):
        raise EvidenceError('Invalid evidence_json: expected JSON object') from None
    if not isinstance(data, dict) or set(data) - {'ucs_backups', 'signature_updates'}:
        raise EvidenceError('Unexpected evidence fields')
    backups = data.get('ucs_backups', [])
    if not isinstance(backups, list) or len(backups) > MAX_BACKUPS:
        raise EvidenceError('ucs_backups must be an array of at most 30 items')
    for item in backups:
        if not isinstance(item, dict) or set(item) != {'name', 'encrypted'} or (
            not isinstance(item['name'], str) or not SAFE_NAME.fullmatch(item['name']) or
            '\\' in item['name'] or '..' in item['name'].split('/') or
            type(item['encrypted']) is not bool
        ):
            raise EvidenceError('Each UCS item needs safe name and boolean encrypted')
    updates = data.get('signature_updates')
    if updates is not None:
        if not isinstance(updates, dict) or set(updates) != {'status', 'last_installed'}:
            raise EvidenceError('signature_updates needs status and last_installed')
        if not isinstance(updates.get('status'), str) or updates['status'] not in ALLOWED_STATUS:
            raise EvidenceError('Unsupported signature-update status')
        last = updates['last_installed']
        if last is not None:
            if not isinstance(last, str) or len(last) != 10:
                raise EvidenceError('last_installed must be ISO YYYY-MM-DD or null')
            try:
                date.fromisoformat(last)
            except ValueError:
                raise EvidenceError('Invalid last_installed date') from None
    return data


def _entry(code: str, title: str, *, obj_name: str, kind: str,
           line: int | None, setting: str, observed: str, description: str,
           recommendation: str, confidence: str = 'static_scope_limited',
           severity: str = 'INFO', associated: list[str] | None = None) -> dict[str, Any]:
    return {
        'code': code, 'title': title, 'severity': severity, 'confidence': confidence,
        'affected_object': obj_name, 'object_type': kind, 'line_number': line,
        'evidence': {'setting': setting, 'observed': observed, 'line_number': line},
        'associated_virtual_servers': (associated or [])[:100],
        'description': description, 'recommendation': recommendation,
        'limitations': 'Static export and optional operator assertions only; incomplete exports, defaults, inheritance, module licensing, effective WAF policy, update history and runtime not verified.',
    }


def _top_objects(text: str, patterns: dict[tuple[str, ...], str]) -> list[ConfigObject]:
    """Read selected top-level objects using Phase 1's bounded brace tokenizer."""
    tokens = tokenize(text)
    found: list[ConfigObject] = []
    i = 0
    while i < len(tokens):
        kind = None; span = 0
        for keys, label in patterns.items():
            if tuple(t.value for t in tokens[i:i+len(keys)]) == keys:
                kind, span = label, len(keys)
                break
        if kind and i+span+1 < len(tokens) and tokens[i+span+1].value == '{':
            end = close_index(tokens, i+span+1)
            found.append(ConfigObject(kind, tokens[i+span].value, tokens[i].line, tokens[i+span+2:end]))
            i = end + 1
        elif tokens[i].value == '{':
            i = close_index(tokens, i) + 1
        else:
            i += 1
    return found


def _list_names(body: tuple[Token, ...], key: str) -> list[tuple[str, int]] | None:
    """Handle explicit tmsh lists with bare names or per-name { } blocks."""
    section = nested_body(body, key)
    if section is None:
        return None
    values: list[tuple[str, int]] = []
    i = 0
    while i < len(section):
        tok = section[i]
        if tok.value in ('{', '}'):
            i += 1; continue
        if i+1 < len(section) and section[i+1].value == '{':
            values.append((tok.value, tok.line))
            i = close_index(section, i+1) + 1
        else:
            values.append((tok.value, tok.line))
            i += 1
    return values


def _top_flag(body: tuple[Token, ...], name: str) -> bool:
    depth = 0
    for tok in body:
        if tok.value == '{':
            depth += 1
        elif tok.value == '}':
            depth -= 1
        elif depth == 0 and tok.value == name:
            return True
    return False


def _irule_associations(objects: tuple[ConfigObject, ...]) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for obj in objects:
        if obj.kind != 'virtual':
            continue
        refs = _list_names(obj.body, 'rules')
        if refs is None:
            continue
        partition = '/' + obj.name.split('/')[1] if obj.name.startswith('/') and len(obj.name.split('/')) > 2 else '/Common'
        for name, _ in refs:
            if name.lower() not in {'none', 'default'}:
                result.setdefault(canonical(name, default_partition=partition), []).append(obj.name)
    return result


def extend_report(report: dict[str, Any], objects: tuple[ConfigObject, ...],
                  source: str, evidence_json: str | None = None) -> dict[str, Any]:
    """Pure extension; Phase 1 findings/observations, IDs and response keys preserved."""
    evidence = parse_evidence(evidence_json)
    findings = list(report['findings'])
    observations = list(report['review_observations'])
    added_findings: list[dict[str, Any]] = []
    added_obs: list[dict[str, Any]] = []
    irules = _top_objects(source, {('ltm', 'rule'): 'irule'})
    uses = _irule_associations(objects)

    # F5-004: absence of an explicit log association is insufficient for a
    # confirmed vulnerability. Some deployments log via inherited/default policy.
    for v in (obj for obj in objects if obj.kind == 'virtual'):
        if len(added_obs) >= MAX_OBSERVATION_PER_GROUP:
            break
        enabled = not _top_flag(v.body, 'disabled')
        if not enabled:
            continue
        refs = _list_names(v.body, 'security-log-profiles')
        if refs is None:
            added_obs.append(_entry('F5-004', 'Virtual-server security logging requires confirmation',
                obj_name=v.name, kind=v.kind, line=v.line,
                setting='security-log-profiles', observed='not explicit in supported export',
                description='The uploaded virtual-server block does not explicitly identify an ASM logging profile. This is not proof logging is disabled.',
                recommendation='Confirm an applicable WAF security policy and logging profile attachment in the running BIG-IP.',
                confidence='insufficient_evidence'))
        elif not refs or all(name.lower() in {'none', 'disabled'} for name, _ in refs):
            added_obs.append(_entry('F5-004', 'Virtual-server security-log profile explicitly empty',
                obj_name=v.name, kind=v.kind, line=refs[0][1] if refs else v.line,
                setting='security-log-profiles', observed='none',
                description='No logging profile is listed in the explicit association. This may be a concern for WAF-protected virtual servers, but runtime logging and applicability remain unverified.',
                recommendation='Confirm WAF association and attach an appropriate event logging profile if required by policy.',
                confidence='explicit_setting_context_required'))

    # F5-005: UCS encryption cannot be inferred from bigip.conf alone.
    backups = evidence.get('ucs_backups')
    if backups is None:
        added_obs.append(_entry('F5-005', 'UCS backup encryption could not be assessed',
            obj_name='UCS archives', kind='backup_evidence', line=None,
            setting='ucs_backups', observed='not supplied',
            description='A normal BIG-IP configuration export does not prove whether stored UCS backup archives are encrypted.',
            recommendation='Inspect UCS archive inventory and export independently verified encryption metadata, without disclosing backup contents or passphrases.',
            confidence='not_assessed'))
    else:
        for item in backups:
            if not item['encrypted']:
                added_findings.append(_entry('F5-005', 'UCS backup reported as unencrypted',
                    obj_name=item['name'], kind='ucs_backup', line=None,
                    setting='ucs_backups.encrypted', observed='false (operator assertion)',
                    description='The separately supplied operator assertion identifies a potentially unencrypted UCS backup; the archive was not opened or verified.',
                    recommendation='Confirm archive encryption independently; protect the backup and create encrypted UCS archives using approved procedures.',
                    confidence='operator_supplied_unverified', severity='MEDIUM'))

    # F5-006: update status is not reliably available from a configuration export.
    update = evidence.get('signature_updates')
    if update is None:
        added_obs.append(_entry('F5-006', 'WAF attack signature update status not verified',
            obj_name='ASM / Advanced WAF', kind='signature_update_evidence', line=None,
            setting='signature_updates', observed='not supplied',
            description='Current signature package status and install history require live or separately exported update evidence.',
            recommendation='Check BIG-IP Live Update installation history, status and current recommended signature package.',
            confidence='not_assessed'))
    elif update['status'] != 'current':
        added_obs.append(_entry('F5-006', 'WAF signature update status requires review',
            obj_name='ASM / Advanced WAF', kind='signature_update_evidence', line=None,
            setting='signature_updates.status', observed=update['status'],
            description='The supplied status is operator-reported; manual or scheduled updating is not automatically a vulnerability.',
            recommendation='Review Live Update status, installation history, network access, licensing and organizational update policy.',
            confidence='operator_supplied_unverified'))

    # F5-008: inventory Tcl-based iRules; report indicators for human review,
    # never execute, infer exploitability, or include code snippets in response.
    for rule in irules[:MAX_OBSERVATION_PER_GROUP]:
        referenced = uses.get(canonical(rule.name), [])
        indicators = sorted({t.value for t in rule.body if t.value in SUSPICIOUS_IRULE_COMMANDS})
        added_obs.append(_entry('F5-008', 'Custom iRule requires security review',
            obj_name=rule.name, kind='irule', line=rule.line,
            setting='iRule commands', observed=('review indicators: ' + ', '.join(indicators)) if indicators else 'custom iRule present',
            description='A custom Tcl iRule was found in the export. Listed command indicators require contextual code review and are not proof of a vulnerability.',
            recommendation='Review the iRule logic, referenced data and application impacts in a controlled test environment; retire unnecessary legacy objects.',
            confidence='static_inventory_only', associated=referenced))

    if len(findings) + len(added_findings) > 1500 or len(observations) + len(added_obs) > 1500 or len(added_findings)+len(added_obs)>MAX_REVIEW_ITEMS:
        raise EvidenceError('F5 Phase 2 evidence exceeds bounded report limits')
    findings.extend(added_findings)
    observations.extend(added_obs)
    report['findings'] = findings
    report['review_observations'] = observations
    summary = report['summary']
    summary['total_findings'] = len(findings)
    summary['total_review_observations'] = len(observations)
    for level in ('critical', 'high', 'medium', 'low'):
        summary[level + '_findings'] = sum(x.get('severity') == level.upper() for x in findings)
    summary['total_irules'] = len(irules)
    report['schema_version'] = 'f5-phase2-1.0'
    report['platform']['name'] = 'F5 BIG-IP LTM / Advanced WAF (Phases 1+2 static subset)'
    coverage = report['coverage']
    coverage['supported_checks'] = ['F5-001', 'F5-002', 'F5-003', 'F5-004', 'F5-005', 'F5-006', 'F5-007', 'F5-008']
    coverage['limitations'] = [x for x in coverage['limitations'] if 'No PDF/frontend integration or F5-004' not in x]
    coverage['limitations'].extend([
        'F5-004 is an association review, not proof of event delivery or compliance; inherited and out-of-band logging may exist.',
        'F5-005/F5-006 require independent evidence; operator assertions are not cryptographically authenticated.',
        'F5-008 is an iRule inventory and indicator review, not a Tcl interpreter or a vulnerability proof.',
    ])
    report['f5_phase2_review'] = {'total_irules': len(irules), 'operator_evidence_supplied': bool(evidence)}
    return report
