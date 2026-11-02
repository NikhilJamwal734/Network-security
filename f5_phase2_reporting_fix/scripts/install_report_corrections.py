"""Safely correct Phase-2 F5 PDF provenance, coverage, and iRule context.

Applies three small, anchored changes; never touches other vendor analysis.
Supports --dry-run, UTF-8 BOM/CRLF, idempotence, transactional rollback.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

PDF = 'frontend/src/utils/normalizedPdf.ts'
ADAPTER = 'frontend/src/api/f5Phase1.ts'
REVIEW = 'app/f5_phase2_addon/review.py'
FILES = (PDF, ADAPTER, REVIEW)
MANIFEST = '.f5_phase2_report_corrections_manifest.json'
BACKUP = '.before_f5_phase2_report_corrections.bak'


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def safe(root: Path, rel: str) -> Path:
    cur = root
    for seg in Path(rel).parts:
        cur = cur / seg
        if cur.is_symlink():
            raise ValueError(f'Symlink component prohibited: {rel}')
    if not cur.resolve().is_relative_to(root.resolve()):
        raise ValueError(f'Outside project root: {rel}')
    return cur


def decode(raw: bytes) -> tuple[str, str, bool]:
    bom = raw.startswith(b'\xef\xbb\xbf')
    value = raw.decode('utf-8-sig')
    if '\r' in value.replace('\r\n', '') or ('\r\n' in value and '\n' in value.replace('\r\n', '')):
        raise ValueError('Mixed or unsupported line endings')
    return value.replace('\r\n', '\n'), ('\r\n' if '\r\n' in value else '\n'), bom


def encode(value: str, eol: str, bom: bool) -> bytes:
    return (b'\xef\xbb\xbf' if bom else b'') + value.replace('\n', eol).encode('utf-8')


def replace_exact(src: str, old: str, new: str, description: str) -> str:
    if old not in src and src.count(new) == 1:
        return src
    if src.count(old) != 1 or src.count(new) != 0:
        raise ValueError(f'Unsupported/partial {description}; no files changed')
    return src.replace(old, new, 1)


PDF_OLD_PROVENANCE = '''    text("Validation occurred before analysis at the API-011.6 endpoint. These are bounded text/file checks, NOT a claim that the configuration is safe or every API route is protected.", {'''
PDF_NEW_PROVENANCE = '''    text(report.platform.platform_id === "f5_bigip"
      ? "Input bytes were validated by the dedicated F5 upload endpoint using shared API-011.6 validation helpers. The accepted file then entered the F5 Phase 1 + 2 analysis pipeline, not the general API-011.4 chain. These checks do not establish device security."
      : "Validation occurred before analysis at the API-011.6 endpoint. These are bounded text/file checks, NOT a claim that the configuration is safe or every API route is protected.", {'''
PDF_OLD_LIMITATIONS = '''    inputSecurity.limitations.forEach((item) => text(`Limitation: ${item}`, {'''
PDF_NEW_LIMITATIONS = '''    const inputLimitations = report.platform.platform_id === "f5_bigip"
      ? [
          "The dedicated F5 endpoint reuses API-011.6 input-validation helpers. Validation coverage of other endpoints is not established.",
          "Multipart parsing precedes handler validation; configure upstream ASGI or reverse-proxy request size limits.",
          "After validation, the dedicated F5 analysis pipeline runs; the general API-011.4 analysis chain is not used.",
          "Input checks do not prove effective device security, complete parsing, or accuracy of the security findings.",
        ]
      : inputSecurity.limitations;
    inputLimitations.forEach((item) => text(`Limitation: ${item}`, {'''
PDF_OLD_F5_IRULE = '''        text(item.description, { indent: 8, size: 8.5, spaceAfter: 4 });'''
PDF_NEW_F5_IRULE = '''        text(item.description, { indent: 8, size: 8.5, spaceAfter: 4 });
        if (item.code === "F5-008" && item.evidence.observed.includes("ASM::disable")) {
          text("Review note: ASM::disable can suppress ASM/Advanced WAF inspection for requests on which it executes. Confirm the iRule event, conditional scope, and any authorization exceptions; this static observation does not prove a live WAF bypass.", {
            indent: 8, size: 8.3, color: COLORS.blue, spaceAfter: 5,
          });
        }'''


def patch_pdf(src: str) -> str:
    if src.count('section("F5 BIG-IP Phases 1 + 2 - Detailed technical evidence")') != 1:
        raise ValueError('F5 Phase 2 PDF evidence section not found exactly once')
    if src.count('if (report.input_security_review)') != 1:
        raise ValueError('API-011.6 upload evidence section not found exactly once')
    src = replace_exact(src, PDF_OLD_PROVENANCE, PDF_NEW_PROVENANCE, 'upload provenance')
    src = replace_exact(src, PDF_OLD_LIMITATIONS, PDF_NEW_LIMITATIONS, 'upload limitation text')
    # Keep F5 note conditional and scoped to its PDF evidence block only.
    anchor = '    const printF5Items = (items: F5Phase1Review["findings"], heading: string) => {'
    if src.count(anchor) != 1:
        raise ValueError('F5 PDF item rendering function not found exactly once')
    before, after = src.split(anchor, 1)
    if after.count(PDF_OLD_F5_IRULE) != 1 and after.count(PDF_NEW_F5_IRULE) != 1:
        raise ValueError('F5 item description anchor changed')
    if after.count(PDF_NEW_F5_IRULE) != 1:
        after = replace_exact(after, PDF_OLD_F5_IRULE, PDF_NEW_F5_IRULE, 'iRule context note')
    return before + anchor + after


ADAPTER_OLD = '''  const limitations = body.coverage.limitations.filter((v): v is string => typeof v === "string");
  return {'''
ADAPTER_NEW = '''  const limitations = body.coverage.limitations.filter((v): v is string => typeof v === "string");
  // Phase 2 evidence remains operator-supplied, not independently verified.
  const phase2: Record<string, unknown> = isObject(body.f5_phase2_review) ? body.f5_phase2_review : {};
  const hasUcsEvidence = phase2.ucs_evidence_supplied === true ||
    [...findings, ...observations].some((item) => item.code === "F5-005" && item.confidence !== "not_assessed");
  const hasSignatureEvidence = phase2.signature_update_evidence_supplied === true ||
    [...findings, ...observations].some((item) => item.code === "F5-006" && item.confidence !== "not_assessed");
  return {'''
ADAPTER_OLD_DOMAINS = '''        { domain: "F5 TLS / cipher / certificate / HSTS Phase 1 subset", status: "assessed" },
        { domain: "Other F5 BIG-IP, LTM and WAF settings", status: "not_assessed" },'''
ADAPTER_NEW_DOMAINS = '''        { domain: "F5 TLS / cipher / certificate / HSTS Phase 1 subset", status: "assessed" },
        { domain: "F5 Phase 2 - virtual logging association and iRule inventory subset", status: "assessed" },
        { domain: "F5 UCS backup evidence (operator assertion only)", status: hasUcsEvidence ? "assessed" : "not_assessed" },
        { domain: "F5 WAF signature update evidence (operator assertion only)", status: hasSignatureEvidence ? "assessed" : "not_assessed" },
        { domain: "Other F5 BIG-IP, LTM and WAF settings", status: "not_assessed" },'''


def patch_adapter(src: str) -> str:
    if 'display_name: "F5 BIG-IP (Phases 1 + 2)"' not in src:
        raise ValueError('F5 adapter must have Phase 2 installed')
    src = replace_exact(src, ADAPTER_OLD, ADAPTER_NEW, 'F5 Phase 2 evidence flags')
    src = replace_exact(src, ADAPTER_OLD_DOMAINS, ADAPTER_NEW_DOMAINS, 'F5 assessment coverage')
    return src


REVIEW_OLD_DESCRIPTION = '''            description='A custom Tcl iRule was found in the export. Listed command indicators require contextual code review and are not proof of a vulnerability.',
            recommendation='Review the iRule logic, referenced data and application impacts in a controlled test environment; retire unnecessary legacy objects.','''
REVIEW_NEW_DESCRIPTION = '''            description=_irule_description(rule, indicators),
            recommendation='Confirm the triggering event and conditions for any ASM::disable token; review iRule logic, referenced data and application impacts in a controlled test environment. No runtime bypass is established.','''
REVIEW_OLD_META = '''    report['f5_phase2_review'] = {'total_irules': len(irules), 'operator_evidence_supplied': bool(evidence)}'''
REVIEW_NEW_META = '''    report['f5_phase2_review'] = {
        'total_irules': len(irules),
        'operator_evidence_supplied': bool(evidence),
        'ucs_evidence_supplied': 'ucs_backups' in evidence,
        'signature_update_evidence_supplied': 'signature_updates' in evidence,
    }'''
REVIEW_FUNCTION = '''def _irule_description(rule: ConfigObject, indicators: list[str]) -> str:
    """Bounded source-context hints only; never evaluate Tcl or emit arbitrary code.

    An iRule can have many branches, so a nearby condition is not proof that
    it guards the ASM::disable command. Only safe URI paths are shown.
    """
    base = ('A custom Tcl iRule was found in the export. Listed command indicators '
            'require contextual review; no runtime vulnerability has been demonstrated.')
    if 'ASM::disable' not in indicators:
        return base
    tokens = list(rule.body)
    calls = [t for t in tokens if t.value == 'ASM::disable']
    detail = f' ASM::disable token appears at source line {calls[0].line}.' if calls else ''
    values = [t.value for t in tokens]
    if any(values[i:i+2] == ['when', 'HTTP_REQUEST'] for i in range(len(values)-1)):
        detail += ' The iRule contains an HTTP_REQUEST event block.'
    for i in range(len(values)-2):
        if values[i] in ('[HTTP::uri]', '[HTTP::path]') and values[i+1] in ('contains', 'equals', 'starts_with'):
            literal = values[i+2]
            if re.fullmatch(r'/[A-Za-z0-9/_-]{1,40}', literal):
                detail += f' A static URI selector {values[i]} {values[i+1]} "{literal}" was found in this iRule.'
                break
    return base + detail + (' ASM::disable may suppress Advanced WAF inspection for the requests on which it executes; '
                            'confirm the actual condition and scope before concluding there is a bypass.')


'''


def patch_review(src: str) -> str:
    if src.count('def extend_report(') != 1:
        raise ValueError('Phase 2 extension function not found exactly once')
    if 'def _irule_description(' not in src:
        src = REVIEW_FUNCTION + src if src.startswith('from __future__') else src.replace('def extend_report(', REVIEW_FUNCTION + 'def extend_report(', 1)
        # Future imports must remain at the top of the module. If inserted at
        # the top, move it immediately before the main extension function.
        if src.startswith(REVIEW_FUNCTION):
            src = src[len(REVIEW_FUNCTION):]
            src = src.replace('def extend_report(', REVIEW_FUNCTION + 'def extend_report(', 1)
    elif src.count('def _irule_description(') != 1 or REVIEW_FUNCTION not in src:
        raise ValueError('Existing custom iRule helper; refusing overwrite')
    src = replace_exact(src, REVIEW_OLD_DESCRIPTION, REVIEW_NEW_DESCRIPTION, 'iRule evidence')
    src = replace_exact(src, REVIEW_OLD_META, REVIEW_NEW_META, 'Phase 2 evidence status')
    return src


PATCHERS = {PDF: patch_pdf, ADAPTER: patch_adapter, REVIEW: patch_review}


def plan(root: Path) -> dict[str, bytes]:
    root = root.resolve()
    replacements: dict[str, bytes] = {}
    for rel in FILES:
        f = safe(root, rel)
        if not f.is_file():
            raise ValueError(f'Required installed Phase 2 file missing: {rel}')
        raw = f.read_bytes()
        src, eol, bom = decode(raw)
        dest = encode(PATCHERS[rel](src), eol, bom)
        if dest != raw:
            replacements[rel] = dest
    return replacements


def install(root: Path, dry_run: bool = False) -> list[str]:
    root = root.resolve()
    manifest = safe(root, MANIFEST)
    changes = plan(root)
    if manifest.exists():
        if changes:
            raise ValueError('Reporting-fix manifest exists but target files differ. Inspect manually.')
        return []
    if dry_run or not changes:
        return list(changes)
    originals = {rel: safe(root, rel).read_bytes() for rel in changes}
    backups = {rel: safe(root, rel).with_name(Path(rel).name + BACKUP) for rel in changes}
    if any(f.exists() for f in backups.values()):
        raise ValueError('Backup-file collision. No files modified.')
    if any(safe(root, rel).is_symlink() for rel in changes):
        raise ValueError('Symlink target prohibited')
    done: list[str] = []
    try:
        for rel, data in changes.items():
            f = safe(root, rel)
            backups[rel].write_bytes(originals[rel])
            f.write_bytes(data)
            done.append(rel)
        record = {'version': 1, 'files': {rel: {
            'original_sha256': sha(originals[rel]),
            'installed_sha256': sha(data),
        } for rel, data in changes.items()}}
        temporary = safe(root, MANIFEST + '.tmp')
        temporary.write_text(json.dumps(record, indent=2), encoding='utf-8')
        temporary.replace(manifest)
    except Exception:
        for rel in reversed(done):
            safe(root, rel).write_bytes(originals[rel])
        for f in backups.values():
            f.unlink(missing_ok=True)
        safe(root, MANIFEST + '.tmp').unlink(missing_ok=True)
        raise
    return done


def rollback(root: Path) -> list[str]:
    root = root.resolve()
    mf = safe(root, MANIFEST)
    if not mf.is_file():
        raise ValueError('No reporting-fix manifest found')
    data = json.loads(mf.read_text(encoding='utf-8'))
    records = data.get('files')
    if data.get('version') != 1 or not isinstance(records, dict) or not records or not set(records).issubset(FILES):
        raise ValueError('Invalid reporting-fix manifest')
    for rel, hashes in records.items():
        target = safe(root, rel)
        bak = target.with_name(target.name+BACKUP)
        if not target.is_file() or sha(target.read_bytes()) != hashes['installed_sha256']:
            raise ValueError(f'File changed after patch; refusing rollback: {rel}')
        if not bak.is_file() or sha(bak.read_bytes()) != hashes['original_sha256']:
            raise ValueError(f'Backup changed or missing: {rel}')
    for rel in records:
        target = safe(root, rel)
        bak = target.with_name(target.name+BACKUP)
        target.write_bytes(bak.read_bytes())
        bak.unlink()
    mf.unlink()
    return list(records)


def main() -> int:
    parser = argparse.ArgumentParser(description='F5 Phase 2 report corrections (provenance, coverage, iRules)')
    parser.add_argument('root', nargs='?', default='.')
    parser.add_argument('--dry-run', action='store_true')
    parser.add_argument('--rollback', action='store_true')
    args = parser.parse_args()
    try:
        modified = rollback(Path(args.root)) if args.rollback else install(Path(args.root), args.dry_run)
        print('Rolled back:' if args.rollback else 'Would update:' if args.dry_run else 'Installed:')
        print('\n'.join('  ' + rel for rel in modified) if modified else '  No changes needed')
        return 0
    except (ValueError, OSError, UnicodeError, KeyError, TypeError) as exc:
        print('ERROR:', exc, file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
