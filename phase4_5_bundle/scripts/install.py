"""Guarded Phase 4.4 + F5 assurance additive patch installer.

Never deletes files; makes SHA256-verified rollback copies before writing.
Uses only known, unique anchors; refuses customized files it cannot recognize.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys

PACKAGE = Path(__file__).resolve().parents[1]
MAIN = 'app/api/main.py'
API = 'app/f5_phase1_addon/api.py'
PDF = 'frontend/src/utils/normalizedPdf.ts'
ADAPTER = 'frontend/src/api/f5Phase1.ts'
CREATED = ('app/security/desktop_boundary.py', 'app/f5_phase5_addon/assurance.py',
           'app/f5_phase5_addon/__init__.py')
MANIFEST = '.phase45_assurance_manifest.json'
BACKUP = '.phase45_assurance_backups'
PDF_ADD = '''    const f5Assurance = (report as NormalizedReport & { f5_assurance_review?: {
      assessment_type: string;
      unresolved_profile_references: Array<{ virtual_server: string; profile: string }>;
      profile_inheritance: Array<{ profile: string; parent: string; effective_inheritance_verified: boolean }>;
      profile_tls_evidence: Array<{ profile: string; explicit_cipher_expression: string | null; explicit_cipher_group: string | null }>;
      irule_control_flow_review: Array<{ rule: string; indicators: Array<{ token: string; line: number }> }>;
      limitations: string[];
    } }).f5_assurance_review;
    if (f5Assurance) {
      section("F5 EVIDENCE ASSURANCE AND VERIFICATION GAPS");
      text("Supplemental static evidence review only. No runtime, live-device, inherited defaults, certificate chain, cipher-suite expansion or UCS content verification is claimed.", {
        size: 8.2, color: COLORS.muted, spaceAfter: 6,
      });
      text(`Unresolved exported profile references: ${f5Assurance.unresolved_profile_references.length} | Explicit inheritance links: ${f5Assurance.profile_inheritance.length} | SSL profiles reviewed: ${f5Assurance.profile_tls_evidence.length} | iRule indicator reviews: ${f5Assurance.irule_control_flow_review.length}`, {
        size: 8.5, bold: true, spaceAfter: 7,
      });
      f5Assurance.unresolved_profile_references.slice(0, 30).forEach(item =>
        text(`Reference not in uploaded subset: ${item.virtual_server} -> ${item.profile}`, { size: 8, spaceAfter: 3 }));
      f5Assurance.profile_inheritance.slice(0, 30).forEach(item =>
        text(`Inheritance unresolved: ${item.profile} derives from ${item.parent}`, { size: 8, spaceAfter: 3 }));
      f5Assurance.l imitations_PLACEHOLDER
    }
'''.replace('      f5Assurance.l imitations_PLACEHOLDER', '''      f5Assurance.limitations.slice(0, 10).forEach(item =>
        text(`Limit: ${item}`, { size: 8, color: COLORS.muted, spaceAfter: 4 }));''')


def sha(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def safe(root: Path, rel: str) -> Path:
    if Path(rel).is_absolute() or '..' in Path(rel).parts:
        raise ValueError('Unsafe relative destination')
    p = root
    for part in Path(rel).parts:
        p = p / part
        if p.is_symlink():
            raise ValueError('Symlink is prohibited: ' + rel)
    if not p.resolve().is_relative_to(root.resolve()):
        raise ValueError('Destination outside project root')
    return p


def decode(src: bytes):
    bom = src.startswith(b'\xef\xbb\xbf')
    text = src.decode('utf-8-sig')
    if ('\r\n' in text and '\n' in text.replace('\r\n', '')) or '\r' in text.replace('\r\n', ''):
        raise ValueError('Mixed or unsupported source line endings')
    return text.replace('\r\n', '\n'), ('\r\n' if '\r\n' in text else '\n'), bom


def encode(src: str, eol: str, bom: bool):
    return (b'\xef\xbb\xbf' if bom else b'') + src.replace('\n', eol).encode('utf-8')


def replace_once(src: str, old: str, new: str, label: str):
    if src.count(old) != 1 or src.count(new) != 0:
        raise ValueError('Unsafe or already patched: ' + label)
    return src.replace(old, new, 1)


def update_main(src: str):
    if 'app.add_middleware(DesktopBoundaryMiddleware)' in src:
        return src
    src = replace_once(src, 'from app.core.audit_logging import AccessAuditMiddleware\n',
                       'from app.core.audit_logging import AccessAuditMiddleware\nfrom app.security.desktop_boundary import DesktopBoundaryMiddleware\n',
                       'main import')
    src = replace_once(src, 'app.add_middleware(AccessAuditMiddleware)',
                       'app.add_middleware(AccessAuditMiddleware)\napp.add_middleware(DesktopBoundaryMiddleware)',
                       'main middleware')
    if 'app.include_router(f5_phase1_addon_router)' not in src:
        raise ValueError('F5 router missing in main app')
    return src


def update_api(src: str):
    if "report['f5_assurance_review'] = build_assurance" in src:
        return src
    if 'extend_report(report, objects, decoded_text, evidence_json)' not in src:
        raise ValueError('Phase 2+ F5 evidence API not present')
    src = replace_once(src, 'from app.f5_phase1_addon.checks import analyze\n',
                       'from app.f5_phase1_addon.checks import analyze\nfrom app.f5_phase5_addon.assurance import build_assurance\n',
                       'F5 import')
    src = replace_once(src, "    return {**report, 'input_security_review': validation}",
                       "    report['f5_assurance_review'] = build_assurance(objects, decoded_text, report)\n    return {**report, 'input_security_review': validation}",
                       'F5 return')
    return src



def update_adapter(src: str):
    if 'f5_assurance_review: body.f5_assurance_review' in src:
        return src
    anchor = '    ...(isObject(body.input_security_review) ? { input_security_review: body.input_security_review } : {}),'
    if src.count(anchor) != 1:
        raise ValueError('Expected normalized F5 adapter return not found')
    return src.replace(anchor, anchor + "\n    ...(isObject(body.f5_assurance_review) ? { f5_assurance_review: body.f5_assurance_review } : {}),", 1)


def update_pdf(src: str):
    if 'F5 EVIDENCE ASSURANCE AND VERIFICATION GAPS' in src:
        return src
    # The name is from the installed phase2 pdf; don't touch unrelated vendor PDF sections.
    marker = '    section("F5 BIG-IP Phases 1 + 2 - Detailed technical evidence");'
    if src.count(marker) != 1:
        raise ValueError('Expected installed F5 Phase2 PDF section missing (no edits made)')
    if 'const f5Phase1Review =' not in src or '  if (f5Phase1Review) {' not in src:
        raise ValueError('Expected F5 PDF guard missing')
    return src.replace(marker, PDF_ADD + marker, 1)


def prepare(root: Path) -> dict[str, tuple[bytes | None, bytes]]:
    result: dict[str, tuple[bytes | None, bytes]] = {}
    for rel, transformer in ((MAIN, update_main), (API, update_api), (ADAPTER, update_adapter), (PDF, update_pdf)):
        p = safe(root, rel)
        if not p.is_file():
            raise ValueError('Existing source file not found: ' + rel)
        old = p.read_bytes()
        src, eol, bom = decode(old)
        new = encode(transformer(src), eol, bom)
        if new != old:
            result[rel] = (old, new)
    for rel in CREATED:
        p = safe(root, rel)
        contents = (PACKAGE / rel).read_bytes()
        if p.exists():
            if not p.is_file() or p.read_bytes() != contents:
                raise ValueError('Existing custom source differs; refusing overwrite: ' + rel)
        else:
            result[rel] = (None, contents)
    if len(result) not in (0, 7):
        raise ValueError('Partial Phase 4/5 patch detected; refusing changes')
    return result


def install(root: Path, dry_run=False):
    root = root.resolve()
    manifest = safe(root, MANIFEST)
    if manifest.exists():
        if prepare(root):
            raise ValueError('Manifest exists but installation modified; inspect project')
        return []
    changes = prepare(root)
    if dry_run or not changes:
        return list(changes)
    bdir = safe(root, BACKUP)
    if bdir.exists():
        raise ValueError('Preexisting backup directory; refusing overwrite')
    bdir.mkdir()
    done = []
    try:
        entries = []
        for i, (rel, (old, new)) in enumerate(changes.items()):
            p = safe(root, rel)
            backup = f'{i}.bak' if old is not None else None
            if backup:
                (bdir / backup).write_bytes(old)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(new)
            done.append((rel, old))
            entries.append({'path': rel, 'old_hash': sha(old) if old is not None else None,
                            'new_hash': sha(new), 'backup': backup})
        tmp = safe(root, MANIFEST+'.tmp')
        tmp.write_text(json.dumps({'version': 1, 'files': entries}, indent=2), encoding='utf-8')
        os.replace(tmp, manifest)
    except Exception:
        for rel, old in reversed(done):
            p = safe(root, rel)
            if old is None: p.unlink(missing_ok=True)
            else: p.write_bytes(old)
        for b in bdir.iterdir(): b.unlink()
        bdir.rmdir()
        safe(root, MANIFEST+'.tmp').unlink(missing_ok=True)
        raise
    return list(changes)


def rollback(root: Path):
    root = root.resolve()
    manifest = safe(root, MANIFEST)
    if not manifest.is_file():
        raise ValueError('No manifest for rollback')
    info = json.loads(manifest.read_text(encoding='utf-8'))
    items = info.get('files')
    allowed = {MAIN, API, ADAPTER, PDF, *CREATED}
    if info.get('version') != 1 or not isinstance(items, list) or len(items) != 7 or {x.get('path') for x in items} != allowed:
        raise ValueError('Manifest mismatch; manual review required')
    bdir = safe(root, BACKUP)
    restored = {}
    for item in items:
        rel = item['path']; p = safe(root, rel)
        if not p.is_file() or sha(p.read_bytes()) != item['new_hash']:
            raise ValueError('Source changed since installation: ' + rel)
        if item['backup']:
            backup = safe(root, BACKUP + '/' + item['backup'])
            if not backup.is_file() or sha(backup.read_bytes()) != item['old_hash']:
                raise ValueError('Backup corrupted: ' + rel)
            restored[rel] = backup.read_bytes()
        else:
            restored[rel] = None
    for rel, original in restored.items():
        p = safe(root, rel)
        if original is None:
            p.unlink()
        else:
            p.write_bytes(original)
    for b in bdir.iterdir(): b.unlink()
    bdir.rmdir()
    manifest.unlink()
    return list(restored)


def main(argv=None):
    cli = argparse.ArgumentParser(description='Guarded Phase 4.4 + F5 evidence assurance installer')
    cli.add_argument('root', nargs='?', default='.')
    mode = cli.add_mutually_exclusive_group()
    mode.add_argument('--dry-run', action='store_true')
    mode.add_argument('--rollback', action='store_true')
    a = cli.parse_args(argv)
    try:
        changed = rollback(Path(a.root)) if a.rollback else install(Path(a.root), a.dry_run)
        print(('ROLLBACK PASS' if a.rollback else 'DRY RUN PASS' if a.dry_run else 'INSTALL PASS') + ': ' + str(len(changed)) + ' source files')
        for p in changed: print('  ' + p)
        return 0
    except (OSError, ValueError, UnicodeError, KeyError, TypeError) as exc:
        print('ERROR: ' + str(exc), file=sys.stderr)
        return 1

if __name__ == '__main__':
    raise SystemExit(main())
