"""Fail-closed, reversible Phase 2 F5 extension installer.

Touches only phase-1 addon API, F5 frontend adapter, F5 PDF section, and
new phase-2 modules. Does not modify main.py, existing vendor parsers or Logs.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import sys
from pathlib import Path

BUNDLE = Path(__file__).resolve().parents[1]
NEW_FILES = (
    'app/f5_phase2_addon/__init__.py',
    'app/f5_phase2_addon/review.py',
)
API = 'app/f5_phase1_addon/api.py'
UI = 'frontend/src/api/f5Phase1.ts'
PDF = 'frontend/src/utils/normalizedPdf.ts'
MANIFEST = '.f5_phase2_manifest.json'
BACKUP = '.before_f5_phase2.bak'


def sha(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def safe(root: Path, rel: str) -> Path:
    p = root
    for part in Path(rel).parts:
        p = p / part
        if p.is_symlink():
            raise ValueError(f'Symlink not allowed: {rel}')
    if not p.resolve().is_relative_to(root.resolve()):
        raise ValueError('Unsafe destination')
    return p


def decode(data: bytes) -> tuple[str, str, bool]:
    bom = data.startswith(b'\xef\xbb\xbf')
    text = data.decode('utf-8-sig')
    if '\r' in text.replace('\r\n','') or ('\r\n' in text and '\n' in text.replace('\r\n','')):
        raise ValueError('Mixed or unsupported line endings')
    return text.replace('\r\n','\n'), '\r\n' if '\r\n' in text else '\n', bom


def encode(text: str, eol: str, bom: bool) -> bytes:
    return (b'\xef\xbb\xbf' if bom else b'') + text.replace('\n', eol).encode('utf-8')


def updated_api(text: str) -> str:
    a = 'from app.f5_phase2_addon.review import extend_report, EvidenceError\n'
    b = 'evidence_json: str | None = Form(None)'
    if a in text and b in text and 'extend_report(report, objects, decoded_text, evidence_json)' in text:
        return text
    anchors = [
        ('from fastapi import APIRouter, File, HTTPException, UploadFile',
         'from fastapi import APIRouter, File, Form, HTTPException, UploadFile'),
        ('from app.f5_phase1_addon.checks import analyze\n',
         'from app.f5_phase1_addon.checks import analyze\n' + a),
        ('async def analyze_f5_phase1(file: UploadFile = File(...))',
         'async def analyze_f5_phase1(file: UploadFile = File(...), evidence_json: str | None = Form(None))'),
        ("        objects = parse(raw.decode('utf-8-sig'))",
         "        decoded_text = raw.decode('utf-8-sig')\n        objects = parse(decoded_text)"),
        ("    report = analyze(objects)\n    return {**report, 'input_security_review': validation}",
         "    report = analyze(objects)\n    try:\n        report = extend_report(report, objects, decoded_text, evidence_json)\n    except EvidenceError as exc:\n        raise HTTPException(status_code=422, detail={'code': 'invalid_f5_evidence', 'message': str(exc)}) from None\n    return {**report, 'input_security_review': validation}"),
    ]
    for src, dst in anchors:
        if text.count(src) != 1:
            raise ValueError(f'Unexpected Phase 1 API structure: {src[:55]}')
        text = text.replace(src, dst, 1)
    return text


def updated_ui(text: str) -> str:
    markers = [
        ('display_name: "F5 BIG-IP (Phase 1)"', 'display_name: "F5 BIG-IP (Phases 1 + 2)"'),
        ('display_name: "F5 BIG-IP LTM / Advanced WAF (Phase 1)"',
         'display_name: "F5 BIG-IP LTM / Advanced WAF (Phases 1 + 2)"'),
        ('"F5 Phase 1 uses a separate endpoint; the other platform pipelines do not assess this configuration."',
         '"F5 Phases 1 and 2 use a separate endpoint; other vendor pipelines do not assess this configuration."'),
    ]
    for before, after in markers:
        if text.count(before) == 1:
            text = text.replace(before, after, 1)
        elif text.count(after) != 1:
            raise ValueError(f'F5 frontend adapter changed unexpectedly: {before[:50]}')
    return text


def updated_pdf(text: str) -> str:
    old = 'section("F5 BIG-IP Phase 1 - Detailed technical evidence");'
    new = 'section("F5 BIG-IP Phases 1 + 2 - Detailed technical evidence");'
    if text.count(old) != 1 and text.count(new) != 1:
        raise ValueError('Cannot locate existing F5 PDF evidence section')
    text = text.replace(old, new)
    old_description = 'Static subset: F5-001 TLS 1.3, F5-002 cipher policy review, F5-003 server certificate validation, F5-007 HSTS. No live TLS probe or deployment verification.'
    new_description = 'Static F5-001/002/003/007 checks plus F5-004 logging associations, F5-005 UCS evidence, F5-006 update evidence and F5-008 iRule inventory. No live F5 or UCS inspection.'
    if text.count(old_description) == 1:
        text = text.replace(old_description, new_description)
    elif text.count(new_description) != 1:
        raise ValueError('F5 PDF evidence description differs; no changes made')
    if '"F5 PHASE 1 COVERAGE LIMITATIONS"' in text:
        text = text.replace('"F5 PHASE 1 COVERAGE LIMITATIONS"', '"F5 PHASES 1 + 2 COVERAGE LIMITATIONS"', 1)
    return text


def plan(root: Path) -> dict[str, bytes]:
    root = root.resolve()
    for rel in (API, UI, PDF):
        if not safe(root, rel).is_file():
            raise ValueError(f'Missing working Phase 1 file: {rel}')
    changes: dict[str, bytes] = {}
    for rel, transformer in ((API, updated_api), (UI, updated_ui), (PDF, updated_pdf)):
        old = safe(root, rel).read_bytes()
        src, eol, bom = decode(old)
        new = encode(transformer(src), eol, bom)
        if new != old:
            changes[rel] = new
    for rel in NEW_FILES:
        target = safe(root, rel)
        original = (BUNDLE / rel).read_bytes()
        if target.exists():
            if not target.is_file() or target.read_bytes() != original:
                raise ValueError(f'Existing custom module; refusing overwrite: {rel}')
        else:
            changes[rel] = original
    return changes


def install(root: Path, dry_run: bool = False) -> list[str]:
    root = root.resolve()
    modifications = plan(root)
    manifest = safe(root, MANIFEST)
    if manifest.exists():
        if modifications:
            raise ValueError('Manifest exists but changes are incomplete; inspect project')
        return []
    if not modifications or dry_run:
        return list(modifications)
    backups = [safe(root, rel).with_name(Path(rel).name+BACKUP) for rel in modifications]
    if any(b.exists() for b in backups):
        raise ValueError('Backup collision; no files modified')
    originals = {rel: safe(root, rel).read_bytes() if safe(root, rel).is_file() else None for rel in modifications}
    done = []
    try:
        for rel, data in modifications.items():
            target = safe(root, rel)
            target.parent.mkdir(parents=True, exist_ok=True)
            if originals[rel] is not None:
                target.with_name(target.name+BACKUP).write_bytes(originals[rel])
            target.write_bytes(data)
            done.append(rel)
        info = {'version': 1, 'files': {rel: {
            'created': originals[rel] is None,
            'installed_sha256': sha(data),
            'original_sha256': sha(originals[rel]) if originals[rel] is not None else None,
        } for rel, data in modifications.items()}}
        tmp = safe(root, MANIFEST+'.tmp')
        tmp.write_text(json.dumps(info, indent=2), encoding='utf-8')
        tmp.replace(manifest)
    except Exception:
        for rel in reversed(done):
            target = safe(root, rel)
            if originals[rel] is None:
                target.unlink(missing_ok=True)
            else:
                target.write_bytes(originals[rel])
                target.with_name(target.name+BACKUP).unlink(missing_ok=True)
        safe(root, MANIFEST+'.tmp').unlink(missing_ok=True)
        raise
    return done


def rollback(root: Path) -> list[str]:
    root = root.resolve()
    manifest = safe(root, MANIFEST)
    if not manifest.is_file():
        raise ValueError('No Phase 2 manifest found')
    info = json.loads(manifest.read_text(encoding='utf-8'))
    files = info.get('files')
    if info.get('version') != 1 or not isinstance(files, dict) or not set(files).issubset(set(NEW_FILES) | {API, UI, PDF}):
        raise ValueError('Invalid rollback manifest')
    # Verify all before changing anything
    for rel, record in files.items():
        target = safe(root, rel)
        if not target.is_file() or sha(target.read_bytes()) != record['installed_sha256']:
            raise ValueError(f'Modified since installation: {rel}')
        if not record['created']:
            back = target.with_name(target.name+BACKUP)
            if not back.is_file() or sha(back.read_bytes()) != record['original_sha256']:
                raise ValueError(f'Backup missing/modified: {rel}')
    for rel, record in files.items():
        target = safe(root, rel)
        if record['created']:
            target.unlink()
        else:
            back = target.with_name(target.name+BACKUP)
            target.write_bytes(back.read_bytes())
            back.unlink()
    manifest.unlink()
    return list(files)


def main() -> int:
    parser = argparse.ArgumentParser(description='F5 BIG-IP Phase 2 installer')
    parser.add_argument('root', nargs='?', default='.')
    parser.add_argument('--dry-run', action='store_true')
    parser.add_argument('--rollback', action='store_true')
    args = parser.parse_args()
    try:
        updates = rollback(Path(args.root)) if args.rollback else install(Path(args.root), args.dry_run)
        print('Rolled back:' if args.rollback else 'Would update:' if args.dry_run else 'Installed:')
        print('\n'.join('  '+rel for rel in updates) if updates else '  No changes needed')
        return 0
    except (ValueError, OSError, UnicodeError, KeyError) as exc:
        print('ERROR:', exc, file=sys.stderr)
        return 1

if __name__ == '__main__':
    raise SystemExit(main())
