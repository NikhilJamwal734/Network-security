"""Add F5 Phase 1 to the existing React selector and normalized PDF.

Never changes the Python backend, existing parser, App.tsx, sidebar, or
existing findings. Dry run, idempotent install and verified rollback.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

BUNDLE = Path(__file__).resolve().parents[1]
NEW_FILE = 'frontend/src/api/f5Phase1.ts'
PAGE = 'frontend/src/pages/UniversalAnalysis.tsx'
PDF = 'frontend/src/utils/normalizedPdf.ts'
MAIN = 'app/f5_phase1_addon/api.py'
FRONTEND = 'frontend/package.json'
MANIFEST = '.f5_phase1_ui_manifest.json'
BACKUP = '.before_f5_phase1_ui.bak'
IMPORTED = 'import { F5_PLATFORM_ID, withF5Platform, analyzeF5Phase1 } from "../api/f5Phase1";'
PDF_IMPORT = 'import type { F5Phase1Review } from "../api/f5Phase1";'

PDF_DETAILS = '''  const f5Phase1Review = (report as NormalizedReport & { f5_phase1_review?: F5Phase1Review }).f5_phase1_review;
  if (f5Phase1Review) {
    section("F5 BIG-IP Phase 1 - Detailed technical evidence");
    text("Static subset: F5-001 TLS 1.3, F5-002 cipher policy review, F5-003 server certificate validation, F5-007 HSTS. No live TLS probe or deployment verification.", {
      size: 8.5, color: COLORS.muted, spaceAfter: 7,
    });
    text(`Profiles: ${f5Phase1Review.total_profiles} | Virtual servers: ${f5Phase1Review.total_virtual_servers} | Findings: ${f5Phase1Review.findings.length} | Review observations: ${f5Phase1Review.review_observations.length}`, {
      size: 9, bold: true, spaceAfter: 7,
    });
    const printF5Items = (items: F5Phase1Review["findings"], heading: string) => {
      text(heading, { bold: true, color: COLORS.blue, size: 9.1, spaceAfter: 6 });
      if (!items.length) text("No items returned in this category.", { size: 8.5, color: COLORS.muted });
      items.slice(0, 500).forEach((item) => {
        ensure(68);
        text(`${item.code} | ${item.title} | ${item.severity.toUpperCase()}`, { bold: true, size: 9.1, spaceAfter: 4 });
        text(`Object: ${item.affected_object} (${item.object_type}) | Source line: ${item.line_number ?? "not available"} | Confidence: ${item.confidence}`, {
          size: 8.2, color: COLORS.muted, spaceAfter: 3,
        });
        text(`Setting: ${item.evidence.setting} | Observed: ${item.evidence.observed}`, { size: 8.4, indent: 8, spaceAfter: 4 });
        if (item.associated_virtual_servers.length) {
          text(`Associated virtual servers: ${item.associated_virtual_servers.join(", ")}`, {
            size: 8.1, indent: 8, spaceAfter: 4,
          });
        }
        text(item.description, { indent: 8, size: 8.5, spaceAfter: 4 });
        text(`Recommendation: ${item.recommendation}`, { indent: 8, size: 8.5, spaceAfter: 5 });
        text(`Limitation: ${item.limitations}`, { indent: 8, color: COLORS.muted, size: 8, spaceAfter: 8 });
      });
      if (items.length > 500) text("Further F5 records omitted because the PDF safety limit was reached; refer to the complete JSON export.", {
        color: COLORS.muted, size: 8.2,
      });
    };
    printF5Items(f5Phase1Review.findings, "CONFIGURATION FINDINGS");
    printF5Items(f5Phase1Review.review_observations, "POLICY REVIEW / INSUFFICIENT EVIDENCE (NOT CONFIRMED VULNERABILITIES)");
    text("F5 PHASE 1 COVERAGE LIMITATIONS", { bold: true, color: COLORS.blue, size: 9, spaceAfter: 5 });
    f5Phase1Review.limitations.forEach((item) => text(`Limitation: ${item}`, {
      size: 8.2, color: COLORS.muted, spaceAfter: 5,
    }));
  }

'''

def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def safe_path(root: Path, relative: str) -> Path:
    current = root
    for part in Path(relative).parts:
        current = current / part
        if current.is_symlink():
            raise ValueError(f"Symlink not allowed: {relative}")
    if not current.resolve().is_relative_to(root):
        raise ValueError(f"Outside project root: {relative}")
    return current


def decode_source(data: bytes) -> tuple[str, str, bool]:
    bom = data.startswith(b'\xef\xbb\xbf')
    text = data.decode('utf-8-sig')
    if '\r' in text.replace('\r\n', '') or ('\r\n' in text and '\n' in text.replace('\r\n','')):
        raise ValueError('Mixed or invalid line endings')
    eol = '\r\n' if '\r\n' in text else '\n'
    return text.replace('\r\n', '\n'), eol, bom


def encode_source(text: str, eol: str, bom: bool) -> bytes:
    return (b'\xef\xbb\xbf' if bom else b'') + text.replace('\n', eol).encode('utf-8')


def insert_page(src: str) -> str:
    if src.count(IMPORTED) > 1:
        raise ValueError('Duplicate F5 import')
    if src.count(IMPORTED) == 1:
        if 'setPlatforms(withF5Platform(list))' not in src or 'choice === F5_PLATFORM_ID' not in src:
            raise ValueError('Partially integrated F5 UI; refusing to modify')
        return src
    marker = 'from "../api/universal";'
    if src.count(marker) != 1:
        raise ValueError('Cannot find unique universal API import in UniversalAnalysis.tsx')
    src = src.replace(marker, marker + '\n' + IMPORTED, 1)
    if src.count('setPlatforms(list)') != 1:
        raise ValueError('Cannot find unique platform list assignment')
    src = src.replace('setPlatforms(list)', 'setPlatforms(withF5Platform(list))', 1)
    pattern = r'const next\s*=\s*await\s+analyzeNormalized\(\s*file\s*,\s*choice\s*===\s*["\']auto["\']\s*\?\s*null\s*:\s*choice\s*,\s*controller\.signal\s*\);'
    if len(re.findall(pattern, src)) != 1:
        raise ValueError('Expected single normalized analysis call not found; preserving custom UI')
    src = re.sub(pattern,
        'const next = choice === F5_PLATFORM_ID\n'
        '        ? await analyzeF5Phase1(file, controller.signal)\n'
        '        : await analyzeNormalized(file, choice === "auto" ? null : choice, controller.signal);',
        src, count=1)
    return src


def insert_pdf(src: str) -> str:
    if 'const f5Phase1Review = (report as NormalizedReport' in src:
        if src.count(PDF_IMPORT) != 1 or src.count('section("F5 BIG-IP Phase 1 - Detailed technical evidence")') != 1:
            raise ValueError('Incomplete F5 PDF integration')
        return src
    anchor_import = 'import type { NormalizedReport, Severity } from "../api/universal";'
    if src.count(anchor_import) != 1:
        raise ValueError('Cannot find unique PDF NormalizedReport import')
    if src.count('  section("Assessment coverage");') != 1:
        raise ValueError('Cannot find unique Assessment coverage PDF anchor')
    src = src.replace(anchor_import, anchor_import + '\n' + PDF_IMPORT, 1)
    src = src.replace('  section("Assessment coverage");', PDF_DETAILS + '  section("Assessment coverage");', 1)
    return src


def plan(root: Path) -> dict[str, bytes]:
    root = root.resolve()
    for required in (MAIN, FRONTEND, PAGE, PDF):
        if not safe_path(root, required).is_file():
            raise ValueError(f'Required Phase 1/backend/frontend file missing: {required}')
    changes = {}
    for rel, func in ((PAGE, insert_page), (PDF, insert_pdf)):
        raw = safe_path(root, rel).read_bytes()
        text, eol, bom = decode_source(raw)
        updated = func(text)
        if updated != text:
            changes[rel] = encode_source(updated, eol, bom)
    dest = safe_path(root, NEW_FILE)
    original = (BUNDLE/'src/api/f5Phase1.ts').read_bytes()
    if dest.exists():
        if not dest.is_file() or dest.read_bytes() != original:
            raise ValueError('Existing customized F5 frontend API adapter; refusing to overwrite')
    else:
        changes[NEW_FILE] = original
    return changes


def install(root: Path, dry_run=False) -> list[str]:
    root = root.resolve()
    changes = plan(root)
    manifest = safe_path(root, MANIFEST)
    if manifest.exists():
        if changes:
            raise ValueError('Previous UI manifest exists but files differ; inspect before retry')
        return []
    if dry_run or not changes:
        return list(changes)
    if any(safe_path(root, rel).with_name(Path(rel).name + BACKUP).exists() for rel in changes):
        raise ValueError('Existing UI backup collision; no files changed')
    originals = {rel: safe_path(root, rel).read_bytes() if safe_path(root, rel).exists() else None for rel in changes}
    done=[]
    try:
        for rel, content in changes.items():
            dst = safe_path(root, rel)
            dst.parent.mkdir(parents=True, exist_ok=True)
            if originals[rel] is not None:
                dst.with_name(dst.name+BACKUP).write_bytes(originals[rel])
            dst.write_bytes(content)
            done.append(rel)
        metadata={'version':1,'files':{rel:{'created': originals[rel] is None,
          'installed_sha256': digest(changes[rel]),
          'original_sha256': digest(originals[rel]) if originals[rel] is not None else None} for rel in changes}}
        tmp=safe_path(root, MANIFEST+'.tmp')
        tmp.write_text(json.dumps(metadata, indent=2), encoding='utf-8')
        tmp.replace(manifest)
    except Exception:
        for rel in reversed(done):
            dst=safe_path(root,rel)
            if originals[rel] is None: dst.unlink(missing_ok=True)
            else:
                dst.write_bytes(originals[rel])
                dst.with_name(dst.name+BACKUP).unlink(missing_ok=True)
        safe_path(root, MANIFEST+'.tmp').unlink(missing_ok=True)
        raise
    return done


def rollback(root: Path) -> list[str]:
    root=root.resolve()
    manifest = safe_path(root, MANIFEST)
    if not manifest.is_file():
        raise ValueError('UI manifest missing')
    meta=json.loads(manifest.read_text(encoding='utf-8'))
    records=meta.get('files')
    if meta.get('version')!=1 or not isinstance(records,dict) or not set(records).issubset({NEW_FILE,PAGE,PDF}):
        raise ValueError('Invalid manifest')
    for rel, record in records.items():
        dst=safe_path(root,rel)
        if not dst.is_file() or digest(dst.read_bytes())!=record['installed_sha256']:
            raise ValueError(f'File modified since installation; refusing rollback: {rel}')
        if not record['created']:
            backup=dst.with_name(dst.name+BACKUP)
            if not backup.is_file() or digest(backup.read_bytes())!=record['original_sha256']:
                raise ValueError(f'Missing/mismatched rollback backup: {rel}')
    for rel, record in records.items():
        dst=safe_path(root,rel)
        if record['created']: dst.unlink()
        else:
            backup=dst.with_name(dst.name+BACKUP)
            dst.write_bytes(backup.read_bytes())
            backup.unlink()
    manifest.unlink()
    return list(records)


def main():
    arg=argparse.ArgumentParser(description='Install F5 Phase 1 in existing React selector, findings and detailed PDF')
    arg.add_argument('root', nargs='?', default='.')
    arg.add_argument('--dry-run', action='store_true')
    arg.add_argument('--rollback', action='store_true')
    args=arg.parse_args()
    try:
        changes=rollback(Path(args.root)) if args.rollback else install(Path(args.root), args.dry_run)
        print('Rolled back:' if args.rollback else 'Would update:' if args.dry_run else 'Installed:')
        print('\n'.join('  '+x for x in changes) if changes else '  No changes needed')
        return 0
    except (ValueError, OSError, UnicodeError, KeyError) as exc:
        print('ERROR:',exc,file=sys.stderr)
        return 1

if __name__=='__main__':
    raise SystemExit(main())
