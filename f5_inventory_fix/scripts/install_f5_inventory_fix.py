"""F5 Phase 1 frontend inventory compatibility fix.

Keeps the existing F5 analysis endpoint and current JSON/PDF/report contracts.
Reuses only counts from the validated F5 Phase 1 response; does not call the
older /api/v1/analyze/universal endpoint for F5. All files backed up for rollback.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

PAGE = 'frontend/src/pages/UniversalAnalysis.tsx'
INVENTORY_PAGE = 'frontend/src/pages/PlatformConfigurationPage.tsx'
F5_ADAPTER = 'frontend/src/api/f5Phase1.ts'
MANIFEST = '.f5_inventory_fix_manifest.json'
BACKUP_DIR = '.f5_inventory_fix_backups'

OLD_IMPORT = 'import { F5_PLATFORM_ID, withF5Platform, analyzeF5Phase1 } from "../api/f5Phase1";'
NEW_IMPORT = 'import { F5_PLATFORM_ID, withF5Platform, analyzeF5Phase1, type F5NormalizedReport } from "../api/f5Phase1";'
OLD_BRANCH = '      if (next.platform.platform_id !== "cisco_asa") {'
NEW_BRANCH = '''      if (next.platform.platform_id === F5_PLATFORM_ID) {
        // F5 Phase 1 is not registered with the older universal inventory API.
        // Reuse validated counts from the successful F5 response instead of
        // uploading the same configuration to an unsupported endpoint.
        const review = (next as F5NormalizedReport).f5_phase1_review;
        onConfigurationChange({
          platform_id: F5_PLATFORM_ID,
          configuration: {
            f5_phase1_profile_count: review.total_profiles,
            f5_phase1_virtual_count: review.total_virtual_servers,
            f5_phase1_findings_count: review.findings.length,
            f5_phase1_observations_count: review.review_observations.length,
          },
          warnings: review.limitations,
        });
      } else if (next.platform.platform_id !== "cisco_asa") {'''

OLD_INVENTORY_ANCHOR = '  } else if (section === "Rules" && ids) {'
NEW_INVENTORY_ANCHOR = '''  } else if (platform === "f5_bigip") {
    if (section === "Configuration") {
      view = <>
        <Grid items={[
          ["SSL / HTTP profiles parsed", display(config.f5_phase1_profile_count)],
          ["Virtual servers parsed", display(config.f5_phase1_virtual_count)],
          ["Phase 1 findings", display(config.f5_phase1_findings_count)],
          ["Policy review observations", display(config.f5_phase1_observations_count)],
        ]}/>
        <Info>These are counts from the F5 BIG-IP Phase 1 analysis response, not a complete device inventory. The findings and detailed evidence remain in the Findings pane and PDF. Inherited settings, additional objects and runtime deployment have not been verified.</Info>
      </>;
    } else {
      view = <Empty title="Not assessed by F5 Phase 1">
        This page does not yet provide a complete F5 BIG-IP {section.toLowerCase()} inventory.
        Phase 1 analyzes supported SSL and HTTP profile settings and their explicitly visible virtual-server associations. Absence of inventory data does not indicate that the device has no such objects.
      </Empty>;
    }
  } else if (section === "Rules" && ids) {'''


def _read_bytes(root: Path, relative: str) -> bytes:
    p = _target(root, relative)
    if not p.is_file():
        raise ValueError(f'Required file missing: {relative}')
    return p.read_bytes()


def _target(root: Path, relative: str) -> Path:
    dest = root
    for component in Path(relative).parts:
        dest = dest / component
        if dest.is_symlink():
            raise ValueError(f'Symlink path not permitted: {relative}')
    if not dest.resolve().is_relative_to(root):
        raise ValueError(f'Invalid destination: {relative}')
    return dest


def _decode(raw: bytes) -> tuple[str, str, bool]:
    bom = raw.startswith(b'\xef\xbb\xbf')
    s = raw.decode('utf-8-sig')
    if '\r' in s.replace('\r\n', '') or ('\r\n' in s and '\n' in s.replace('\r\n', '')):
        raise ValueError('Mixed or invalid source line endings')
    ending = '\r\n' if '\r\n' in s else '\n'
    return s.replace('\r\n', '\n'), ending, bom


def _encode(s: str, ending: str, bom: bool) -> bytes:
    return (b'\xef\xbb\xbf' if bom else b'') + s.replace('\n', ending).encode('utf-8')


def patch_universal(src: str) -> str:
    if NEW_IMPORT in src and NEW_BRANCH in src:
        if src.count(NEW_IMPORT) != 1 or src.count(NEW_BRANCH) != 1:
            raise ValueError('Duplicate F5 inventory integration')
        return src
    if src.count(OLD_IMPORT) != 1:
        raise ValueError('F5 Phase 1 import not found once; keep this custom UI unchanged')
    if src.count(OLD_BRANCH) != 1 or 'getPlatformDetails(file, next.platform.platform_id, controller.signal)' not in src:
        raise ValueError('Expected universal inventory request not found exactly once')
    if 'onConfigurationChange' not in src:
        raise ValueError('Missing existing configuration inventory callback')
    return src.replace(OLD_IMPORT, NEW_IMPORT, 1).replace(OLD_BRANCH, NEW_BRANCH, 1)


def patch_inventory(src: str) -> str:
    if 'platform === "f5_bigip"' in src and 'f5_phase1_profile_count' in src:
        if src.count('f5_phase1_profile_count') != 1:
            raise ValueError('Unexpected duplicated F5 inventory block')
        return src
    if src.count(OLD_INVENTORY_ANCHOR) != 1 or 'const platform = report.platform.platform_id;' not in src:
        raise ValueError('Expected configuration inventory page structure not found; preserving file')
    return src.replace(OLD_INVENTORY_ANCHOR, NEW_INVENTORY_ANCHOR, 1)


def _plan(root: Path) -> dict[str, bytes]:
    _read_bytes(root, F5_ADAPTER)
    changes: dict[str, bytes] = {}
    for rel, fn in ((PAGE, patch_universal), (INVENTORY_PAGE, patch_inventory)):
        raw = _read_bytes(root, rel)
        source, eol, bom = _decode(raw)
        target = fn(source)
        if target != source:
            changes[rel] = _encode(target, eol, bom)
    return changes


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def install(root: Path, dry_run: bool = False) -> list[str]:
    root = root.resolve()
    manifest = _target(root, MANIFEST)
    changes = _plan(root)
    if manifest.exists():
        if changes:
            raise ValueError('Manifest exists but installed UI differs; inspect custom edits before retrying')
        return []
    if dry_run or not changes:
        return list(changes)
    if set(changes) != {PAGE, INVENTORY_PAGE}:
        raise ValueError('Partial/previous integration detected: no changes made')
    backup = _target(root, BACKUP_DIR)
    if backup.exists():
        raise ValueError('Backup directory already exists; no files changed')
    originals = {rel: _read_bytes(root, rel) for rel in changes}
    written: list[str] = []
    try:
        backup.mkdir()
        for i, (rel, raw) in enumerate(originals.items()):
            (backup / f'{i}.bak').write_bytes(raw)
        meta = {'version': 1, 'files': [
            {'relative': rel, 'backup': f'{i}.bak', 'original_sha256': _sha(originals[rel]), 'installed_sha256': _sha(changes[rel])}
            for i, rel in enumerate(changes)
        ]}
        for rel, new in changes.items():
            _target(root, rel).write_bytes(new)
            written.append(rel)
        manifest.write_text(json.dumps(meta, indent=2), encoding='utf-8')
    except Exception:
        for rel in written:
            _target(root, rel).write_bytes(originals[rel])
        if backup.exists():
            for b in backup.iterdir():
                b.unlink()
            backup.rmdir()
        if manifest.exists():
            manifest.unlink()
        raise
    return written


def rollback(root: Path) -> list[str]:
    root = root.resolve()
    manifest = _target(root, MANIFEST)
    if not manifest.is_file():
        raise ValueError('No installation manifest found; refusing to guess original files')
    meta = json.loads(manifest.read_text(encoding='utf-8'))
    if meta.get('version') != 1 or len(meta.get('files', [])) != 2:
        raise ValueError('Unexpected manifest format')
    backup = _target(root, BACKUP_DIR)
    restored: dict[str, bytes] = {}
    for item in meta['files']:
        rel = item['relative']
        current = _read_bytes(root, rel)
        raw = (backup / item['backup']).read_bytes()
        if _sha(current) != item['installed_sha256'] or _sha(raw) != item['original_sha256']:
            raise ValueError(f'File changed after installation or backup altered: {rel}; refusing rollback')
        restored[rel] = raw
    for rel, raw in restored.items():
        _target(root, rel).write_bytes(raw)
    manifest.unlink()
    for item in meta['files']:
        (backup / item['backup']).unlink()
    backup.rmdir()
    return list(restored)


def main() -> int:
    ap = argparse.ArgumentParser(description='Skip unsupported F5 universal inventory call and show supported F5 summary')
    ap.add_argument('root', nargs='?', default='.')
    ap.add_argument('--dry-run', action='store_true')
    ap.add_argument('--rollback', action='store_true')
    args = ap.parse_args()
    try:
        changed = rollback(Path(args.root)) if args.rollback else install(Path(args.root), args.dry_run)
        print('Rolled back:' if args.rollback else 'Would update:' if args.dry_run else 'Installed:')
        for rel in changed:
            print('  ' + rel)
        if not changed:
            print('  No changes needed')
        return 0
    except (OSError, ValueError, UnicodeError, KeyError) as exc:
        print(f'ERROR: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
