"""Guarded display-label update for the installed F5 BIG-IP React adapter.

Only edits frontend/src/api/f5Phase1.ts. No changes to API IDs, endpoints,
security checks, PDF evidence content, or vendor discovery semantics.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

TARGET = Path('frontend/src/api/f5Phase1.ts')
MANIFEST = Path('.f5_professional_label_manifest.json')
BACKUP = Path('.f5_professional_label_original.bin')

OLD_PLATFORM = 'display_name: "F5 BIG-IP (Phases 1 + 2)"'
NEW_PLATFORM = 'display_name: "F5 BIG-IP LTM & Advanced WAF"'
OLD_REPORT = 'display_name: "F5 BIG-IP LTM / Advanced WAF (Phases 1 + 2)"'
NEW_REPORT = 'display_name: "F5 BIG-IP LTM & Advanced WAF"'
OLD_HELPER = '''export function withF5Platform(items: SupportedPlatform[]): SupportedPlatform[] {
  return items.some((p) => p.platform_id === F5_PLATFORM_ID)
    ? items
    : [...items, F5_PLATFORM];
}'''
NEW_HELPER = '''export function withF5Platform(items: SupportedPlatform[]): SupportedPlatform[] {
  // Keep one professional F5 label even when discovery returns an F5 entry.
  return items.some((p) => p.platform_id === F5_PLATFORM_ID)
    ? items.map((p) => p.platform_id === F5_PLATFORM_ID
        ? { ...p, display_name: F5_PLATFORM.display_name }
        : p)
    : [...items, F5_PLATFORM];
}'''


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def atomic_new(path: Path, data: bytes) -> None:
    """Create path, failing if it already exists."""
    with path.open('xb') as handle:
        handle.write(data)


def safe_target(root: Path) -> Path:
    if any((root / sub).is_symlink() for sub in (Path('frontend'), Path('frontend/src'), Path('frontend/src/api'), TARGET)):
        raise ValueError('A source path is a symlink; refusing an unsafe edit')
    path = root / TARGET
    if not path.is_file():
        raise ValueError(f'Missing expected installed adapter: {TARGET}')
    return path


def patch(original: bytes) -> bytes:
    # Preserve UTF-8 BOM and Windows CRLF/LF byte formatting.
    has_bom = original.startswith(b'\xef\xbb\xbf')
    content = original[3:] if has_bom else original
    try:
        src = content.decode('utf-8')
    except UnicodeError as exc:
        raise ValueError('Adapter must be UTF-8') from exc
    newline = '\r\n' if '\r\n' in src else '\n'
    canonical = src.replace('\r\n', '\n')
    if canonical.count(NEW_PLATFORM) == 2 and canonical.count(NEW_HELPER) == 1:
        return original
    requirements = {
        'selector label': (OLD_PLATFORM, 1),
        'report platform label': (OLD_REPORT, 1),
        'F5 registry helper': (OLD_HELPER, 1),
        'F5 platform ID': ('export const F5_PLATFORM_ID = "f5_bigip";', 1),
    }
    for name, (anchor, count) in requirements.items():
        if canonical.count(anchor) != count:
            raise ValueError(f'Unexpected {name} anchor; refusing to modify customized source')
    canonical = canonical.replace(OLD_PLATFORM, NEW_PLATFORM, 1)
    canonical = canonical.replace(OLD_REPORT, NEW_REPORT, 1)
    canonical = canonical.replace(OLD_HELPER, NEW_HELPER, 1)
    output = canonical.replace('\n', newline).encode('utf-8')
    return (b'\xef\xbb\xbf' if has_bom else b'') + output


def install(root: Path, dry_run: bool = False) -> str:
    target = safe_target(root)
    manifest, backup = root / MANIFEST, root / BACKUP
    before = target.read_bytes()
    after = patch(before)
    if before == after:
        if manifest.exists() and backup.exists():
            details = json.loads(manifest.read_text(encoding='utf-8'))
            if sha(before) != details.get('patched_sha256'):
                raise ValueError('Source no longer matches installed patch; inspect before proceeding')
        return 'ALREADY INSTALLED: F5 BIG-IP LTM & Advanced WAF'
    if manifest.exists() or backup.exists():
        raise ValueError('An existing backup/manifest is present; refusing to overwrite')
    if dry_run:
        return 'DRY RUN PASS: only frontend/src/api/f5Phase1.ts would be updated'
    atomic_new(backup, before)
    try:
        atomic_new(manifest, json.dumps({
            'target': TARGET.as_posix(),
            'original_sha256': sha(before),
            'patched_sha256': sha(after),
            'label': 'F5 BIG-IP LTM & Advanced WAF',
        }, indent=2).encode('utf-8'))
        target.write_bytes(after)
    except BaseException:
        if target.exists():
            target.write_bytes(before)
        manifest.unlink(missing_ok=True)
        backup.unlink(missing_ok=True)
        raise
    return 'INSTALLED: F5 BIG-IP LTM & Advanced WAF (selector and normalized report label)'


def rollback(root: Path) -> str:
    target = safe_target(root)
    manifest, backup = root / MANIFEST, root / BACKUP
    if not manifest.is_file() or not backup.is_file():
        raise ValueError('Manifest or original source backup missing')
    details = json.loads(manifest.read_text(encoding='utf-8'))
    if details.get('target') != TARGET.as_posix():
        raise ValueError('Unexpected manifest target')
    if sha(target.read_bytes()) != details.get('patched_sha256'):
        raise ValueError('Adapter changed after installation; refusing to overwrite user edits')
    original = backup.read_bytes()
    if sha(original) != details.get('original_sha256'):
        raise ValueError('Original backup hash mismatch')
    target.write_bytes(original)
    manifest.unlink()
    backup.unlink()
    return 'ROLLED BACK: original F5 adapter restored'


def main() -> None:
    ap = argparse.ArgumentParser(description='Safely rename F5 platform selection label')
    ap.add_argument('project_root', type=Path, nargs='?', default=Path('.'))
    group = ap.add_mutually_exclusive_group()
    group.add_argument('--dry-run', action='store_true')
    group.add_argument('--rollback', action='store_true')
    args = ap.parse_args()
    try:
        root = args.project_root.resolve(strict=True)
        print(rollback(root) if args.rollback else install(root, args.dry_run))
    except (ValueError, OSError, KeyError, json.JSONDecodeError) as exc:
        ap.exit(1, f'ERROR: {exc}\n')


if __name__ == '__main__':
    main()
