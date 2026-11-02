"""Upgrade API-012.0 structured logging to include safe uploaded basenames.

Requires the existing logging_patch installation. Makes a reversible, narrowly
scoped text edit to two Python files. No backend behavior is changed besides
additional audit fields. Existing manifest/backup are left intact.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil

MANIFEST = '.audit_filename_manifest.json'
BACKUPS = '.audit_filename_backup'
AUDIT = Path('app/core/audit_logging.py')
HARDENED = Path('app/api/hardened_analysis.py')

SAFE_FN_FUNC = '''def _safe_upload_filename(name: object) -> str | None:
    """A bounded, basename-only label; never a path or arbitrary control text.

    A filename may itself contain private information. This feature is
    intentionally enabled by administrators who need filename auditability.
    """
    if not isinstance(name, str) or not (1 <= len(name) <= 120):
        return None
    if name in ('.', '..') or name != name.strip():
        return None
    if not name.isascii() or not all(
        ch.isalnum() or ch in '._- ' for ch in name
    ):
        return None
    return name


'''
FIELD_INSERTION = '''    filename = _safe_upload_filename(fields.get('filename'))
    if filename is not None:
        safe['filename'] = filename
'''
CALLS = (
    "audit_event('upload_audit', 'upload_rejected', platform=",
    "audit_event('upload_audit', 'upload_accepted', platform=",
    "audit_event('security_analysis', 'analysis_started', platform=",
    "audit_event('security_analysis', 'analysis_failed', platform=",
    "audit_event('security_analysis', 'analysis_completed', platform=",
)


def _hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe_path(root: Path, rel: Path) -> Path:
    dest = root / rel
    if dest.is_symlink() or not dest.resolve().is_relative_to(root):
        raise ValueError('Unsafe target path: ' + rel.as_posix())
    return dest


def _transform(data: bytes, kind: str) -> bytes:
    bom = data.startswith(b'\xef\xbb\xbf')
    text = data.decode('utf-8-sig')
    if '\r' in text.replace('\r\n', '') or ('\r\n' in text and '\n' in text.replace('\r\n', '')):
        raise ValueError('Mixed or unsupported line endings')
    ending = '\r\n' if '\r\n' in text else '\n'
    text = text.replace('\r\n', '\n')
    if kind == 'audit':
        anchor = 'def _clean_fields(fields: dict) -> dict:\n'
        if text.count(anchor) != 1 or text.count('    return safe\n') != 1:
            raise ValueError('Unrecognized audit_logging.py version')
        if '_safe_upload_filename' in text or "safe['filename']" in text:
            raise ValueError('Filename logging already modified; cannot safely apply')
        text = text.replace(anchor, SAFE_FN_FUNC + anchor, 1)
        text = text.replace('    return safe\n', FIELD_INSERTION + '    return safe\n', 1)
    elif kind == 'hardened':
        if text.count('from app.core.audit_logging import audit_event\n') != 1:
            raise ValueError('Existing logging patch not installed in hardened endpoint')
        for call in CALLS:
            if text.count(call) != 1:
                raise ValueError('Unrecognized hardened logging call: ' + call)
            text = text.replace(call, call.replace(', platform=', ', filename=file.filename, platform='), 1)
    else:
        raise ValueError('Unknown patch target')
    return (b'\xef\xbb\xbf' if bom else b'') + text.replace('\n', ending).encode('utf-8')


def _load_manifest(root: Path, *, validate_installed: bool = True) -> dict:
    path = _safe_path(root, Path(MANIFEST))
    if not path.is_file():
        raise ValueError('Filename logging manifest not found')
    m = json.loads(path.read_text(encoding='utf-8'))
    if m.get('patch') != 'safe-filename-audit-v1' or set(m.get('files', {})) != {AUDIT.as_posix(), HARDENED.as_posix()}:
        raise ValueError('Invalid filename logging manifest')
    if validate_installed:
        for name, hashes in m['files'].items():
            target = _safe_path(root, Path(name))
            if not target.is_file() or _hash(target.read_bytes()) != hashes['installed_sha256']:
                raise ValueError('File changed since filename patch installation: ' + name)
    return m


def install(root: Path) -> list[str]:
    root = root.resolve()
    if not root.is_dir():
        raise ValueError('Project directory does not exist')
    manifest = _safe_path(root, Path(MANIFEST))
    if manifest.exists():
        _load_manifest(root)
        return []
    backups = _safe_path(root, Path(BACKUPS))
    if backups.exists():
        raise ValueError('Filename patch backup already exists')
    edits = {}
    for rel, kind in ((AUDIT, 'audit'), (HARDENED, 'hardened')):
        path = _safe_path(root, rel)
        if not path.is_file():
            raise ValueError('Missing logging component: ' + rel.as_posix())
        original = path.read_bytes()
        edits[path] = (original, _transform(original, kind))
    backups.mkdir(parents=True)
    changed = []
    try:
        records = {}
        for path, (before, after) in edits.items():
            rel = path.relative_to(root)
            backup = backups / rel
            backup.parent.mkdir(parents=True, exist_ok=True)
            backup.write_bytes(before)
            records[rel.as_posix()] = {'original_sha256':_hash(before),'installed_sha256':_hash(after)}
        for path, (before, after) in edits.items():
            temporary = path.with_name(path.name + '.filename_logging.tmp')
            if temporary.exists() or temporary.is_symlink():
                raise ValueError('Existing temporary file: ' + str(temporary))
            temporary.write_bytes(after)
            os.replace(temporary, path)
            changed.append(path)
        manifest.write_text(json.dumps({'patch':'safe-filename-audit-v1','files':records},indent=2)+'\n',encoding='utf-8')
        return sorted(records)
    except Exception:
        for p in changed:
            p.write_bytes(edits[p][0])
        for p in edits:
            p.with_name(p.name + '.filename_logging.tmp').unlink(missing_ok=True)
        shutil.rmtree(backups, ignore_errors=True)
        raise


def rollback(root: Path) -> list[str]:
    root = root.resolve()
    record = _load_manifest(root)
    backups = _safe_path(root, Path(BACKUPS))
    restores = {}
    for name, hashes in record['files'].items():
        target = _safe_path(root, Path(name))
        original_path = _safe_path(root, Path(BACKUPS) / name)
        if not original_path.is_file():
            raise ValueError('Missing backup: ' + name)
        original = original_path.read_bytes()
        if _hash(original) != hashes['original_sha256']:
            raise ValueError('Backup modified: ' + name)
        restores[target] = original
    for target, original in restores.items():
        target.write_bytes(original)
    shutil.rmtree(backups)
    (root / MANIFEST).unlink()
    return sorted(record['files'])


def main():
    parser = argparse.ArgumentParser(description='Add safe basename auditing to FirewallAnalyzer logging')
    parser.add_argument('root', nargs='?', default='.')
    parser.add_argument('--rollback', action='store_true')
    a = parser.parse_args()
    try:
        result = rollback(Path(a.root)) if a.rollback else install(Path(a.root))
    except (ValueError, OSError, UnicodeError, KeyError, json.JSONDecodeError) as exc:
        parser.exit(1, f'ERROR: {exc}\n')
    print('Updated: ' + ', '.join(result) if result else 'Already installed; no changes')


if __name__ == '__main__':
    main()
