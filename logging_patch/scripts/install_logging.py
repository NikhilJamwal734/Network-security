"""Conservative install/rollback for API 12 structured file logging."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1]
MANIFEST = '.audit_logging_manifest.json'
BACKUP_DIR = '.audit_logging_backup'
MAIN = Path('app/api/main.py')
HARDENED = Path('app/api/hardened_analysis.py')
MODULE = Path('app/core/audit_logging.py')

MAIN_IMPORT = 'from app.core.audit_logging import AccessAuditMiddleware\n'
MAIN_REGISTER = 'app.add_middleware(AccessAuditMiddleware)\n'
MAIN_OLD_IMPORT = 'from app.api.release_status import router as release_status_router\n'
MAIN_OLD_REGISTER = 'app.include_router(release_status_router)\n'
HARDENED_IMPORT = 'from app.core.audit_logging import audit_event\n'
HARDENED_OLD_IMPORT = ('from app.core.input_hardening import MAX_CONFIG_BYTES, InputProblem, '
                       'check_filename, check_platform, inspect_config_bytes\n')
OLD_BODY = '''    except InputProblem as exc:
        raise HTTPException(status_code=exc.status_code, detail={'code': exc.code, 'message': exc.message}) from None

    from app.api.pipeline_validation import analyze_pipeline_validation
    result = await analyze_pipeline_validation(file=file, platform=platform)
    if not isinstance(result, dict):
        raise HTTPException(status_code=502, detail='Unexpected upstream response shape.')
    return {**result, 'input_security_review': review}
'''
NEW_BODY = '''    except InputProblem as exc:
        audit_event('upload_audit', 'upload_rejected', platform=platform or 'auto',
                    code=exc.code, status_code=exc.status_code)
        raise HTTPException(status_code=exc.status_code, detail={'code': exc.code, 'message': exc.message}) from None

    audit_event('upload_audit', 'upload_accepted', platform=platform or 'auto', size_bytes=len(data))
    audit_event('security_analysis', 'analysis_started', platform=platform or 'auto')
    from app.api.pipeline_validation import analyze_pipeline_validation
    try:
        result = await analyze_pipeline_validation(file=file, platform=platform)
        if not isinstance(result, dict):
            raise HTTPException(status_code=502, detail='Unexpected upstream response shape.')
    except Exception as exc:
        audit_event('security_analysis', 'analysis_failed', platform=platform or 'auto',
                    error_type=type(exc).__name__)
        raise
    findings = result.get('findings')
    count = len(findings) if isinstance(findings, list) else None
    audit_event('security_analysis', 'analysis_completed', platform=platform or 'auto', finding_count=count)
    return {**result, 'input_security_review': review}
'''


def _hash(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _target(root: Path, rel: Path) -> Path:
    dst = root / rel
    if dst.is_symlink() or not dst.resolve().is_relative_to(root):
        raise ValueError(f'Unsafe path: {rel.as_posix()}')
    return dst


def _text_change(raw: bytes, *, kind: str) -> bytes:
    has_bom = raw.startswith(b'\xef\xbb\xbf')
    text = raw.decode('utf-8-sig')
    if '\r' in text.replace('\r\n', '') or ('\r\n' in text and '\n' in text.replace('\r\n', '')):
        raise ValueError('Mixed or unsupported line endings')
    newline = '\r\n' if '\r\n' in text else '\n'
    text = text.replace('\r\n', '\n')
    if kind == 'main':
        if text.count(MAIN_IMPORT) != text.count(MAIN_REGISTER) or text.count(MAIN_IMPORT) > 1:
            raise ValueError('Partial/duplicate logging middleware registration')
        if MAIN_IMPORT not in text:
            if text.count(MAIN_OLD_IMPORT) != 1 or text.count(MAIN_OLD_REGISTER) != 1:
                raise ValueError('API-012.0 release router anchors not found uniquely')
            text = text.replace(MAIN_OLD_IMPORT, MAIN_OLD_IMPORT + MAIN_IMPORT, 1)
            text = text.replace(MAIN_OLD_REGISTER, MAIN_OLD_REGISTER + MAIN_REGISTER, 1)
    elif kind == 'hardened':
        if text.count(HARDENED_IMPORT) > 1:
            raise ValueError('Duplicate logging imports')
        patched = 'audit_event(\'upload_audit\', \'upload_rejected\'' in text
        if patched != (HARDENED_IMPORT in text):
            raise ValueError('Partial logging in hardened upload')
        if not patched:
            if text.count(HARDENED_OLD_IMPORT) != 1 or text.count(OLD_BODY) != 1:
                raise ValueError('Unrecognized hardened analysis layout; no files changed')
            text = text.replace(HARDENED_OLD_IMPORT, HARDENED_OLD_IMPORT + HARDENED_IMPORT, 1)
            text = text.replace(OLD_BODY, NEW_BODY, 1)
    else:
        raise ValueError('Unknown patch target')
    return (b'\xef\xbb\xbf' if has_bom else b'') + text.replace('\n', newline).encode('utf-8')


def plan(root: Path) -> dict[Path, bytes]:
    root = root.resolve()
    if not root.is_dir():
        raise ValueError('Project root does not exist')
    source = PACKAGE / MODULE
    result: dict[Path, bytes] = {}
    for rel, kind in ((MAIN, 'main'), (HARDENED, 'hardened')):
        dst = _target(root, rel)
        if not dst.is_file():
            raise ValueError(f'Required API 12 component missing: {rel.as_posix()}')
        raw = dst.read_bytes()
        target = _text_change(raw, kind=kind)
        if target != raw:
            result[dst] = target
    dst = _target(root, MODULE)
    if dst.exists():
        if not dst.is_file() or dst.read_bytes() != source.read_bytes():
            raise ValueError('Refusing to overwrite customized audit_logging.py')
    else:
        result[dst] = source.read_bytes()
    return result


def _load_manifest(root: Path) -> dict:
    p = _target(root, Path(MANIFEST))
    if not p.is_file():
        raise ValueError('Logging manifest missing')
    record = json.loads(p.read_text(encoding='utf-8'))
    if record.get('patch') != 'audit-logging-v1' or set(record.get('files', {})) - {MAIN.as_posix(), HARDENED.as_posix(), MODULE.as_posix()}:
        raise ValueError('Invalid logging manifest')
    if not record.get('files'):
        raise ValueError('Empty logging manifest')
    for name, info in record['files'].items():
        dst = _target(root, Path(name))
        if not dst.is_file() or _hash(dst.read_bytes()) != info['installed_sha256']:
            raise ValueError(f'Installed file edited since logging patch: {name}')
    return record


def install(root: Path) -> list[str]:
    root = root.resolve()
    changes = plan(root)
    manifest = _target(root, Path(MANIFEST))
    if manifest.exists():
        _load_manifest(root)
        if changes:
            raise ValueError('Previously installed files changed')
        return []
    if not changes:
        return []
    backups = _target(root, Path(BACKUP_DIR))
    if backups.exists():
        raise ValueError('Backup directory already exists; refusing to overwrite')
    backups.mkdir(parents=True)
    initial: dict[Path, bytes | None] = {}
    records = {}
    try:
        for dest, installed in changes.items():
            old = dest.read_bytes() if dest.exists() else None
            initial[dest] = old
            name = dest.relative_to(root).as_posix()
            records[name] = {'installed_sha256': _hash(installed), 'original_sha256': _hash(old) if old is not None else None}
            if old is not None:
                backup = backups / name
                backup.parent.mkdir(parents=True, exist_ok=True)
                backup.write_bytes(old)
        for dest, installed in changes.items():
            tmp = dest.with_name(dest.name + '.audit_logging.tmp')
            if tmp.exists() or tmp.is_symlink():
                raise ValueError(f'Existing temporary file: {tmp}')
            dest.parent.mkdir(parents=True, exist_ok=True)
            tmp.write_bytes(installed)
            os.replace(tmp, dest)
        manifest.write_text(json.dumps({'patch':'audit-logging-v1','files':records}, indent=2)+'\n',encoding='utf-8')
        return sorted(records)
    except Exception:
        for dest, old in initial.items():
            if old is None:
                dest.unlink(missing_ok=True)
            else:
                dest.write_bytes(old)
            dest.with_name(dest.name + '.audit_logging.tmp').unlink(missing_ok=True)
        import shutil
        shutil.rmtree(backups, ignore_errors=True)
        raise


def rollback(root: Path) -> list[str]:
    root = root.resolve()
    record = _load_manifest(root)
    backups = _target(root, Path(BACKUP_DIR))
    originals = {}
    for name, info in record['files'].items():
        backup = _target(root, Path(BACKUP_DIR) / name)
        if info['original_sha256'] is not None:
            if not backup.is_file() or _hash(backup.read_bytes()) != info['original_sha256']:
                raise ValueError(f'Missing or modified backup: {name}')
            originals[name] = backup.read_bytes()
        else:
            originals[name] = None
    for name, old in originals.items():
        dst = _target(root, Path(name))
        if old is None:
            dst.unlink()
        else:
            dst.write_bytes(old)
    import shutil
    shutil.rmtree(backups)
    (root / MANIFEST).unlink()
    return sorted(originals)


def main():
    parser = argparse.ArgumentParser(description='Install/rollback FirewallAnalyzer logging')
    parser.add_argument('root', nargs='?', default='.')
    parser.add_argument('--rollback', action='store_true')
    args = parser.parse_args()
    try:
        changed = rollback(Path(args.root)) if args.rollback else install(Path(args.root))
    except (OSError, UnicodeError, ValueError, KeyError, json.JSONDecodeError) as exc:
        parser.exit(1, f'ERROR: {exc}\n')
    if changed:
        print(('Rolled back' if args.rollback else 'Installed') + ': ' + ', '.join(changed))
    else:
        print('Already installed; no changes')


if __name__ == '__main__':
    main()
