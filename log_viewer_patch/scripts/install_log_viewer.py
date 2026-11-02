"""Install/remove the API-12 local Logs page without altering detection engine.

Checks all edits and prerequisites before writing. Preserves BOM/newlines, keeps
backups with SHA256, and refuses to overwrite unknown customized files.
"""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import shutil
import sys

ROOT = Path(__file__).resolve().parents[1]
PAYLOAD = ROOT / 'payload'
MANIFEST = '.log_viewer_patch_manifest.json'
BACKUP = '.log_viewer_patch_backup'
MAIN = Path('app/api/main.py')
APP = Path('frontend/src/App.tsx')
ADDED = (
    Path('app/api/log_viewer.py'),
    Path('frontend/src/api/logs.ts'),
    Path('frontend/src/pages/Logs.tsx'),
    Path('frontend/src/pages/Logs.css'),
    Path('tools/Watch-FirewallLogs.ps1'),
)
API_IMPORT = 'from app.api.log_viewer import router as local_audit_logs_router'
API_REGISTER = 'app.include_router(local_audit_logs_router)'
RELEASE_IMPORT = 'from app.api.release_status import router as release_status_router'
RELEASE_REGISTER = 'app.include_router(release_status_router)'
UI_IMPORT = 'const Logs = lazy(() => import("./pages/Logs"));'
UI_NAV = '{ label: "Logs", icon: "◷" }'
UI_VIEW = '{activePage === "Logs" && <Logs />}'


def _hash(blob: bytes) -> str:
    return sha256(blob).hexdigest()


def _safe(root: Path, rel: Path) -> Path:
    target = root / rel
    if any(part in ('.', '..') for part in rel.parts):
        raise ValueError('Unsafe relative path')
    if target.is_symlink() or not target.resolve().is_relative_to(root):
        raise ValueError('Refusing symlink or path outside the project: ' + rel.as_posix())
    return target


def _read_text(blob: bytes) -> tuple[str, bool, str]:
    bom = blob.startswith(b'\xef\xbb\xbf')
    value = blob.decode('utf-8-sig')
    if '\r' in value.replace('\r\n', '') or ('\r\n' in value and '\n' in value.replace('\r\n', '')):
        raise ValueError('Unsupported or mixed line endings; not editing this file')
    newline = '\r\n' if '\r\n' in value else '\n'
    return value.replace('\r\n', '\n'), bom, newline


def _encode(value: str, bom: bool, newline: str) -> bytes:
    return (b'\xef\xbb\xbf' if bom else b'') + value.replace('\n', newline).encode('utf-8')


def _patch_api(blob: bytes) -> bytes:
    value, bom, newline = _read_text(blob)
    if API_IMPORT in value or API_REGISTER in value:
        if value.count(API_IMPORT) == 1 and value.count(API_REGISTER) == 1:
            return blob
        raise ValueError('API main contains partial or duplicate log viewer wiring')
    if value.count(RELEASE_IMPORT) != 1 or value.count(RELEASE_REGISTER) != 1:
        raise ValueError('API-12 release_status anchors missing in app/api/main.py')
    value = value.replace(RELEASE_IMPORT, RELEASE_IMPORT + '\n' + API_IMPORT, 1)
    value = value.replace(RELEASE_REGISTER, RELEASE_REGISTER + '\n' + API_REGISTER, 1)
    return _encode(value, bom, newline)


def _patch_app(blob: bytes) -> bytes:
    value, bom, newline = _read_text(blob)
    if any(x in value for x in (UI_IMPORT, UI_NAV, UI_VIEW)):
        if all(x in value for x in (UI_IMPORT, UI_NAV, UI_VIEW)):
            return blob
        raise ValueError('Frontend App.tsx has partial Logs page wiring; inspect manually')
    # Baseline and API0097+ use lazy page imports and a Dashboard navigation item.
    import_anchor = 'const Dashboard = lazy(() => import("./pages/Dashboard"));'
    if value.count(import_anchor) != 1:
        raise ValueError('Unsupported App.tsx: Dashboard lazy import was not found exactly once')
    value = value.replace(import_anchor, UI_IMPORT + '\n' + import_anchor, 1)
    nav_rx = re.compile(r'\{\s*label:\s*"Dashboard"\s*,\s*icon:\s*"[^"\n]+"\s*\}')
    nav_matches = list(nav_rx.finditer(value))
    if len(nav_matches) != 1:
        raise ValueError('Unsupported App.tsx: Dashboard navigation item must appear exactly once')
    nav = nav_matches[0].group()
    value = value.replace(nav, nav + ', ' + UI_NAV, 1)
    # Many later App.tsx variants use a PageName string union.
    union_match = re.search(r'\btype\s+PageName\s*=([^;]+);', value, re.S)
    if union_match and '"Logs"' not in union_match.group(1):
        old = union_match.group()
        if '"Dashboard"' not in old:
            raise ValueError('App.tsx PageName union does not include Dashboard')
        updated = old.replace('"Dashboard"', '"Dashboard" | "Logs"', 1)
        value = value.replace(old, updated, 1)
    # The Logs page must render independently of whether a report has been loaded.
    standard = re.search(r'(?m)^(?P<indent>[ \t]*)\{activePage === "(?:Universal Analysis|Dashboard)" && \(', value)
    if standard:
        indent = standard.group('indent')
        value = value[:standard.start()] + indent + UI_VIEW + '\n' + value[standard.start():]
    else:
        older = re.search(r'\{report && activePage === "Dashboard" &&', value)
        if not older:
            raise ValueError('Unsupported App.tsx: could not identify where pages are rendered')
        value = value[:older.start()] + UI_VIEW + '\n        ' + value[older.start():]
    return _encode(value, bom, newline)


def _check_dependencies(project: Path) -> None:
    for rel in (MAIN, APP, Path('app/core/audit_logging.py')):
        if not _safe(project, rel).is_file():
            raise ValueError('Required project file missing: ' + rel.as_posix())
    if not (project / 'frontend/src/pages').is_dir():
        raise ValueError('Missing frontend/src/pages')


def _plan(project: Path) -> dict[Path, bytes]:
    _check_dependencies(project)
    result: dict[Path, bytes] = {}
    for rel, patcher in ((MAIN, _patch_api), (APP, _patch_app)):
        target = _safe(project, rel)
        old = target.read_bytes()
        new = patcher(old)
        if new != old:
            result[rel] = new
    for rel in ADDED:
        target = _safe(project, rel)
        source = _safe(PAYLOAD.resolve(), rel)
        data = source.read_bytes()
        if target.exists():
            if not target.is_file() or target.read_bytes() != data:
                raise ValueError('Will not overwrite an existing customized file: ' + rel.as_posix())
        else:
            result[rel] = data
    return result


def _verify_manifest(project: Path) -> dict:
    manifest = _safe(project, Path(MANIFEST))
    if not manifest.is_file():
        raise ValueError('Installer manifest not found')
    record = json.loads(manifest.read_text(encoding='utf-8'))
    if record.get('patch') != 'api12-local-log-viewer-v1' or not isinstance(record.get('files'), dict):
        raise ValueError('Unexpected log viewer manifest')
    allowed = {MAIN.as_posix(), APP.as_posix()} | {p.as_posix() for p in ADDED}
    if not set(record['files']) <= allowed or not record['files']:
        raise ValueError('Invalid recorded target files')
    for rel, meta in record['files'].items():
        target = _safe(project, Path(rel))
        if not target.is_file() or _hash(target.read_bytes()) != meta.get('after'):
            raise ValueError('File changed since installation: ' + rel)
    return record


def install(project: Path) -> list[str]:
    project = project.resolve()
    if not project.is_dir():
        raise ValueError('Project directory does not exist')
    manifest = _safe(project, Path(MANIFEST))
    if manifest.exists():
        _verify_manifest(project)
        return []
    changes = _plan(project)  # No writes before all prerequisites are satisfied.
    if not changes:
        return []
    backup = _safe(project, Path(BACKUP))
    if backup.exists():
        raise ValueError('Unrecognized existing log viewer backup directory')
    original = {rel: (_safe(project, rel).read_bytes() if _safe(project, rel).exists() else None) for rel in changes}
    files = {rel.as_posix(): {'before': _hash(old) if old is not None else None, 'after': _hash(new)}
             for rel, new in changes.items() for old in [original[rel]]}
    written: list[Path] = []
    backup.mkdir()
    try:
        for rel, old in original.items():
            if old is not None:
                path = backup / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(old)
        for rel, new in changes.items():
            target = _safe(project, rel)
            target.parent.mkdir(parents=True, exist_ok=True)
            tmp = target.with_name(target.name + '.local_log_viewer.tmp')
            if tmp.exists() or tmp.is_symlink():
                raise ValueError('Temporary path already exists: ' + rel.as_posix())
            tmp.write_bytes(new)
            os.replace(tmp, target)
            written.append(rel)
        manifest.write_text(json.dumps({'patch': 'api12-local-log-viewer-v1', 'files': files}, indent=2) + '\n', encoding='utf-8')
        return [p.as_posix() for p in changes]
    except Exception:
        for rel in reversed(written):
            target = _safe(project, rel)
            if original[rel] is None:
                target.unlink(missing_ok=True)
            else:
                target.write_bytes(original[rel])
        shutil.rmtree(backup, ignore_errors=True)
        raise


def rollback(project: Path) -> list[str]:
    project = project.resolve()
    record = _verify_manifest(project)
    restores: dict[Path, bytes | None] = {}
    for name, meta in record['files'].items():
        rel = Path(name)
        if meta['before'] is None:
            restores[rel] = None
        else:
            backup = _safe(project, Path(BACKUP) / rel)
            if not backup.is_file():
                raise ValueError('Missing backup for ' + name)
            data = backup.read_bytes()
            if _hash(data) != meta['before']:
                raise ValueError('Backup changed since installation: ' + name)
            restores[rel] = data
    for rel, old in restores.items():
        target = _safe(project, rel)
        if old is None:
            target.unlink()
        else:
            target.write_bytes(old)
    shutil.rmtree(_safe(project, Path(BACKUP)))
    _safe(project, Path(MANIFEST)).unlink()
    return [p.as_posix() for p in restores]


def main() -> int:
    parser = argparse.ArgumentParser(description='Install a read-only local API and colour Logs UI for FirewallAnalyzer')
    parser.add_argument('root', nargs='?', default='.', type=Path)
    parser.add_argument('--rollback', action='store_true')
    args = parser.parse_args()
    try:
        changed = rollback(args.root) if args.rollback else install(args.root)
    except (OSError, ValueError, KeyError, UnicodeError, json.JSONDecodeError) as exc:
        print('ERROR: ' + str(exc), file=sys.stderr)
        return 1
    if changed:
        print(('Rolled back' if args.rollback else 'Installed') + ':')
        for rel in changed:
            print('  ' + rel)
    else:
        print('Already installed. No changes needed.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
