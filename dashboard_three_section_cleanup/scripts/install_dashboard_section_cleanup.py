"""Hide three dashboard-only review sections without altering APIs or PDF reports.

Targets:
- PDF export readiness (API-011.3)
- End-to-end pipeline checks (API-011.4)
- Configuration review evidence *subsection* (keeps Configuration review metrics)

Supports Windows BOM/CRLF, dry run, idempotence and checksum-guarded rollback.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import tempfile
from pathlib import Path

MANIFEST_NAME = '.dashboard_three_section_cleanup_manifest.json'
PAGE = 'src/pages/UniversalAnalysis.tsx'
REVIEW = 'src/components/AdvancedAssessmentPanel.tsx'
PANELS = (
    ('PdfExportReadinessSnippet', 'pdf_export_review'),
    ('PipelineValidationSnippet', 'pipeline_validation_review'),
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def atomic_write(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode='wb', dir=path.parent, prefix=f'.{path.name}.', suffix='.tmp', delete=False) as fh:
        tmp = Path(fh.name)
        try:
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
        except BaseException:
            tmp.unlink(missing_ok=True)
            raise
    try:
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


def decode(raw: bytes, path: Path) -> tuple[str, bool, str]:
    bom = raw.startswith(b'\xef\xbb\xbf')
    try:
        s = raw.decode('utf-8-sig')
    except UnicodeDecodeError as exc:
        raise ValueError(f'{path}: invalid UTF-8; refusing to modify') from exc
    if '\r' in s.replace('\r\n', ''):
        raise ValueError(f'{path}: unsupported line endings; refusing to modify')
    newline = '\r\n' if '\r\n' in s else '\n'
    return s.replace('\r\n', '\n'), bom, newline


def encode(s: str, bom: bool, newline: str) -> bytes:
    return (b'\xef\xbb\xbf' if bom else b'') + s.replace('\n', newline).encode('utf-8')


def remove_snippets(page: str) -> tuple[str, list[str]]:
    result = page
    removed = []
    for name, property_name in PANELS:
        # Anchors match known API-011.3/011.4 source; unknown variants fail closed.
        call = re.compile(r'(?m)^[ \t]*<' + name + r'\s+review=\{report\.' + property_name + r'\}\s*/>[ \t]*(?:\n|$)')
        imp = re.compile(r'(?m)^[ \t]*import\s+' + name + r'\s+from\s+["\']\.\./components/' + name + r'["\'];?[ \t]*(?:\n|$)')
        calls = list(call.finditer(result))
        imports = list(imp.finditer(result))
        if len(calls) > 1 or len(imports) > 1:
            raise ValueError(f'{name}: duplicate JSX/import; no changes made')
        if not calls and not imports:
            if name in result:
                raise ValueError(f'{name}: found unfamiliar source usage; no changes made')
            continue
        if len(calls) != 1 or len(imports) != 1:
            raise ValueError(f'{name}: missing expected JSX or import; no changes made')
        result = call.sub('', result, count=1)
        result = imp.sub('', result, count=1)
        if name in result:
            raise ValueError(f'{name}: additional references remain; no changes made')
        removed.append(name)
    return result, removed


def find_div_end(text: str, start: int) -> int:
    """Find the matching closing div; no generic JSX subtree rewriting."""
    opener = re.compile(r'<\s*/?\s*div\b[^>]*>', re.IGNORECASE)
    depth = 0
    for match in opener.finditer(text, start):
        token = match.group(0)
        if token.startswith('</'):
            depth -= 1
            if depth == 0:
                return match.end()
            if depth < 0:
                break
        elif not token.endswith('/>'):
            depth += 1
    raise ValueError('Configuration review evidence: unbalanced JSX div structure')


def remove_evidence(panel: str) -> tuple[str, bool]:
    marker = re.compile(r'<div\s+data-dashboard-snippet=["\']configuration-evidence["\']\s*>')
    matches = list(marker.finditer(panel))
    if len(matches) > 1:
        raise ValueError('Configuration review evidence: duplicate panel markers')
    result = panel
    if len(matches) == 1:
        start = matches[0].start()
        end = find_div_end(result, start)
        if 'Configuration review evidence' not in result[start:end]:
            raise ValueError('Configuration evidence marker has unexpected content')
        # Don't remove nearby content, metrics, or the parent section.
        line_start = result.rfind('\n', 0, start) + 1
        prefix = result[line_start:start]
        if prefix.strip():
            raise ValueError('Configuration evidence marker is not at a dedicated line')
        end += 1 if end < len(result) and result[end] == '\n' else 0
        result = result[:line_start] + result[end:]
    elif '<h3>Visible configuration evidence</h3>' in panel:
        # Legacy verbose UI: remove evidence details only, leave "Not assessed".
        head = '      <h3>Visible configuration evidence</h3>'
        if result.count(head) != 1 or result.count('      <h3>Not assessed</h3>') != 1:
            raise ValueError('Unsupported legacy configuration evidence layout')
        start = result.index(head)
        end = result.index('      <h3>Not assessed</h3>', start)
        result = result[:start] + result[end:]
    else:
        if 'Configuration review evidence' in panel:
            raise ValueError('Configuration review evidence has an unknown JSX structure')
        return result, False

    # Remove the now-unused destructured observations field if appropriate.
    destructure = re.compile(r'(const\s*\{\s*review_score\s*:\s*score\s*,\s*)observations\s*,\s*(coverage_review\s*:\s*coverage\s*\}\s*=\s*assessment\s*;)')
    if 'observations' not in result.replace('const { review_score: score, observations, coverage_review: coverage } = assessment;', ''):
        result, count = destructure.subn(r'\1\2', result, count=1)
        if count != 1 and re.search(r'\bobservations\b', result):
            raise ValueError('Unexpected observations binding; refusing to introduce unused variable')
    return result, True


def plan(frontend: Path) -> tuple[dict[Path, bytes], list[str]]:
    frontend = frontend.resolve()
    if not (frontend / 'package.json').is_file():
        raise ValueError(f'Not a React frontend directory: {frontend}')
    files = [(PAGE, remove_snippets), (REVIEW, remove_evidence)]
    changes: dict[Path, bytes] = {}
    notes: list[str] = []
    for relative, transform in files:
        path = frontend / relative
        if not path.is_file():
            raise ValueError(f'Missing expected dashboard source: {path}')
        original = path.read_bytes()
        text, bom, newline = decode(original, path)
        updated, detail = transform(text)
        if updated != text:
            changes[path] = encode(updated, bom, newline)
            notes.append(f'{relative}: {detail}')
        else:
            notes.append(f'{relative}: already has no targeted sections')
    return changes, notes


def install(frontend: Path, dry_run: bool = False) -> list[str]:
    frontend = frontend.resolve()
    changes, notes = plan(frontend)
    manifest_path = frontend / MANIFEST_NAME
    if dry_run:
        return ['[preview] ' + line for line in notes]
    if manifest_path.exists():
        try:
            manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
        except (ValueError, UnicodeDecodeError) as exc:
            raise ValueError('Existing cleanup manifest is invalid; refusing to overwrite') from exc
        if manifest.get('version') != 1:
            raise ValueError('Unknown cleanup manifest version')
        if changes:
            raise ValueError('Cleanup partially reverted or edited after installation; review before reapplying')
        return ['Already installed; no changes made.']
    if not changes:
        return ['No targeted dashboard sections remain; no changes needed.']

    records = []
    for path, updated in changes.items():
        before = path.read_bytes()
        records.append({
            'path': path.relative_to(frontend).as_posix(),
            'before_b64': base64.b64encode(before).decode('ascii'),
            'before_sha256': sha256(before),
            'after_sha256': sha256(updated),
        })
    if sum(len(item['before_b64']) for item in records) > 3_000_000:
        raise ValueError('Backup too large for safe manifest')
    written = []
    try:
        for path, updated in changes.items():
            atomic_write(path, updated)
            written.append(path)
        content = json.dumps({'version': 1, 'files': records}, indent=2).encode('utf-8')
        atomic_write(manifest_path, content)
    except BaseException:
        for path in reversed(written):
            record = next(x for x in records if x['path'] == path.relative_to(frontend).as_posix())
            atomic_write(path, base64.b64decode(record['before_b64']))
        raise
    return ['Updated: ' + path.relative_to(frontend).as_posix() for path in changes]


def rollback(frontend: Path) -> list[str]:
    frontend = frontend.resolve()
    manifest_path = frontend / MANIFEST_NAME
    if not manifest_path.is_file():
        raise ValueError('No cleanup manifest found; nothing rolled back')
    data = json.loads(manifest_path.read_text(encoding='utf-8'))
    if data.get('version') != 1 or not isinstance(data.get('files'), list):
        raise ValueError('Invalid cleanup manifest')
    restores = []
    for record in data['files']:
        path = frontend / record['path']
        if path.resolve().parent != (frontend / Path(record['path']).parent).resolve() or not path.resolve().is_relative_to(frontend):
            raise ValueError('Unsafe manifest path')
        current = path.read_bytes()
        if sha256(current) != record['after_sha256']:
            raise ValueError(f'{path}: modified after cleanup; refusing to overwrite later edits')
        before = base64.b64decode(record['before_b64'], validate=True)
        if sha256(before) != record['before_sha256']:
            raise ValueError('Corrupted rollback backup')
        restores.append((path, before))
    for path, before in restores:
        atomic_write(path, before)
    manifest_path.unlink()
    return ['Restored: ' + path.relative_to(frontend).as_posix() for path, _ in restores]


def main() -> None:
    parser = argparse.ArgumentParser(description='Remove three Dashboard cards; preserve backend/PDF')
    parser.add_argument('frontend', nargs='?', type=Path, default=Path('frontend'))
    parser.add_argument('--dry-run', action='store_true')
    parser.add_argument('--rollback', action='store_true')
    args = parser.parse_args()
    if args.dry_run and args.rollback:
        parser.error('--dry-run and --rollback are mutually exclusive')
    try:
        messages = rollback(args.frontend) if args.rollback else install(args.frontend, args.dry_run)
    except (OSError, ValueError, UnicodeError) as exc:
        parser.exit(1, f'ERROR: {exc}\n')
    for message in messages:
        print(message)


if __name__ == '__main__':
    main()
