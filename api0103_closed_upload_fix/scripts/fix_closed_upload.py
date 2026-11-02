"""Surgical fix for API-010.3 POST /rule-correlation closed-upload 500.

Usage (from the project root):
    python api0103_closed_upload_fix/scripts/fix_closed_upload.py "."
"""
from pathlib import Path
import shutil
import sys

OLD = '''    # Preserve the existing upload validation: this is the canonical parser
    # and the single source of truth for findings and scoring.
    old_report = await _run_precision(file=file, platform=platform)
    await file.seek(0)
    data = await file.read(_MAX_CORRELATION_BYTES + 1)
    capped = len(data) > _MAX_CORRELATION_BYTES
'''
NEW = '''    # Capture a bounded sample BEFORE the legacy analysis closes UploadFile.
    # The existing universal route calls await file.close() in its finally block.
    # Rewind so the canonical upload validator still receives the full file.
    await file.seek(0)
    data = await file.read(_MAX_CORRELATION_BYTES + 1)
    await file.seek(0)
    # Preserve existing upload validation, findings and scoring as the source of truth.
    old_report = await _run_precision(file=file, platform=platform)
    capped = len(data) > _MAX_CORRELATION_BYTES
'''

def patch_source(text: str) -> str:
    if text.count(NEW) == 1:
        return text
    if text.count(OLD) != 1:
        raise ValueError('Unexpected rule_correlation.py layout; no changes applied. Please share the file for review.')
    return text.replace(OLD, NEW, 1)

def install(root: Path) -> str:
    root = root.resolve()
    target = root / 'app' / 'api' / 'rule_correlation.py'
    if not target.is_file():
        raise FileNotFoundError(f'API-010.3 endpoint not found: {target}')
    original = target.read_text(encoding='utf-8-sig')
    updated = patch_source(original)
    if updated == original:
        return f'Already fixed: {target}'
    backup = target.with_name(target.name + '.before_closed_upload_fix.bak')
    if not backup.exists():
        shutil.copy2(target, backup)
    target.write_text(updated, encoding='utf-8')
    return f'Fixed: {target}\nBackup: {backup}'

if __name__ == '__main__':
    try:
        root = Path(sys.argv[1]) if len(sys.argv) == 2 else Path.cwd()
        print(install(root))
    except (OSError, ValueError) as exc:
        sys.exit(f'ERROR: {exc}')
