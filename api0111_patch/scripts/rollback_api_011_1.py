"""Restore 11.1 backups, removing 11.1-only additions; keep 11.0 untouched."""
from __future__ import annotations
from pathlib import Path
import shutil
import sys

MODIFIED = ('app/api/main.py', 'frontend/src/api/universal.ts',
            'frontend/src/pages/UniversalAnalysis.tsx', 'frontend/src/utils/normalizedPdf.ts')
ADDED = ('app/api/correlation_accuracy.py', 'app/core/correlation_accuracy.py',
         'tests/test_api_011_1_correlation_accuracy.py',
         'frontend/src/components/CorrelationAccuracySnippet.tsx',
         'frontend/src/components/CorrelationAccuracySnippet.css')


def rollback(root: Path) -> list[str]:
    root = root.resolve()
    backups: dict[Path, Path] = {}
    for rel in MODIFIED:
        dst = root / rel
        backup = dst.with_name(dst.name + '.before_api0111.bak')
        if not backup.is_file():
            raise ValueError(f'11.1 backup missing: {backup}. No files were changed.')
        backups[dst] = backup
    changed = []
    for dst, backup in backups.items():
        shutil.copy2(backup, dst)
        backup.unlink()
        changed.append(str(dst.relative_to(root)))
    for rel in ADDED:
        dst = root / rel
        backup = dst.with_name(dst.name + '.before_api0111.bak')
        if backup.is_file():
            shutil.copy2(backup, dst)
            backup.unlink()
            changed.append(rel)
        elif dst.is_file():
            dst.unlink()
            changed.append(rel)
    return changed


if __name__ == '__main__':
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path.cwd()
    try:
        restored = rollback(target)
    except (OSError, ValueError) as error:
        sys.exit(f'ERROR: {error}')
    print('API-011.1 rolled back:')
    for name in restored:
        print('  ' + name)
