"""Restore 11.1 state from 11.2 backups; refuse incomplete rollback."""
from __future__ import annotations
from pathlib import Path
import shutil
import sys

MODIFIED = ('app/api/main.py', 'frontend/src/api/universal.ts',
            'frontend/src/pages/UniversalAnalysis.tsx',
            'frontend/src/utils/normalizedPdf.ts')
ADDED = ('app/api/report_validation.py', 'app/core/report_validation.py',
         'tests/test_api_011_2_report_validation.py',
         'frontend/src/components/ReportValidationSnippet.tsx',
         'frontend/src/components/ReportValidationSnippet.css')


def rollback(root: Path) -> list[str]:
    root = root.resolve()
    sources: dict[Path, Path] = {}
    for rel in MODIFIED:
        dst = root/rel
        bak = dst.with_name(dst.name+'.before_api0112.bak')
        if not bak.is_file():
            raise ValueError(f'Cannot safely roll back: backup missing for {rel}')
        sources[dst] = bak
    changed: list[str] = []
    for dst, bak in sources.items():
        shutil.copy2(bak, dst)
        bak.unlink()
        changed.append(str(dst.relative_to(root)))
    for rel in ADDED:
        dst = root/rel
        bak = dst.with_name(dst.name+'.before_api0112.bak')
        if bak.is_file():
            shutil.copy2(bak, dst)
            bak.unlink()
            changed.append(rel)
        elif dst.is_file():
            dst.unlink()
            changed.append(rel)
    return changed


if __name__ == '__main__':
    if len(sys.argv) > 2: sys.exit('Usage: rollback_api_011_2.py [project-root]')
    root = Path(sys.argv[1]) if len(sys.argv) == 2 else Path.cwd()
    try: changed = rollback(root)
    except (OSError, ValueError) as exc: sys.exit(f'ERROR: {exc}')
    print('API-011.2 rolled back:')
    for rel in changed: print('  ' + rel)
