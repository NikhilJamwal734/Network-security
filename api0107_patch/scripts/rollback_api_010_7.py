"""Restore files backed up by API-010.7. Leaves unused new modules in place."""
from __future__ import annotations
from pathlib import Path
import shutil
import sys

PREVIOUS = '.before_api0107.bak'
BACKEND = ('app/api/main.py',)
FRONTEND = ('src/api/universal.ts', 'src/pages/UniversalAnalysis.tsx',
            'src/utils/normalizedPdf.ts')


def rollback(root: Path) -> list[str]:
    root = root.resolve()
    desired = [root / p for p in BACKEND] + [root / 'frontend' / p for p in FRONTEND]
    backups = {dest: dest.with_name(dest.name + PREVIOUS) for dest in desired}
    # Do not partially restore on an unfamiliar layout.
    if any(dest.exists() and not src.exists() for dest, src in backups.items()):
        absent = [str(src) for dest, src in backups.items() if dest.exists() and not src.exists()]
        raise ValueError('Required backup(s) missing; rollback aborted: ' + ', '.join(absent))
    restored = []
    for dest, src in backups.items():
        if src.is_file():
            shutil.copy2(src, dest)
            restored.append(str(dest.relative_to(root)))
    return restored


if __name__ == '__main__':
    if len(sys.argv) > 2:
        sys.exit('Usage: rollback_api_010_7.py [project-root]')
    root = Path(sys.argv[1]) if len(sys.argv) == 2 else Path.cwd()
    try:
        changes = rollback(root)
    except (OSError, ValueError) as error:
        sys.exit(f'ERROR: {error}')
    print('Restored API-010.7 modified sources:')
    for p in changes:
        print('  ' + p)
    print('Restart FastAPI, then cd frontend && npm run build.')
