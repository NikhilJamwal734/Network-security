"""Restore the previous API and UI integration files only."""
from __future__ import annotations
from pathlib import Path
import shutil
import sys

ROOT = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path.cwd()
RELS = ('app/api/main.py', 'frontend/src/api/universal.ts',
        'frontend/src/pages/UniversalAnalysis.tsx', 'frontend/src/utils/normalizedPdf.ts')
for rel in RELS:
    target = ROOT / rel
    backup = target.with_name(target.name + '.before_api0108.bak')
    if backup.is_file():
        shutil.copy2(backup, target)
        print('Restored:', rel)
    else:
        print('No backup for:', rel)
print('New API-010.8 modules remain on disk; they are not imported after rollback.')
