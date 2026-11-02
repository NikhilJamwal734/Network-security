"""Restore API-010.9 modified tracked files from the first-install backups."""
from pathlib import Path
import shutil
import sys

BACKUP = '.before_api0109.bak'
ROOT_RELS = ('app/api/main.py', 'app/api/ids_configuration.py',
             'app/core/ids_configuration.py', 'tests/test_api_010_9_ids_configuration.py')
FRONT_RELS = ('src/api/universal.ts', 'src/pages/UniversalAnalysis.tsx',
              'src/utils/normalizedPdf.ts', 'src/components/IdsDeepSnippet.tsx',
              'src/components/IdsDeepSnippet.css')


def rollback(root: Path) -> list[str]:
    root = root.resolve()
    restored = []
    for subroot, rels in ((root, ROOT_RELS), (root / 'frontend', FRONT_RELS)):
        for rel in rels:
            file = subroot / rel
            backup = file.with_name(file.name + BACKUP)
            if backup.is_file():
                shutil.copy2(backup, file)
                restored.append(str(file.relative_to(root)))
    return restored


if __name__ == '__main__':
    root = Path(sys.argv[1]) if len(sys.argv) == 2 else Path.cwd()
    changes = rollback(root)
    print('Restored files:', changes if changes else 'No backups found; no files changed.')
    print('New API-010.9 files without backups remain on disk but can be safely unused after restoring main.py.')
