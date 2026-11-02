"""Restore only the dashboard components backed up by this UI-only patch."""
from pathlib import Path
import sys
from install_dashboard_findings_cleanup import MODERN, LEGACY, BACKUP_SUFFIX


def rollback(root: Path) -> list[str]:
    root = root.resolve()
    restored = []
    for rel in (MODERN, LEGACY):
        file = root / rel
        backup = file.with_name(file.name + BACKUP_SUFFIX)
        if backup.exists():
            file.write_bytes(backup.read_bytes())
            restored.append(str(rel))
    return restored


if __name__ == '__main__':
    if len(sys.argv) > 2:
        sys.exit('Usage: rollback_dashboard_findings_cleanup.py [frontend-directory]')
    root = Path(sys.argv[1]) if len(sys.argv) == 2 else Path.cwd()/'frontend'
    restored = rollback(root)
    print('Restored: ' + ', '.join(restored) if restored else 'No dashboard backups found.')
