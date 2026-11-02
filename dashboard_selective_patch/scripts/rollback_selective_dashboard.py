r"""Undo only the files changed by the selective Dashboard installer.

  .\.venv-win\Scripts\python.exe dashboard_selective_patch\scripts\rollback_selective_dashboard.py ".\frontend"
"""
from pathlib import Path
import sys

SUFFIX = '.before_selective_dashboard.bak'
TARGETS = (
    'src/pages/UniversalAnalysis.tsx',
    'src/components/AdvancedAssessmentPanel.tsx',
    'src/components/VendorDeepReviewPanel.tsx',
    'src/components/RuleCorrelationPanel.tsx',
    'src/components/CorrelationAssurancePanel.tsx',
)


def rollback(frontend: Path) -> list[str]:
    root = frontend.resolve()
    if not (root / 'package.json').is_file():
        raise ValueError(f'Frontend package.json not found: {root}')
    candidates = []
    for rel in TARGETS:
        target = root / rel
        backup = target.with_name(target.name + SUFFIX)
        if backup.is_file():
            candidates.append((target, backup.read_bytes(), rel))
    for target, content, _ in candidates:
        target.write_bytes(content)
    return [rel for _, _, rel in candidates]


if __name__ == '__main__':
    if len(sys.argv) > 2:
        sys.exit('Usage: rollback_selective_dashboard.py [frontend-directory]')
    frontend = Path(sys.argv[1]) if len(sys.argv) == 2 else Path.cwd() / 'frontend'
    try:
        restored = rollback(frontend)
    except (OSError, ValueError) as error:
        sys.exit(f'ERROR: {error}')
    print('Restored from selective-dashboard backups:' if restored else 'No selective-dashboard backups found.')
    for rel in restored:
        print('  ' + rel)
