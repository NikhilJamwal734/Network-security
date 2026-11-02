"""Restore pre-011.0 integrations from first-install backups.

New, unreferenced 011.0 modules are retained for audit; restoring original
integrations disables them. Refuse to rollback when expected markers are missing.
"""
from __future__ import annotations
from pathlib import Path
import sys

BACKUP = '.before_api0110.bak'
RESTORE = ('app/api/main.py',
           'frontend/src/api/universal.ts',
           'frontend/src/pages/UniversalAnalysis.tsx',
           'frontend/src/utils/normalizedPdf.ts')
ANCHORS = ('app.include_router(consolidation_router)',
           '/api/v1/analyze/consolidated',
           '<ConsolidationSnippet review={report.consolidation_review} />',
           'section("Cross-platform review consolidation — Evidence quality and provenance")')


def rollback(root: Path) -> list[str]:
    root = root.resolve()
    plan = []
    for rel, anchor in zip(RESTORE, ANCHORS):
        dst = root / rel
        bak = dst.with_name(dst.name + BACKUP)
        if not dst.is_file() or not bak.is_file():
            raise ValueError(f'Rollback prerequisite missing: {rel}, or its saved backup')
        current = dst.read_text(encoding='utf-8-sig')
        if anchor not in current:
            raise ValueError(f'Current file does not contain expected API-011.0 integration: {rel}')
        plan.append((dst, bak.read_bytes()))
    for dst, data in plan:
        dst.write_bytes(data)
    return [str(dst.relative_to(root)) for dst, _ in plan]


if __name__ == '__main__':
    if len(sys.argv) > 2:
        sys.exit('Usage: rollback_api_011_0.py [project-root]')
    try:
        changes = rollback(Path(sys.argv[1]) if len(sys.argv) == 2 else Path.cwd())
    except (ValueError, OSError) as error:
        sys.exit(f'ERROR: {error}')
    print('Restored pre-011.0 integration files:')
    for change in changes:
        print('  ' + change)
    print('New 011.0 source files are retained but no longer routed or rendered.')
