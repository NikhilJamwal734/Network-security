"""Plan an additive backend extension based on API-011.3 anchors."""
from __future__ import annotations
from pathlib import Path
import sys

PACKAGE = Path(__file__).resolve().parents[1]


def plan(root: Path) -> dict[Path, bytes]:
    root = root.resolve()
    for prerequisite in ('app/api/pdf_export_readiness.py', 'app/core/pdf_export_readiness.py'):
        if not (root / prerequisite).is_file():
            raise ValueError(f'API-011.3 prerequisite missing: {prerequisite}')
    target = root / 'app/api/main.py'
    if not target.is_file():
        raise ValueError('Missing app/api/main.py')
    raw = target.read_bytes()
    bom = raw.startswith(b'\xef\xbb\xbf')
    text = raw.decode('utf-8-sig')
    eol = '\r\n' if '\r\n' in text else '\n'
    canonical = text.replace('\r\n', '\n')
    previous_import = 'from app.api.pdf_export_readiness import router as pdf_export_readiness_router\n'
    previous_router = 'app.include_router(pdf_export_readiness_router)\n'
    new_import = 'from app.api.pipeline_validation import router as pipeline_validation_router\n'
    new_router = 'app.include_router(pipeline_validation_router)\n'
    if (new_import in canonical) != (new_router in canonical):
        raise ValueError('Partial API-011.4 backend router registration')
    if new_import not in canonical:
        if canonical.count(previous_import)!=1 or canonical.count(previous_router)!=1:
            raise ValueError('API-011.3 registration anchor missing or ambiguous')
        canonical = canonical.replace(previous_import, previous_import+new_import, 1)
        canonical = canonical.replace(previous_router, previous_router+new_router, 1)
    updated = (b'\xef\xbb\xbf' if bom else b'') + canonical.replace('\n',eol).encode('utf-8')
    changes: dict[Path, bytes] = {}
    if raw != updated:
        changes[target] = updated
    for rel in ('app/core/pipeline_validation.py','app/api/pipeline_validation.py'):
        source = (PACKAGE/rel).read_bytes()
        dst = root/rel
        if dst.exists():
            if dst.read_bytes()!=source: raise ValueError(f'Refusing overwrite of customized module: {dst}')
        else: changes[dst] = source
    return changes


if __name__ == '__main__':
    root = Path(sys.argv[1]) if len(sys.argv)==2 else Path.cwd()
    if len(sys.argv)>2: sys.exit('Usage: install_api_011_4.py [project-root]')
    try:
        changes=plan(root)
        print('Backend files to change (use combined installer for safe backups):')
        for x in changes:print(' -',x)
    except (OSError,ValueError,UnicodeError) as e: sys.exit(f'ERROR: {e}')
