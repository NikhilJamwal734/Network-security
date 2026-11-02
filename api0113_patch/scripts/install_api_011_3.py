"""Validate API-011.2 anchor files before backend patch writes."""
from __future__ import annotations
from pathlib import Path
from shutil import copy2
import sys

PACKAGE=Path(__file__).resolve().parents[1]


def plan(root:Path)->dict[Path,bytes]:
    root=root.resolve()
    for rel in ('app/api/report_validation.py','app/core/report_validation.py'):
        if not (root/rel).is_file(): raise ValueError(f'Install API-011.2 first: {rel}')
    dst=root/'app/api/main.py'
    if not dst.is_file(): raise ValueError('Missing app/api/main.py')
    raw=dst.read_bytes()
    bom=raw.startswith(b'\xef\xbb\xbf')
    text=raw.decode('utf-8-sig')
    crlf='\r\n' in text
    src=text.replace('\r\n','\n')
    import_line='from app.api.pdf_export_readiness import router as pdf_export_readiness_router'
    include_line='app.include_router(pdf_export_readiness_router)'
    import_anchor='from app.api.report_validation import router as report_validation_router\n'
    include_anchor='app.include_router(report_validation_router)\n'
    if (import_line in src)!=(include_line in src): raise ValueError('Partial API-011.3 router registration')
    if import_line not in src:
        if src.count(import_anchor)!=1 or src.count(include_anchor)!=1:
            raise ValueError('Missing or ambiguous API-011.2 router anchor')
        src=src.replace(import_anchor,import_anchor+import_line+'\n',1)
        src=src.replace(include_anchor,include_anchor+include_line+'\n',1)
    payload=(b'\xef\xbb\xbf' if bom else b'')+src.replace('\n','\r\n' if crlf else '\n').encode('utf-8')
    changes={}
    if raw!=payload: changes[dst]=payload
    for rel, source_rel in (('app/api/pdf_export_readiness.py', 'app/api/pdf_export_readiness.py'),
                            ('app/core/pdf_export_readiness.py', 'app/core/pdf_export_readiness.py'),
                            ('tests/test_api_011_3_pdf_readiness.py', 'tests/test_api_011_3_pdf_readiness_patch.py')):
        src_file=PACKAGE/source_rel
        dst=root/rel
        if dst.is_file() and dst.read_bytes()!=src_file.read_bytes():
            raise ValueError(f'Refusing to overwrite customized file: {dst}')
        if not dst.exists(): changes[dst]=src_file.read_bytes()
    return changes


def install(root:Path)->list[str]:
    root=root.resolve()
    changes=plan(root)
    for dst,data in changes.items():
        dst.parent.mkdir(parents=True,exist_ok=True)
        backup=dst.with_name(dst.name+'.before_api0113.bak')
        if dst.is_file() and not backup.exists(): copy2(dst,backup)
        dst.write_bytes(data)
    return [dst.relative_to(root).as_posix() for dst in changes]


if __name__=='__main__':
    root=Path(sys.argv[1]) if len(sys.argv)==2 else Path.cwd()
    if len(sys.argv)>2: sys.exit('Usage: install_api_011_3.py [project-root]')
    try: print('Changed:',install(root))
    except (OSError,ValueError,UnicodeError) as exc: sys.exit(f'ERROR: {exc}')
