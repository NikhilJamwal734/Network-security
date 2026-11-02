from __future__ import annotations
import importlib.util
from pathlib import Path
from tempfile import TemporaryDirectory
import pytest

ROOT=Path(__file__).resolve().parents[1]

def load(path,name):
    spec=importlib.util.spec_from_file_location(name,path)
    obj=importlib.util.module_from_spec(spec);assert spec and spec.loader;spec.loader.exec_module(obj)
    return obj

installer=load(ROOT/'scripts/install_all_api_011_4.py','all114')
rollback=load(ROOT/'scripts/rollback_api_011_4.py','rollback114')


def setup(root):
    files={
        'app/api/main.py':'from app.api.pdf_export_readiness import router as pdf_export_readiness_router\napp.include_router(pdf_export_readiness_router)\n',
        'app/api/pdf_export_readiness.py':'# present 11.3',
        'app/core/pdf_export_readiness.py':'# present 11.3',
        'frontend/package.json':'{}',
        'frontend/src/api/universal.ts':'  pdf_export_review?: PdfExportReview;\nconst endpoint="/api/v1/analyze/pdf-readiness";',
        'frontend/src/pages/UniversalAnalysis.tsx':'import PdfExportReadinessSnippet from "../components/PdfExportReadinessSnippet";\n<PdfExportReadinessSnippet review={report.pdf_export_review} />',
        'frontend/src/utils/normalizedPdf.ts':'  section("Assessment coverage");',
    }
    for name,value in files.items():
        p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(value.encode())


def test_install_idempotent_rollback_and_unchanged_originals():
    with TemporaryDirectory() as temp:
        root=Path(temp);setup(root)
        before={p:p.read_bytes() for p in root.rglob('*') if p.is_file()}
        changed=installer.install(root)
        assert len(changed)==8
        assert installer.install(root)==[]
        assert len(changed)==len(set(changed))
        assert (root/'app/api/main.py').read_text(encoding='utf8').count('app.include_router(pipeline_validation_router)')==1
        assert 'PdfExportReadinessSnippet' in (root/'frontend/src/pages/UniversalAnalysis.tsx').read_text(encoding='utf8')
        assert len(rollback.rollback(root))==len(changed)
        assert all(p.read_bytes()==data for p,data in before.items())
        assert not (root/'app/api/pipeline_validation.py').exists()
        assert not (root/'.api0114_install_manifest.json').exists()


def test_invalid_pdf_anchor_rejects_before_backend_change():
    with TemporaryDirectory() as temp:
        root=Path(temp);setup(root)
        bad=root/'frontend/src/utils/normalizedPdf.ts';bad.write_text('BROKEN',encoding='utf-8')
        old=(root/'app/api/main.py').read_bytes()
        with pytest.raises(ValueError):installer.install(root)
        assert (root/'app/api/main.py').read_bytes()==old
        assert not (root/'app/core/pipeline_validation.py').exists()


def test_modified_file_protected_from_rollback():
    with TemporaryDirectory() as temp:
        root=Path(temp);setup(root)
        installer.install(root)
        f=root/'frontend/src/pages/UniversalAnalysis.tsx';f.write_bytes(f.read_bytes()+b'// future edit')
        with pytest.raises(ValueError,match='modified since'):rollback.rollback(root)
        assert f.read_bytes().endswith(b'// future edit')


def test_api_main_bom_crlf_preserved():
    with TemporaryDirectory() as temp:
        root=Path(temp);setup(root)
        f=root/'app/api/main.py'
        f.write_bytes(b'\xef\xbb\xbf'+f.read_bytes().replace(b'\n',b'\r\n'))
        installer.install(root)
        raw=f.read_bytes()
        assert raw.startswith(b'\xef\xbb\xbf')
        assert b'\r\n' in raw
        assert b'\n' not in raw.replace(b'\r\n',b'')


def test_install_manifests_isolated_between_projects():
    with TemporaryDirectory() as tmp1,TemporaryDirectory() as tmp2:
        a=Path(tmp1);b=Path(tmp2)
        setup(a);setup(b)
        assert len(installer.install(a))==8
        assert len(installer.install(b))==8
        rollback.rollback(a)
        assert (b/'.api0114_install_manifest.json').exists()
