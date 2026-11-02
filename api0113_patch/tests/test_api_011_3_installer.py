from __future__ import annotations
import importlib.util
from pathlib import Path
from tempfile import TemporaryDirectory
import pytest

ROOT=Path(__file__).resolve().parents[1]

def load(path,name):
    spec=importlib.util.spec_from_file_location(name,path)
    assert spec and spec.loader
    mod=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

allmod=load(ROOT/'scripts/install_all_api_011_3.py','all113')
rollback=load(ROOT/'scripts/rollback_api_011_3.py','rb113')


def setup(root):
    data={
        'app/api/main.py':'from app.api.report_validation import router as report_validation_router\napp.include_router(report_validation_router)\n',
        'app/api/report_validation.py':'# API-11.2',
        'app/core/report_validation.py':'# API-11.2',
        'frontend/package.json':'{}',
        'frontend/src/api/universal.ts': '  report_validation_review?: ReportValidationReview;\nconst endpoint = "/api/v1/analyze/report-validation";',
        'frontend/src/pages/UniversalAnalysis.tsx': 'import ReportValidationSnippet from "../components/ReportValidationSnippet";\n<ReportValidationSnippet review={report.report_validation_review} />',
        'frontend/src/utils/normalizedPdf.ts': 'import type { jsPDF } from "jspdf";\n  section("Assessment coverage");\n  pdf.save(`${normalizedFilename(filename)}.${normalizedFilename(report.platform.platform_id)}.security-report.pdf`);',
    }
    for rel,value in data.items():
        dest=root/rel;dest.parent.mkdir(parents=True,exist_ok=True)
        dest.write_bytes(value.encode('utf-8'))


def test_full_install_idempotence_and_rollback():
    with TemporaryDirectory() as tmp:
        root=Path(tmp); setup(root)
        original={p:p.read_bytes() for p in root.rglob('*') if p.is_file()}
        changes=allmod.install(root)
        assert len(changes)==10
        assert allmod.install(root)==[]
        pdf=(root/'frontend/src/utils/normalizedPdf.ts').read_text('utf-8')
        dash=(root/'frontend/src/pages/UniversalAnalysis.tsx').read_text('utf-8')
        assert 'exportReview.observations.forEach' in pdf
        assert 'exportReview.observations.forEach' not in dash
        assert 'inspectPdfExport(new Uint8Array(payload)' in pdf
        assert 'downloadVerifiedPdf(payload' in pdf
        assert '<PdfExportReadinessSnippet' in dash
        assert 'ReportValidationSnippet' in dash
        assert 'app.include_router(pdf_export_readiness_router)' in (root/'app/api/main.py').read_text('utf-8')
        rollback.rollback(root)
        assert all(p.read_bytes()==v for p,v in original.items())
        assert not (root/'app/core/pdf_export_readiness.py').exists()


def test_missing_pdf_anchor_aborts_all():
    with TemporaryDirectory() as tmp:
        root=Path(tmp);setup(root)
        (root/'frontend/src/utils/normalizedPdf.ts').write_text('WRONG LAYOUT',encoding='utf-8')
        before=(root/'app/api/main.py').read_bytes()
        with pytest.raises(ValueError):allmod.install(root)
        assert (root/'app/api/main.py').read_bytes()==before
        assert not (root/'app/core/pdf_export_readiness.py').exists()


def test_rollback_rejects_later_edits():
    with TemporaryDirectory() as tmp:
        root=Path(tmp);setup(root)
        allmod.install(root)
        f=root/'frontend/src/pages/UniversalAnalysis.tsx'
        f.write_bytes(f.read_bytes()+b'\n// user edit\n')
        with pytest.raises(ValueError,match='edited since installation'):rollback.rollback(root)
        assert b'// user edit' in f.read_bytes()


def test_crlf_and_utf8_bom_preserved():
    with TemporaryDirectory() as tmp:
        root=Path(tmp);setup(root)
        f=root/'frontend/src/pages/UniversalAnalysis.tsx'
        content=f.read_bytes().replace(b'\n',b'\r\n')
        f.write_bytes(b'\xef\xbb\xbf'+content)
        allmod.install(root)
        changed=f.read_bytes()
        assert changed.startswith(b'\xef\xbb\xbf')
        assert b'\r\n' in changed
        assert b'\n' not in changed.replace(b'\r\n',b'')


def test_existing_custom_component_refuses_overwrite():
    with TemporaryDirectory() as tmp:
        root=Path(tmp);setup(root)
        f=root/'frontend/src/utils/pdfExportIntegrity.ts'
        f.parent.mkdir(parents=True,exist_ok=True)
        f.write_text('my custom changes',encoding='utf-8')
        with pytest.raises(ValueError,match='Refusing to overwrite'):allmod.install(root)
        assert f.read_text('utf-8')=='my custom changes'
