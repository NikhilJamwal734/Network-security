from __future__ import annotations
from tempfile import TemporaryDirectory
from pathlib import Path
import importlib.util
import pytest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('f114',ROOT/'scripts/install_api_011_4_frontend.py')
f=importlib.util.module_from_spec(spec);assert spec and spec.loader;spec.loader.exec_module(f)


def setup(root):
    for rel,value in {
        'package.json':'{}',
        'src/api/universal.ts':'  pdf_export_review?: PdfExportReview;\nconst endpoint="/api/v1/analyze/pdf-readiness";',
        'src/pages/UniversalAnalysis.tsx':'import PdfExportReadinessSnippet from "../components/PdfExportReadinessSnippet";\n<PdfExportReadinessSnippet review={report.pdf_export_review} />',
        'src/utils/normalizedPdf.ts':'  section("Assessment coverage");',
    }.items():
        p=root/rel;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(value.encode())


def test_frontend_plan_all_changes():
    with TemporaryDirectory() as tmp:
        root=Path(tmp);setup(root)
        changes=f.plan(root);assert len(changes)==5
        for dst,content in changes.items():dst.parent.mkdir(parents=True,exist_ok=True);dst.write_bytes(content)
        assert f.plan(root)=={}
        pdf=(root/'src/utils/normalizedPdf.ts').read_text('utf-8')
        dash=(root/'src/pages/UniversalAnalysis.tsx').read_text('utf-8')
        assert 'pipelineReview.stages.forEach' in pdf
        assert 'pipelineReview.stages.forEach' not in dash
        assert 'PipelineValidationSnippet' in dash


def test_invalid_pdf_anchor_fails_before_writes():
    with TemporaryDirectory() as tmp:
        root=Path(tmp);setup(root)
        p=root/'src/utils/normalizedPdf.ts';p.write_text('broken',encoding='utf-8')
        with pytest.raises(ValueError):f.plan(root)
        assert not (root/'src/components/PipelineValidationSnippet.tsx').exists()


def test_crlf_bom_preserved():
    with TemporaryDirectory() as tmp:
        root=Path(tmp);setup(root)
        p=root/'src/pages/UniversalAnalysis.tsx';p.write_bytes(b'\xef\xbb\xbf'+p.read_bytes().replace(b'\n',b'\r\n'))
        changed=f.plan(root)[p]
        assert changed.startswith(b'\xef\xbb\xbf') and b'\r\n' in changed
        assert b'\n' not in changed.replace(b'\r\n',b'')


def test_custom_component_blocked():
    with TemporaryDirectory() as tmp:
        root=Path(tmp);setup(root)
        p=root/'src/components/PipelineValidationSnippet.tsx';p.parent.mkdir(parents=True,exist_ok=True)
        p.write_text('custom')
        with pytest.raises(ValueError,match='customized'):f.plan(root)
