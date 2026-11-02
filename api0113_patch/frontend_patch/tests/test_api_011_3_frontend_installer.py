from __future__ import annotations
import importlib.util
from pathlib import Path
from tempfile import TemporaryDirectory
import pytest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('fe113',ROOT/'scripts/install_api_011_3_frontend.py')
assert spec and spec.loader
mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)


def base(root):
    data={
        'package.json':'{}',
        'src/api/universal.ts':'  report_validation_review?: ReportValidationReview;\nconst endpoint = "/api/v1/analyze/report-validation";',
        'src/pages/UniversalAnalysis.tsx':'import ReportValidationSnippet from "../components/ReportValidationSnippet";\n<ReportValidationSnippet review={report.report_validation_review} />',
        'src/utils/normalizedPdf.ts':'import type { jsPDF } from "jspdf";\n  section("Assessment coverage");\n  pdf.save(`${normalizedFilename(filename)}.${normalizedFilename(report.platform.platform_id)}.security-report.pdf`);',
    }
    for key,v in data.items():
        p=root/key;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(v.encode('utf-8'))


def test_frontend_plan_and_idempotence():
    with TemporaryDirectory() as tmp:
        root=Path(tmp);base(root)
        assert len(mod.plan(root))==6
        assert len(mod.install(root))==6
        assert mod.plan(root)=={}


def test_broken_export_function_blocks_before_writes():
    with TemporaryDirectory() as tmp:
        root=Path(tmp);base(root)
        pdf=root/'src/utils/normalizedPdf.ts'
        pdf.write_text('wrong',encoding='utf-8')
        before=(root/'src/api/universal.ts').read_bytes()
        with pytest.raises(ValueError):mod.install(root)
        assert (root/'src/api/universal.ts').read_bytes()==before
