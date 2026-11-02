"""Optional local verification checks a real, parseable PDF rather than just magic bytes."""
from __future__ import annotations
import importlib.util
from pathlib import Path
from tempfile import TemporaryDirectory
import pytest

pypdf = pytest.importorskip('pypdf')
reportlab = pytest.importorskip('reportlab')
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('pdfaudit113',ROOT/'scripts/audit_saved_pdf.py')
assert spec and spec.loader
mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)


def fixture_pdf(path:Path,heading=True):
    from reportlab.pdfgen.canvas import Canvas
    c=Canvas(str(path),pagesize=(595,842))
    c.drawString(40,770,'ASSESSMENT COVERAGE')
    c.drawString(40,740,'REPORT INTERPRETATION')
    if heading:c.drawString(40,710,'PDF EXPORT READINESS - Detailed preflight observations')
    c.drawString(40,34,'Page 1 of 1')
    c.showPage();c.save()


def test_real_pdf_parsed_and_sections_present():
    with TemporaryDirectory() as tmp:
        f=Path(tmp)/'output.pdf';fixture_pdf(f)
        result=mod.audit(f,require_113=True)
        assert result['passed'],result
        assert result['page_count']==1


def test_missing_section_rejected():
    with TemporaryDirectory() as tmp:
        f=Path(tmp)/'output.pdf';fixture_pdf(f,False)
        result=mod.audit(f,require_113=True)
        assert not result['passed']
        assert 'PDF EXPORT READINESS' in str(result['issues'])


def test_invalid_pdf_rejected():
    with TemporaryDirectory() as tmp:
        f=Path(tmp)/'broken.pdf';f.write_bytes(b'%PDF-1.7 garbage')
        with pytest.raises(ValueError):mod.audit(f)
