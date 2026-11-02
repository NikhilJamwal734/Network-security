"""API-011.3 additive PDF readiness preflight endpoint."""
from __future__ import annotations
from typing import Any
from fastapi import APIRouter, File, Query, UploadFile
from app.core.pdf_export_readiness import assess_pdf_readiness

router = APIRouter(tags=['PDF Export Readiness'])


@router.post('/api/v1/analyze/pdf-readiness')
async def analyze_pdf_readiness(
    file: UploadFile = File(...), platform: str | None = Query(default=None, max_length=64),
) -> dict[str, Any]:
    from app.api.report_validation import analyze_report_validation
    upstream = await analyze_report_validation(file=file, platform=platform)
    return {**upstream, 'pdf_export_review': assess_pdf_readiness(upstream)}
