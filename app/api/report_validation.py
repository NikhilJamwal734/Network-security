"""API-011.2: upstream single-upload report plus additive report contract preflight."""
from __future__ import annotations
from typing import Any
from fastapi import APIRouter, File, Query, UploadFile
from app.core.report_validation import validate_report_contract

router = APIRouter(tags=['Report Validation'])

async def _previous_analysis(*, file: UploadFile, platform: str | None) -> dict[str, Any]:
    from app.api.correlation_accuracy import analyze_correlation_accuracy
    return await analyze_correlation_accuracy(file=file, platform=platform)

@router.post('/api/v1/analyze/report-validation')
async def analyze_report_validation(
    file: UploadFile = File(...), platform: str | None = Query(default=None, max_length=64),
) -> dict[str, Any]:
    previous = await _previous_analysis(file=file, platform=platform)
    review = validate_report_contract(previous)
    return {**previous, 'report_validation_review': review}
