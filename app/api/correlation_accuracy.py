"""API-011.1: append a read-only accuracy advisory to the API-011.0 response."""
from __future__ import annotations
from typing import Any
from fastapi import APIRouter, File, Query, UploadFile
from app.core.correlation_accuracy import review_correlation_accuracy

router = APIRouter(tags=['Advisory Correlation Accuracy'])


async def _previous_analysis(*, file: UploadFile, platform: str | None) -> dict[str, Any]:
    from app.api.consolidation import analyze_consolidated
    return await analyze_consolidated(file=file, platform=platform)


@router.post('/api/v1/analyze/correlation-accuracy')
async def analyze_correlation_accuracy(
    file: UploadFile = File(...), platform: str | None = Query(default=None, max_length=64),
) -> dict[str, Any]:
    # Prior API handles uploaded file lifetime. No second upload read is made.
    previous = await _previous_analysis(file=file, platform=platform)
    review = review_correlation_accuracy(previous)
    return {**previous, 'correlation_accuracy_review': review}
