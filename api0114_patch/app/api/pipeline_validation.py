"""API-011.4 single-upload additive pipeline contract endpoint."""
from __future__ import annotations
from typing import Any
from fastapi import APIRouter, File, Query, UploadFile
from app.core.pipeline_validation import inspect_pipeline

router = APIRouter(tags=['Pipeline Validation'])


@router.post('/api/v1/analyze/pipeline-validation')
async def analyze_pipeline_validation(
    file: UploadFile = File(...), platform: str | None = Query(default=None, max_length=64),
) -> dict[str, Any]:
    from app.api.pdf_export_readiness import analyze_pdf_readiness
    upstream = await analyze_pdf_readiness(file=file, platform=platform)
    return {**upstream, 'pipeline_validation_review': inspect_pipeline(upstream)}
