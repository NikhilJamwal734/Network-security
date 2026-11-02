"""API-011.0: preserve the complete prior report and append consolidation data."""
from __future__ import annotations
from typing import Any
from fastapi import APIRouter, File, Query, UploadFile
from app.core.consolidation import consolidate_report

router = APIRouter(tags=['Cross-Review Evidence Consolidation'])


async def _previous_analysis(*, file: UploadFile, platform: str | None) -> dict[str, Any]:
    from app.api.ids_configuration import analyze_ids_configuration
    return await analyze_ids_configuration(file=file, platform=platform)


@router.post('/api/v1/analyze/consolidated')
async def analyze_consolidated(
    file: UploadFile = File(...), platform: str | None = Query(default=None, max_length=64),
) -> dict[str, Any]:
    # Do not reread the upload. Upstream snapshots/rewinds as needed.
    previous = await _previous_analysis(file=file, platform=platform)
    review = consolidate_report(previous)
    return {**previous, 'consolidation_review': review}
