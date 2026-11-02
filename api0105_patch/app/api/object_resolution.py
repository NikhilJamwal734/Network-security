"""Opt-in API-010.5 wrapper; capture source before the prior analyzer closes it."""
from __future__ import annotations
from typing import Any
from fastapi import APIRouter, File, Query, UploadFile
from app.core.object_resolution import resolve_and_compare

router = APIRouter(tags=['Network Object Resolution'])
MAX_SAMPLE_BYTES = 2 * 1024 * 1024


async def _previous_analysis(*, file: UploadFile, platform: str | None) -> dict[str, Any]:
    from app.api.correlation_assurance import analyze_correlation_assurance
    return await analyze_correlation_assurance(file=file, platform=platform)


@router.post('/api/v1/analyze/object-resolution')
async def analyze_object_resolution(
    file: UploadFile = File(...),
    platform: str | None = Query(default=None, max_length=64),
) -> dict[str, Any]:
    await file.seek(0)
    sample = await file.read(MAX_SAMPLE_BYTES + 1)
    await file.seek(0)
    previous = await _previous_analysis(file=file, platform=platform)
    capped = len(sample) > MAX_SAMPLE_BYTES
    raw = sample[:MAX_SAMPLE_BYTES]
    try:
        source = raw.decode('utf-8-sig', errors='strict')
    except UnicodeDecodeError as error:
        if capped and error.end == len(raw) and error.reason == 'unexpected end of data':
            source = raw[:error.start].decode('utf-8-sig', errors='strict')
        else:
            source = ''
            capped = True
    identifier = previous['platform']['platform_id']
    return {**previous, 'object_resolution': resolve_and_compare(identifier, source, source_truncated=capped)}
