"""API-010.7 additive endpoint; snapshot input before upstream closes UploadFile."""
from __future__ import annotations
from typing import Any

from fastapi import APIRouter, File, Query, UploadFile
from app.core.service_ipv6 import review_service_ipv6

router = APIRouter(tags=['Service Groups and IPv6'])
MAX_SAMPLE_BYTES = 2 * 1024 * 1024


async def _previous_analysis(*, file: UploadFile, platform: str | None) -> dict[str, Any]:
    from app.api.object_assurance import analyze_object_assurance
    return await analyze_object_assurance(file=file, platform=platform)


@router.post('/api/v1/analyze/service-ipv6')
async def analyze_service_ipv6(
    file: UploadFile = File(...),
    platform: str | None = Query(default=None, max_length=64),
) -> dict[str, Any]:
    await file.seek(0)
    sample = await file.read(MAX_SAMPLE_BYTES + 1)
    await file.seek(0)
    previous = await _previous_analysis(file=file, platform=platform)
    truncated = len(sample) > MAX_SAMPLE_BYTES
    raw = sample[:MAX_SAMPLE_BYTES]
    try:
        source = raw.decode('utf-8-sig', errors='strict')
    except UnicodeDecodeError as error:
        if truncated and error.end == len(raw) and error.reason == 'unexpected end of data':
            source = raw[:error.start].decode('utf-8-sig', errors='strict')
        else:
            source = ''
            truncated = True
    platform_id = previous['platform']['platform_id']
    result = review_service_ipv6(platform_id, source, source_truncated=truncated)
    return {**previous, 'service_ipv6': result}
