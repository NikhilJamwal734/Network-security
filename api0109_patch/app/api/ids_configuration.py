"""API 010.9: preserve the 010.8 response; add Snort/Suricata PDF-first review."""
from __future__ import annotations
from typing import Any
from fastapi import APIRouter, File, Query, UploadFile
from app.core.ids_configuration import review_ids_configuration

router = APIRouter(tags=['IDS Deep Configuration Review'])
MAX_SAMPLE_BYTES = 2 * 1024 * 1024


async def _previous_analysis(*, file: UploadFile, platform: str | None) -> dict[str, Any]:
    from app.api.nat_route_reachability import analyze_nat_route_reachability
    return await analyze_nat_route_reachability(file=file, platform=platform)


@router.post('/api/v1/analyze/ids-configuration')
async def analyze_ids_configuration(
    file: UploadFile = File(...), platform: str | None = Query(default=None, max_length=64),
) -> dict[str, Any]:
    # Important: earlier stages may close UploadFile. Snapshot first, rewind.
    await file.seek(0)
    sample = await file.read(MAX_SAMPLE_BYTES + 1)
    await file.seek(0)
    previous = await _previous_analysis(file=file, platform=platform)
    raw = sample[:MAX_SAMPLE_BYTES]
    truncated = len(sample) > MAX_SAMPLE_BYTES
    try:
        source = raw.decode('utf-8-sig', errors='strict')
    except UnicodeDecodeError as exc:
        if truncated and exc.end == len(raw) and exc.reason == 'unexpected end of data':
            source = raw[:exc.start].decode('utf-8-sig', errors='strict')
        else:
            source = ''
            truncated = True
    platform_id = previous['platform']['platform_id']
    review = review_ids_configuration(platform_id, source, source_truncated=truncated)
    return {**previous, 'ids_deep_review': review}
