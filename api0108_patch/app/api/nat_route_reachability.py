"""API-010.8 additive route: preserve all prior fields and PDF-only evidence."""
from __future__ import annotations
from typing import Any
from fastapi import APIRouter, File, Query, UploadFile
from app.core.nat_route_reachability import review_nat_route_reachability

router = APIRouter(tags=['NAT Routing and Reachability'])
MAX_SAMPLE_BYTES = 2 * 1024 * 1024


async def _previous_analysis(*, file: UploadFile, platform: str | None) -> dict[str, Any]:
    from app.api.service_ipv6 import analyze_service_ipv6
    return await analyze_service_ipv6(file=file, platform=platform)


@router.post('/api/v1/analyze/nat-route-reachability')
async def analyze_nat_route_reachability(
    file: UploadFile = File(...), platform: str | None = Query(default=None, max_length=64),
) -> dict[str, Any]:
    await file.seek(0)
    raw = await file.read(MAX_SAMPLE_BYTES + 1)
    await file.seek(0)
    previous = await _previous_analysis(file=file, platform=platform)
    truncated = len(raw) > MAX_SAMPLE_BYTES
    data = raw[:MAX_SAMPLE_BYTES]
    try:
        source = data.decode('utf-8-sig', errors='strict')
    except UnicodeDecodeError as error:
        if truncated and error.end == len(data) and error.reason == 'unexpected end of data':
            source = data[:error.start].decode('utf-8-sig', errors='strict')
        else:
            source = ''
            truncated = True
    platform_id = previous['platform']['platform_id']
    review = review_nat_route_reachability(platform_id, source, source_truncated=truncated)
    return {**previous, 'nat_route_reachability': review}
