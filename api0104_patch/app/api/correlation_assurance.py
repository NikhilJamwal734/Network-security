"""API-010.4 opt-in route, wraps the user's already-fixed API-010.3 route.

Critically: read/rewind UploadFile BEFORE calling API-010.3, because the
canonical analyzer closes uploaded files after processing them.
"""
from __future__ import annotations

from typing import Any
from fastapi import APIRouter, File, Query, UploadFile

from app.core.correlation_assurance import verify_correlations

router = APIRouter(tags=['Rule Correlation Assurance'])
MAX_SAMPLE_BYTES = 2 * 1024 * 1024


async def _previous_analysis(*, file: UploadFile, platform: str | None) -> dict[str, Any]:
    from app.api.rule_correlation import analyze_rule_correlation
    return await analyze_rule_correlation(file=file, platform=platform)


@router.post('/api/v1/analyze/correlation-assurance')
async def analyze_correlation_assurance(
    file: UploadFile = File(...),
    platform: str | None = Query(default=None, max_length=64),
) -> dict[str, Any]:
    # The canonical upload validator and existing analyzer remain in charge.
    # Capture a strictly bounded sample BEFORE either may close UploadFile.
    await file.seek(0)
    sample = await file.read(MAX_SAMPLE_BYTES + 1)
    await file.seek(0)
    previous = await _previous_analysis(file=file, platform=platform)
    capped = len(sample) > MAX_SAMPLE_BYTES
    raw = sample[:MAX_SAMPLE_BYTES]
    # Strict UTF-8 only. If a sample boundary cuts a multi-byte character,
    # remove only that incomplete tail (not arbitrary malformed bytes).
    try:
        source = raw.decode('utf-8-sig', errors='strict')
    except UnicodeDecodeError as error:
        if capped and error.end == len(raw) and error.reason == 'unexpected end of data':
            source = raw[:error.start].decode('utf-8-sig', errors='strict')
        else:
            # If the existing validator accepted a different encoding, we abstain.
            source = ''
            capped = True
    platform_id = previous['platform']['platform_id']
    result = verify_correlations(platform_id, source, previous['rule_correlation'], source_truncated=capped)
    return {**previous, 'correlation_assurance': result}
