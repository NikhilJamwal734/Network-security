"""API-010.3 opt-in endpoint; reuses API-010.2 validation and score contract."""
from typing import Any

from fastapi import APIRouter, File, Query, UploadFile

from app.core.rule_correlation import correlate_rules

router = APIRouter(tags=['Rule Correlation'])


async def _run_precision(*, file: UploadFile, platform: str | None) -> dict[str, Any]:
    from app.api.precision_review import analyze_precision_review
    return await analyze_precision_review(file=file, platform=platform)
_MAX_CORRELATION_BYTES = 2 * 1024 * 1024


@router.post('/api/v1/analyze/rule-correlation')
async def analyze_rule_correlation(
    file: UploadFile = File(...),
    platform: str | None = Query(default=None, max_length=64),
) -> dict[str, Any]:
    # Preserve the existing upload validation: this is the canonical parser
    # and the single source of truth for findings and scoring.
    old_report = await _run_precision(file=file, platform=platform)
    await file.seek(0)
    data = await file.read(_MAX_CORRELATION_BYTES + 1)
    capped = len(data) > _MAX_CORRELATION_BYTES
    # Input is validated by the existing endpoint; this secondary bounded pass
    # is used only for optional correlation. Do not attempt lossy decoding.
    sampled = data[:_MAX_CORRELATION_BYTES]
    try:
        text = sampled.decode('utf-8-sig', errors='strict')
    except UnicodeDecodeError as error:
        # An otherwise valid UTF-8 stream may end halfway through a code
        # point at our optional 2 MiB review boundary. Drop only that
        # incomplete tail; never replace malformed bytes elsewhere.
        if not capped or error.end != len(sampled) or error.reason != 'unexpected end of data':
            raise
        text = sampled[:error.start].decode('utf-8-sig', errors='strict')
    result = correlate_rules(old_report['platform']['platform_id'], text, source_truncated=capped)
    return {**old_report, 'rule_correlation': result}
