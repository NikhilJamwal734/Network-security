"""API-011.6: validated input entry point for the prior analysis pipeline."""
from __future__ import annotations
from typing import Any
from fastapi import APIRouter, File, HTTPException, Query, UploadFile
from app.core.input_hardening import MAX_CONFIG_BYTES, InputProblem, check_filename, check_platform, inspect_config_bytes
from app.core.audit_logging import audit_event

router = APIRouter(tags=['Input Security Validation'])


@router.post('/api/v1/analyze/hardened')
async def analyze_hardened(
    file: UploadFile = File(...), platform: str | None = Query(default=None, max_length=64),
) -> dict[str, Any]:
    try:
        # Reject untrusted metadata first. File bytes are read with a strict
        # cap, rather than consuming arbitrary-length uploads in this handler.
        check_platform(platform)
        check_filename(file.filename)
        await file.seek(0)
        data = await file.read(MAX_CONFIG_BYTES + 1)
        review = inspect_config_bytes(data, filename=file.filename, platform=platform)
        await file.seek(0)
    except InputProblem as exc:
        audit_event('upload_audit', 'upload_rejected', filename=file.filename, platform=platform or 'auto',
                    code=exc.code, status_code=exc.status_code)
        raise HTTPException(status_code=exc.status_code, detail={'code': exc.code, 'message': exc.message}) from None

    audit_event('upload_audit', 'upload_accepted', filename=file.filename, platform=platform or 'auto', size_bytes=len(data))
    audit_event('security_analysis', 'analysis_started', filename=file.filename, platform=platform or 'auto')
    from app.api.pipeline_validation import analyze_pipeline_validation
    try:
        result = await analyze_pipeline_validation(file=file, platform=platform)
        if not isinstance(result, dict):
            raise HTTPException(status_code=502, detail='Unexpected upstream response shape.')
    except Exception as exc:
        audit_event('security_analysis', 'analysis_failed', filename=file.filename, platform=platform or 'auto',
                    error_type=type(exc).__name__)
        raise
    findings = result.get('findings')
    count = len(findings) if isinstance(findings, list) else None
    audit_event('security_analysis', 'analysis_completed', filename=file.filename, platform=platform or 'auto', finding_count=count)
    return {**result, 'input_security_review': review}
