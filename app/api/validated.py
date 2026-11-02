"""API-010.0 opt-in quality-gated normalized configuration assessment.

The existing universal endpoint validates and routes uploaded untrusted text.
Do not introduce a second upload reader or change legacy response formats.
"""

from typing import Any
from fastapi import APIRouter, File, Query, UploadFile

from app.api.assessment import _NORMALIZERS, _registry
from app.api.universal import analyze_universal
from app.core.advanced_assessment import build_advanced_assessment
from app.core.report_quality import validate_report_quality

router = APIRouter(tags=["Report Validation"])


@router.post("/api/v1/analyze/validated")
async def analyze_validated(
    file: UploadFile = File(...),
    platform: str | None = Query(default=None, max_length=64),
) -> dict[str, Any]:
    """Return existing normalized + assessment data with an independent
    report-consistency diagnostic. No change to security finding totals.
    """
    source = await analyze_universal(file=file, platform=platform)
    selected = source["platform_detection"]
    platform_id = selected["platform_id"]
    descriptor = _registry.get(platform_id).descriptor
    normalized = _NORMALIZERS[platform_id](
        source, descriptor, detection_method=selected["method"]
    ).to_dict()
    assessment = build_advanced_assessment(normalized, source)
    quality = validate_report_quality(normalized, source, assessment)
    return {**normalized, "assessment": assessment, "quality": quality}
