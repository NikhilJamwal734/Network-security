"""API-010.2 opt-in precision endpoint; earlier endpoint contracts stay intact."""
from typing import Any

from fastapi import APIRouter, File, Query, UploadFile

from app.api.assessment import _NORMALIZERS, _registry
from app.api.universal import analyze_universal
from app.core.advanced_assessment import build_advanced_assessment
from app.core.report_quality import validate_report_quality

router = APIRouter(tags=["Precision Review"])


@router.post("/api/v1/analyze/precision-review")
async def analyze_precision_review(
    file: UploadFile = File(...),
    platform: str | None = Query(default=None, max_length=64),
) -> dict[str, Any]:
    source = await analyze_universal(
        file=file, platform=platform, _vendor_review=True, _precision_review=True
    )
    selection = source["platform_detection"]
    platform_id = selection["platform_id"]
    descriptor = _registry.get(platform_id).descriptor
    normalized = _NORMALIZERS[platform_id](
        source, descriptor, detection_method=selection["method"]
    ).to_dict()
    assessment = build_advanced_assessment(normalized, source)
    quality = validate_report_quality(normalized, source, assessment)
    return {
        **normalized,
        "assessment": assessment,
        "quality": quality,
        "vendor_review": source["vendor_review"],
    }
