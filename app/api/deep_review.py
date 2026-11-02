"""API-010.1 opt-in deep vendor review, preserving API-010.0 response shapes.

Reuses the universal upload validator/router: no second file reader, no
untrusted configuration execution, and no changes to legacy endpoints.
"""
from typing import Any

from fastapi import APIRouter, File, Query, UploadFile

from app.api.assessment import _NORMALIZERS, _registry
from app.api.universal import analyze_universal
from app.core.advanced_assessment import build_advanced_assessment
from app.core.report_quality import validate_report_quality

router = APIRouter(tags=["Vendor-specific Analysis"])


@router.post("/api/v1/analyze/deep-review")
async def analyze_deep_review(
    file: UploadFile = File(...),
    platform: str | None = Query(default=None, max_length=64),
) -> dict[str, Any]:
    source = await analyze_universal(file=file, platform=platform, _vendor_review=True)
    selected = source["platform_detection"]
    platform_id = selected["platform_id"]
    descriptor = _registry.get(platform_id).descriptor
    normalized = _NORMALIZERS[platform_id](
        source, descriptor, detection_method=selected["method"]
    ).to_dict()
    assessment = build_advanced_assessment(normalized, source)
    quality = validate_report_quality(normalized, source, assessment)
    return {
        **normalized,
        "assessment": assessment,
        "quality": quality,
        "vendor_review": source["vendor_review"],
    }
