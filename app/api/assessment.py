"""API-009.8 opt-in, backward-compatible assessment route for four platforms.

Uses the SAME tested upload validator / platform router as API-009.6 and the
same verified normalizers. No second untrusted-file reader is introduced.
"""

from typing import Any

from fastapi import APIRouter, File, Query, UploadFile

from app.api.universal import analyze_universal
from app.core.advanced_assessment import build_advanced_assessment
from app.core.catalog import create_default_registry
from app.core.normalization import normalize_cisco_asa_report
from app.core.fortios_normalization import normalize_fortios_report
from app.core.snort_normalization import normalize_snort_report
from app.core.suricata_normalization import normalize_suricata_report

router = APIRouter(tags=["Advanced Assessment"])
_registry = create_default_registry()
_NORMALIZERS = {
    "cisco_asa": normalize_cisco_asa_report,
    "fortios": normalize_fortios_report,
    "snort": normalize_snort_report,
    "suricata": normalize_suricata_report,
}


@router.post("/api/v1/analyze/assessment")
async def analyze_assessment(
    file: UploadFile = File(...),
    platform: str | None = Query(default=None, max_length=64),
) -> dict[str, Any]:
    source = await analyze_universal(file=file, platform=platform)
    selection = source["platform_detection"]
    platform_id = selection["platform_id"]
    descriptor = _registry.get(platform_id).descriptor
    normalized = _NORMALIZERS[platform_id](
        source, descriptor, detection_method=selection["method"]
    ).to_dict()
    normalized["assessment"] = build_advanced_assessment(normalized, source)
    return normalized
