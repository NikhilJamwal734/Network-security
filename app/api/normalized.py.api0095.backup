"""API-009.6 opt-in normalized reports: ASA, Snort, Suricata, FortiOS."""

from typing import Any
from fastapi import APIRouter, File, Query, UploadFile

from app.api.universal import analyze_universal
from app.core.catalog import create_default_registry
from app.core.normalization import normalize_cisco_asa_report
from app.core.fortios_normalization import normalize_fortios_report
from app.core.snort_normalization import normalize_snort_report
from app.core.suricata_normalization import normalize_suricata_report

router = APIRouter(tags=["Normalized Analysis"])
_registry = create_default_registry()


@router.post("/api/v1/analyze/normalized")
async def analyze_normalized(
    file: UploadFile = File(...),
    platform: str | None = Query(default=None, max_length=64),
) -> dict[str, Any]:
    report = await analyze_universal(file=file, platform=platform)
    selected = report["platform_detection"]
    platform_id = selected["platform_id"]
    descriptor = _registry.get(platform_id).descriptor
    if platform_id == "cisco_asa":
        normalized = normalize_cisco_asa_report(
            report, descriptor, detection_method=selected["method"]
        )
    elif platform_id == "fortios":
        normalized = normalize_fortios_report(
            report, descriptor, detection_method=selected["method"]
        )
    elif platform_id == "snort":
        normalized = normalize_snort_report(
            report, descriptor, detection_method=selected["method"]
        )
    elif platform_id == "suricata":
        normalized = normalize_suricata_report(
            report, descriptor, detection_method=selected["method"]
        )
    else:
        raise RuntimeError("Registered platform does not have a verified normalizer")
    return normalized.to_dict()
