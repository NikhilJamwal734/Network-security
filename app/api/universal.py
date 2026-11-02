"""API-009.5 universal upload boundary and trusted platform routing.

Uploaded text is never executed. Shared IDS rule syntax requires explicit
Snort/Suricata selection; only vendor-specific markers enable automatic routing.
"""

import inspect
from pathlib import Path
from typing import Any

from fastapi import APIRouter, File, HTTPException, Query, UploadFile

from app.core.catalog import create_default_registry
from app.core.detection import PlatformDetectionError, select_platform
from app.security.untrusted_config import read_untrusted_config
from app.security.snort_rules_upload import read_snort_rules_upload
from app.security.suricata_yaml_upload import read_suricata_yaml_upload

router = APIRouter(tags=["Universal Analysis"])
_registry = create_default_registry()
_ALLOWED_EXTENSIONS = frozenset({".conf", ".cfg", ".txt", ".rules", ".yaml", ".yml"})


@router.get("/api/v1/platforms")
def list_supported_platforms() -> dict[str, list[dict[str, Any]]]:
    return {
        "platforms": [
            {
                "platform_id": descriptor.platform_id,
                "display_name": descriptor.display_name,
                "family": descriptor.family.value,
                "extensions": list(descriptor.extensions),
            }
            for descriptor in _registry.list_platforms()
        ]
    }


@router.post("/api/v1/analyze/universal")
async def analyze_universal(
    file: UploadFile = File(...),
    platform: str | None = Query(default=None, max_length=64),
    _vendor_review: bool = False,
    _precision_review: bool = False,
) -> dict[str, Any]:
    try:
        extension = Path(file.filename or "").suffix.lower()
        if extension not in _ALLOWED_EXTENSIONS:
            raise HTTPException(
                status_code=400,
                detail="Unsupported file extension. Allowed: .conf, .cfg, .txt, .rules, .yaml, .yml",
            )
        if extension == ".rules":
            validated = await read_snort_rules_upload(file)
        elif extension in (".yaml", ".yml"):
            validated = await read_suricata_yaml_upload(file)
        else:
            validated = read_untrusted_config(file)
            if inspect.isawaitable(validated):
                validated = await validated
        if isinstance(validated, str):
            lines = validated.splitlines()
        elif isinstance(validated, list) and all(isinstance(x, str) for x in validated):
            lines = validated
        else:
            raise RuntimeError("read_untrusted_config must return decoded text or text lines")

        try:
            selected = select_platform(lines, _registry, platform)
        except PlatformDetectionError as exc:
            status = 400 if exc.code == "unsupported_platform" else 422
            raise HTTPException(
                status_code=status,
                detail={"code": exc.code, "message": str(exc)},
            ) from None
        adapter = _registry.get(selected.platform_id)
        if extension not in adapter.descriptor.extensions:
            raise HTTPException(
                status_code=400,
                detail="The file extension is not supported for the selected platform.",
            )
        report = adapter.analyze(lines)
        if _vendor_review:
            from app.core.vendor_review import (
                review_cisco_asa, review_fortios, review_snort, review_suricata,
            )
            from app.parsers.firewalls.fortios import FortiOSParser
            from app.parsers.ids.snort import SnortParser
            from app.parsers.ids.suricata import SuricataParser
            if selected.platform_id == "cisco_asa":
                vendor_review = review_cisco_asa(lines)
            elif selected.platform_id == "fortios":
                vendor_review = review_fortios(FortiOSParser().parse(lines))
            elif selected.platform_id == "snort":
                vendor_review = review_snort(SnortParser().parse(lines))
            elif selected.platform_id == "suricata":
                vendor_review = review_suricata(SuricataParser().parse(lines))
            else:
                raise RuntimeError("Unsupported vendor review platform")
            report = {**report, "vendor_review": vendor_review}
            if _precision_review:
                from app.core.precision_review import refine_vendor_review
                report["vendor_review"] = refine_vendor_review(
                    selected.platform_id, lines, vendor_review
                )
        return {
            **report,
            "platform_detection": {
                "platform_id": selected.platform_id,
                "method": selected.method,
            },
        }
    finally:
        await file.close()
