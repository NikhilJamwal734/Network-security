"""API-009.9: safe explicit multi-file Snort / Suricata rule inspection.

This opt-in endpoint does not change existing single-file reports. Uploaded
configurations and rule file contents are data only and never executed.
"""

from __future__ import annotations

import inspect
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, File, HTTPException, Query, UploadFile

from app.core.catalog import create_default_registry
from app.core.detection import PlatformDetectionError, select_platform
from app.core.ids_bundle import analyze_ids_rule_bundle
from app.security.snort_rules_upload import read_snort_rules_upload
from app.security.suricata_yaml_upload import read_suricata_yaml_upload
from app.security.untrusted_config import read_untrusted_config

router = APIRouter(tags=["IDS Rule Bundle"])
_registry = create_default_registry()
MAX_RULE_FILES = 8
MAX_COMBINED_BYTES = 4 * 1024 * 1024


def _safe_filename(filename: str | None) -> str:
    if not filename or len(filename) > 120 or filename.strip() != filename:
        raise HTTPException(status_code=400, detail="Invalid uploaded filename.")
    if "/" in filename or "\\" in filename or filename in (".", ".."):
        raise HTTPException(status_code=400, detail="Use simple filenames without directory paths.")
    if any(ord(c) < 32 or ord(c) == 127 for c in filename):
        raise HTTPException(status_code=400, detail="Invalid filename characters.")
    return filename


async def _validated_lines(file: UploadFile, *, is_rule: bool) -> tuple[str, list[str], int]:
    filename = _safe_filename(file.filename)
    suffix = Path(filename).suffix.lower()
    if is_rule:
        if suffix != ".rules":
            raise HTTPException(status_code=400, detail="Rule attachments must use the .rules extension.")
        text = await read_snort_rules_upload(file)
    else:
        if suffix in (".yaml", ".yml"):
            text = await read_suricata_yaml_upload(file)
        elif suffix in (".conf", ".cfg", ".txt"):
            text = read_untrusted_config(file)
            if inspect.isawaitable(text):
                text = await text
        else:
            raise HTTPException(status_code=400, detail="Unsupported configuration filename extension.")
    if isinstance(text, list) and all(isinstance(item, str) for item in text):
        text = "\n".join(text)
    if not isinstance(text, str):
        raise RuntimeError("Upload validator must return text")
    return filename, text.splitlines(), len(text.encode("utf-8"))


@router.post("/api/v1/analyze/ids-bundle")
async def analyze_ids_bundle(
    platform: Literal["snort", "suricata"] = Query(...),
    rules: list[UploadFile] = File(...),
    config: UploadFile | None = File(default=None),
) -> dict:
    """Inspect 1–8 explicitly selected rule files and an optional IDS config.

    Never resolve a YAML 'rule-files' entry or Snort 'include' directive.
    References are inert labels used solely for coverage/candidate matching.
    """
    uploaded = [*rules, *([config] if config else [])]
    try:
        if not 1 <= len(rules) <= MAX_RULE_FILES:
            raise HTTPException(status_code=400, detail="Upload between 1 and 8 rule files.")
        seen_names: set[str] = set()
        validated_rules: list[tuple[str, list[str]]] = []
        total_bytes = 0
        for file in rules:
            filename, lines, size = await _validated_lines(file, is_rule=True)
            if filename.casefold() in seen_names:
                raise HTTPException(status_code=400, detail="Duplicate uploaded filename.")
            seen_names.add(filename.casefold())
            total_bytes += size
            if total_bytes > MAX_COMBINED_BYTES:
                raise HTTPException(status_code=413, detail="Combined upload exceeds 4 MiB limit.")
            validated_rules.append((filename, lines))

        validated_config = None
        if config is not None:
            name, lines, size = await _validated_lines(config, is_rule=False)
            if name.casefold() in seen_names:
                raise HTTPException(status_code=400, detail="Duplicate uploaded filename.")
            if platform == "snort" and Path(name).suffix.lower() in (".yaml", ".yml"):
                raise HTTPException(status_code=400, detail="Snort configuration must be .conf, .cfg, or .txt.")
            total_bytes += size
            if total_bytes > MAX_COMBINED_BYTES:
                raise HTTPException(status_code=413, detail="Combined upload exceeds 4 MiB limit.")
            try:
                selected = select_platform(lines, _registry, platform)
            except PlatformDetectionError as error:
                raise HTTPException(status_code=422, detail={"code": error.code, "message": str(error)}) from None
            if selected.platform_id != platform:
                raise HTTPException(status_code=422, detail="Configuration platform mismatch.")
            validated_config = (name, lines)

        return analyze_ids_rule_bundle(platform=platform, rule_files=validated_rules, config=validated_config)
    finally:
        for uploaded_file in uploaded:
            if uploaded_file is not None:
                await uploaded_file.close()
