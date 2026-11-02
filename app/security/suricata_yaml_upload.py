"""Narrow .yaml/.yml reader with the same text bounds as existing IDS uploads.

This reader does NOT deserialize YAML. It only verifies input bytes, leaving
restricted interpretation to the SuricataParser. No filesystem paths are opened.
"""

from pathlib import Path

from fastapi import HTTPException, UploadFile
from app.security import untrusted_config


async def read_suricata_yaml_upload(file: UploadFile) -> str:
    if Path(file.filename or "").suffix.lower() not in (".yaml", ".yml"):
        raise HTTPException(status_code=400, detail="Expected a .yaml or .yml file.")
    max_bytes = untrusted_config.MAX_UPLOAD_BYTES
    raw = await file.read(max_bytes + 1)
    if len(raw) > max_bytes:
        raise HTTPException(status_code=413, detail="Configuration exceeds upload size limit.")
    if not raw:
        raise HTTPException(status_code=400, detail="Configuration file is empty.")
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="Configuration must be UTF-8 encoded.") from None
    if not text.strip():
        raise HTTPException(status_code=400, detail="Configuration contains no text.")
    if any((ord(c) < 32 and c not in "\n\r\t") or ord(c) == 127 for c in text):
        raise HTTPException(status_code=400, detail="Configuration contains invalid control characters.")
    lines = text.splitlines()
    if len(lines) > untrusted_config.MAX_CONFIG_LINES or any(
        len(line) > untrusted_config.MAX_LINE_LENGTH for line in lines
    ):
        raise HTTPException(status_code=413, detail="Configuration exceeds structural size limits.")
    return text
