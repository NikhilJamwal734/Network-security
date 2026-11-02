"""Restricted .rules upload reader for Snort (API-009.4).

The existing API-008 reader remains the authority for .conf/.cfg/.txt.
This reader only extends upload support to .rules, enforcing the shared
2 MiB, UTF-8, control-character, line-count and line-length limits.
"""

from fastapi import HTTPException, UploadFile

from app.security import untrusted_config


async def read_snort_rules_upload(file: UploadFile) -> str:
    if not (file.filename or "").lower().endswith(".rules"):
        raise HTTPException(status_code=400, detail="Expected a .rules file.")

    max_bytes = untrusted_config.MAX_UPLOAD_BYTES
    max_lines = untrusted_config.MAX_CONFIG_LINES
    max_line_length = untrusted_config.MAX_LINE_LENGTH

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
    if any((ord(char) < 32 and char not in "\n\r\t") or ord(char) == 127 for char in text):
        raise HTTPException(status_code=400, detail="Configuration contains invalid control characters.")
    lines = text.splitlines()
    if len(lines) > max_lines or any(len(line) > max_line_length for line in lines):
        raise HTTPException(status_code=413, detail="Configuration exceeds structural size limits.")
    return text
