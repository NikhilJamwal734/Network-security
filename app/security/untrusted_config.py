
"""
Validate untrusted Cisco ASA configuration uploads.

SECURITY RULE:
Uploaded configuration content is text data only.

This module NEVER executes uploaded text, SQL,
shell commands, Python code, or ASA CLI commands.
"""

from pathlib import PurePath

from fastapi import HTTPException, UploadFile


MAX_UPLOAD_BYTES = 2 * 1024 * 1024
MAX_CONFIG_LINES = 50_000
MAX_LINE_LENGTH = 16_384

ALLOWED_EXTENSIONS = {
    ".conf",
    ".cfg",
    ".txt",
}


async def read_untrusted_config(
    upload: UploadFile,
) -> str:
    """
    Read an uploaded firewall configuration as plain text.

    Returns:
        A validated Python string, not executable code.

    Raises:
        HTTPException for invalid uploads.
    """

    # Normalize path separators, but never use the
    # uploaded filename to create or execute a file.
    filename = (
        (upload.filename or "")
        .replace("\\", "/")
        .rsplit("/", 1)[-1]
    )

    if not filename:
        raise HTTPException(
            status_code=400,
            detail="Missing configuration filename.",
        )

    extension = PurePath(filename).suffix.lower()

    if extension not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=(
                "Unsupported file type. "
                "Use .conf, .cfg, or .txt."
            ),
        )

    # Read only up to the limit plus one byte.
    # Never load an arbitrarily large upload.
    raw = await upload.read(MAX_UPLOAD_BYTES + 1)

    if len(raw) == 0:
        raise HTTPException(
            status_code=400,
            detail="Configuration file is empty.",
        )

    if len(raw) > MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail="Configuration exceeds 2 MiB.",
        )

    try:
        # Strict decoding: invalid byte sequences
        # are not silently replaced or ignored.
        config_text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise HTTPException(
            status_code=400,
            detail="Configuration must use valid UTF-8.",
        ) from exc

    if not config_text.strip():
        raise HTTPException(
            status_code=400,
            detail="Configuration contains only whitespace.",
        )

    # Reject binary/control characters, but allow
    # ordinary text, spaces, tabs, and line endings.
    for character in config_text:
        code = ord(character)

        if (
            code < 32
            and character not in "\t\n\r"
        ) or code == 127:
            raise HTTPException(
                status_code=400,
                detail=(
                    "Configuration contains invalid "
                    "control characters."
                ),
            )

    lines = config_text.splitlines()

    if len(lines) > MAX_CONFIG_LINES:
        raise HTTPException(
            status_code=413,
            detail="Configuration has too many lines.",
        )

    if any(
        len(line) > MAX_LINE_LENGTH
        for line in lines
    ):
        raise HTTPException(
            status_code=413,
            detail="Configuration contains an excessively long line.",
        )

    # SQL and shell-looking strings remain untouched.
    # They are returned as plain text, never executed.
    return config_text
