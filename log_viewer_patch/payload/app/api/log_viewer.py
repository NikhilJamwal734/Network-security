"""Local-only, read-only JSONL audit log viewer for FirewallAnalyzer.

Reads ONLY the five managed log streams. Does not expose arbitrary file paths,
raw log lines, or authentication material. No changes to detection logic.
"""
from __future__ import annotations

from collections import deque
from datetime import datetime, timezone
import ipaddress
import json
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

from fastapi import APIRouter, HTTPException, Query, Request, Response
from app.core.audit_logging import BACKUPS, STREAMS, log_directory

router = APIRouter(tags=["Local Audit Logs"])
LogStream = Literal["application", "api_access", "upload_audit", "security_analysis", "error"]

_STR_FIELDS = ("timestamp_utc", "event", "filename", "platform", "route", "method", "code", "error_type", "request_id")
_NUM_FIELDS = ("status_code", "finding_count", "size_bytes", "duration_ms")


def _is_local(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_loopback
    except ValueError:
        return False


def _origin_is_local(origin: str) -> bool:
    """Browser UI is supported on a loopback HTTP(S) origin only."""
    try:
        result = urlsplit(origin)
        return (result.scheme in ("http", "https") and
                result.hostname in ("localhost", "127.0.0.1", "::1") and
                result.username is None and result.password is None and
                result.path in ("", "/") and not result.query and not result.fragment)
    except ValueError:
        return False


def _level(entry: dict[str, Any]) -> str:
    event = str(entry.get("event", "")).lower()
    status = entry.get("status_code")
    if event in ("api_failure", "analysis_failed", "upload_rejected") or (isinstance(status, int) and status >= 500):
        return "error"
    if "warning" in event or (isinstance(status, int) and status >= 400):
        return "warning"
    if event in ("analysis_completed", "upload_accepted"):
        return "success"
    return "info"


def _clean_record(raw: Any) -> dict[str, Any] | None:
    if not isinstance(raw, dict):
        return None
    event = raw.get("event")
    if not isinstance(event, str) or not event or len(event) > 64:
        return None
    clean: dict[str, Any] = {}
    for key in _STR_FIELDS:
        value = raw.get(key)
        if isinstance(value, str):
            # Drop control characters and bound values; never echo unknown keys.
            clean[key] = "".join(ch for ch in value[:200] if ch.isprintable())
    for key in _NUM_FIELDS:
        value = raw.get(key)
        if isinstance(value, (int, float)) and not isinstance(value, bool) and 0 <= value < 1_000_000_000:
            clean[key] = value
    clean["level"] = _level(clean)
    return clean


def read_recent(stream: LogStream, limit: int = 100) -> list[dict[str, Any]]:
    """Return newest-first entries across active and rotated log files."""
    if stream not in STREAMS or not 1 <= limit <= 500:
        raise ValueError("Invalid log stream or limit")
    folder = log_directory()
    if folder.is_symlink():
        return []
    result: list[dict[str, Any]] = []
    # Active file is newest; backups .1, .2, ... are progressively older.
    for name in (f"{stream}.log", *(f"{stream}.log.{n}" for n in range(1, BACKUPS + 1))):
        path: Path = folder / name
        if path.is_symlink() or not path.is_file():
            continue
        # A bounded memory tail per file; each rotated file is capped by writer.
        try:
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                lines = deque(handle, maxlen=limit)
            for line in reversed(lines):
                try:
                    entry = _clean_record(json.loads(line))
                except (ValueError, TypeError):
                    continue
                if entry is not None:
                    result.append(entry)
                if len(result) == limit:
                    return result
        except (OSError, PermissionError):
            continue
    return result


@router.get("/api/v1/logs")
async def list_logs(
    request: Request,
    response: Response,
    stream: LogStream = Query(default="security_analysis"),
    limit: int = Query(default=100, ge=1, le=500),
) -> dict[str, Any]:
    """Local-only operations dashboard; do NOT publish without real authentication."""
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    if request.client is None or not _is_local(request.client.host):
        raise HTTPException(status_code=403, detail="Log viewer is limited to the local machine")
    origin = request.headers.get("origin")
    if origin is not None and not _origin_is_local(origin):
        raise HTTPException(status_code=403, detail="Only local browser origins may read logs")
    events = read_recent(stream, limit)
    return {
        "stream": stream,
        "entries": events,
        "count": len(events),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
