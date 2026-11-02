"""Privacy-preserving JSONL audit logging for FirewallAnalyzer API 12.

Does not log request/response bodies, configuration text, filenames, raw URLs,
headers, credentials or client addresses. Single-process rotating files only.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import re
import sys
import threading
import time

STREAMS = ('application', 'api_access', 'upload_audit', 'security_analysis', 'error')
MAX_BYTES = 2 * 1024 * 1024
BACKUPS = 3
_LOCK = threading.RLock()
_LOGGERS: dict[str, logging.Logger] = {}
_SAFE_CODES = re.compile(r'^[A-Za-z0-9_\-]{1,64}$')
_SAFE_PLATFORM = frozenset({'cisco_asa', 'fortios', 'snort', 'suricata', 'auto', 'unknown'})
_API_ROUTES = frozenset({
    '/api/v1/analyze/hardened', '/api/v1/analyze/pipeline-validation',
    '/api/v1/analyze/pdf-readiness', '/api/v1/analyze/report-validation',
    '/api/v1/analyze/correlation-accuracy', '/api/v1/analyze/consolidated',
    '/api/v1/release/status', '/api/health', '/api/report',
})


def log_directory() -> Path:
    """Source checkout: <project>/logs; packaged EXE: user's LocalAppData."""
    if getattr(sys, 'frozen', False):
        base = Path(os.environ.get('LOCALAPPDATA') or Path.home() / 'AppData' / 'Local')
        return base / 'FirewallAnalyzer' / 'logs'
    return Path(__file__).resolve().parents[2] / 'logs'


def _logger(stream: str) -> logging.Logger:
    if stream not in STREAMS:
        raise ValueError('Unknown logging stream')
    with _LOCK:
        if stream in _LOGGERS:
            return _LOGGERS[stream]
        folder = log_directory()
        folder.mkdir(parents=True, exist_ok=True)
        # Existing symlinked logs would allow file writes outside the intended directory.
        if folder.is_symlink():
            raise OSError('Log directory must not be a symlink')
        path = folder / (stream + '.log')
        if path.is_symlink():
            raise OSError('Refusing a symlinked log file')
        logger = logging.getLogger('firewall_analyzer.audit.' + stream)
        logger.setLevel(logging.INFO)
        logger.propagate = False
        handler = RotatingFileHandler(
            path, maxBytes=MAX_BYTES, backupCount=BACKUPS, encoding='utf-8', delay=True,
        )
        handler.setFormatter(logging.Formatter('%(message)s'))
        logger.addHandler(handler)
        _LOGGERS[stream] = logger
        return logger


def _clean_fields(fields: dict) -> dict:
    # Explicit allowlist; don't accidentally persist raw config, paths or secrets.
    safe: dict = {}
    for key in ('request_id', 'code', 'error_type'):
        value = fields.get(key)
        if isinstance(value, str) and _SAFE_CODES.fullmatch(value):
            safe[key] = value
    platform = fields.get('platform')
    if platform in _SAFE_PLATFORM:
        safe['platform'] = platform
    route = fields.get('route')
    if route in _API_ROUTES or route == 'other_api':
        safe['route'] = route
    method = fields.get('method')
    if method in ('GET', 'POST', 'OPTIONS', 'PUT', 'PATCH', 'DELETE'):
        safe['method'] = method
    for key in ('status_code', 'finding_count', 'size_bytes', 'duration_ms'):
        value = fields.get(key)
        if isinstance(value, (int, float)) and not isinstance(value, bool) and 0 <= value < 1_000_000_000:
            safe[key] = round(value, 2) if isinstance(value, float) else value
    return safe


def audit_event(stream: str, event: str, **fields) -> None:
    """Write a bounded, structured JSON record; fail safe if disk logging breaks."""
    if not isinstance(event, str) or not _SAFE_CODES.fullmatch(event):
        raise ValueError('Invalid audit event')
    record = {
        'timestamp_utc': datetime.now(timezone.utc).isoformat(timespec='milliseconds'),
        'event': event,
        **_clean_fields(fields),
    }
    try:
        _logger(stream).info(json.dumps(record, ensure_ascii=True, separators=(',', ':')))
    except (OSError, PermissionError) as exc:
        # Logging failures must be visible, but must not leak confidential data.
        sys.stderr.write('FirewallAnalyzer: audit log unavailable (' + type(exc).__name__ + ').\n')


class AccessAuditMiddleware:
    """ASGI middleware; observes status without reading request or response bodies."""

    def __init__(self, app):
        self.app = app
        audit_event('application', 'logging_initialized')

    async def __call__(self, scope, receive, send):
        if scope.get('type') != 'http':
            return await self.app(scope, receive, send)
        path = scope.get('path', '')
        if not isinstance(path, str) or not path.startswith('/api/'):
            return await self.app(scope, receive, send)
        route = path if path in _API_ROUTES else 'other_api'
        started = time.perf_counter()
        status = 500
        error_type = None

        async def send_status(message):
            nonlocal status
            if message['type'] == 'http.response.start':
                status = int(message.get('status', 500))
            await send(message)

        try:
            return await self.app(scope, receive, send_status)
        except Exception as exc:
            error_type = type(exc).__name__
            raise
        finally:
            took = round((time.perf_counter() - started) * 1000, 2)
            audit_event('api_access', 'http_request', route=route, method=scope.get('method'),
                        status_code=status, duration_ms=took)
            if status >= 500 or error_type is not None:
                audit_event('error', 'api_failure', route=route, status_code=status,
                            error_type=error_type or 'HTTPError')
