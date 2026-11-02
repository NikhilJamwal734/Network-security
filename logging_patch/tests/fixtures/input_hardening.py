"""API-011.6: bounded, fail-closed validation for a *single* text configuration.

This module checks the uploaded bytes, not the safety/accuracy of configuration
rules. It does not replace framework-level multipart/body size enforcement.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256

MAX_CONFIG_BYTES = 8 * 1024 * 1024
MAX_FILENAME_UTF8_BYTES = 255
MAX_LINES = 250_000
MAX_LINE_LENGTH = 32_768
PLATFORMS = frozenset({'cisco_asa', 'fortios', 'snort', 'suricata'})
MAGIC_PREFIXES = (b'PK\x03\x04', b'PK\x05\x06', b'\x1f\x8b', b'\x7fELF', b'%PDF-', b'MZ', b'\xff\xfe', b'\xfe\xff', b'\x00\x00\xfe\xff', b'\xff\xfe\x00\x00')


@dataclass(frozen=True)
class InputProblem(ValueError):
    code: str
    message: str
    status_code: int = 422

    def __str__(self) -> str:
        return self.message


def check_platform(value: str | None) -> None:
    if value is not None and value not in PLATFORMS:
        raise InputProblem('unsupported_platform', 'Unsupported platform. Choose a supported platform identifier or omit the parameter.')


def check_filename(name: str | None) -> None:
    if not isinstance(name, str) or not name:
        raise InputProblem('invalid_filename', 'Invalid or missing configuration filename.')
    try:
        encoded_name = name.encode('utf-8', errors='strict')
    except UnicodeError:
        raise InputProblem('invalid_filename', 'Invalid UTF-8 configuration filename.') from None
    if len(encoded_name) > MAX_FILENAME_UTF8_BYTES:
        raise InputProblem('invalid_filename', 'Configuration filename is too long.')
    if (name in ('.', '..') or name.strip() != name or name.endswith('.') or
            any(c in name for c in ('/', '\\', ':')) or
            any(ord(c) < 32 or ord(c) == 127 for c in name)):
        raise InputProblem('invalid_filename', 'Configuration filename must be a plain basename without control characters.')


def inspect_config_bytes(data: bytes, *, filename: str | None, platform: str | None) -> dict:
    """Return a bounded evidence summary. NEVER embed the original input or filename."""
    check_platform(platform)
    check_filename(filename)
    if not isinstance(data, bytes):
        raise InputProblem('invalid_data', 'Uploaded configuration must contain bytes.')
    if not data or not data.strip():
        raise InputProblem('empty_upload', 'Configuration file is empty.')
    if len(data) > MAX_CONFIG_BYTES:
        raise InputProblem('upload_too_large', f'Configuration exceeds {MAX_CONFIG_BYTES // (1024*1024)} MiB upload limit.', 413)
    if data.startswith(MAGIC_PREFIXES):
        raise InputProblem('binary_input', 'Binary, archived, or non-UTF-8 configuration is unsupported.')
    try:
        content = data.decode('utf-8-sig', errors='strict')
    except UnicodeDecodeError:
        raise InputProblem('invalid_encoding', 'Configuration must be valid UTF-8 (optional UTF-8 BOM).') from None
    if not content.strip():
        raise InputProblem('empty_upload', 'Configuration contains no meaningful text.')
    if any(ord(ch) < 32 and ch not in ('\t', '\n', '\r') or ord(ch) == 127 for ch in content):
        raise InputProblem('unexpected_control', 'Configuration contains unsupported control characters.')
    # splitlines() is safe after the bounded byte check; limit whole lines to
    # reduce pathological parser work without silently truncating evidence.
    lines = content.splitlines()
    if len(lines) > MAX_LINES:
        raise InputProblem('too_many_lines', 'Configuration has too many lines for this release.', 413)
    if any(len(line) > MAX_LINE_LENGTH for line in lines):
        raise InputProblem('overlong_line', 'Configuration has a line longer than the supported limit.', 413)
    return {
        'version': '1.0', 'status': 'accepted', 'scope': 'single_file_text_input_precheck',
        'summary': {'byte_count': len(data), 'line_count': len(lines), 'checks_passed': 6},
        'sha256': sha256(data).hexdigest(),
        'checks': [
            {'name': 'filename_basename', 'result': 'pass'},
            {'name': 'platform_identifier', 'result': 'pass'},
            {'name': 'bounded_upload_size', 'result': 'pass'},
            {'name': 'nonempty_text', 'result': 'pass'},
            {'name': 'utf8_and_nonbinary', 'result': 'pass'},
            {'name': 'line_and_control_limits', 'result': 'pass'},
        ],
        'limitations': [
            'Only the API-011.6 endpoint performs these checks; older API entry points remain available unless separately restricted.',
            'Multipart parsing happens before this handler. Configure request-body limits at the reverse proxy or ASGI server.',
            'These checks do not prove the configuration is safe, the parser is resource-bounded, or the security findings are accurate.',
            'The upload is processed by the existing API-011.4 analysis chain after validation.',
        ],
    }
