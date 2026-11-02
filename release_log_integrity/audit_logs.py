"""Optional, offline FirewallAnalyzer log integrity snapshots.

No application hooks, no log mutation, no secret data written to the report.
Requires a separate HMAC key and a signed manifest saved outside the log folder.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import sys
from datetime import datetime, timezone

STREAMS = ("application", "api_access", "upload_audit", "security_analysis", "error")
MAX_BACKUPS = 3
MAX_FILE_BYTES = 16 * 1024 * 1024
PATTERN = re.compile(r"^(?:application|api_access|upload_audit|security_analysis|error)\.log(?:\.[1-3])?$")
SCHEMA = "firewall-analyzer-log-snapshot-v1"


class AuditError(Exception):
    """Expected operational or input error."""


def default_logs() -> Path:
    base = os.environ.get("LOCALAPPDATA")
    if not base:
        return Path.home() / "AppData" / "Local" / "FirewallAnalyzer" / "logs"
    return Path(base) / "FirewallAnalyzer" / "logs"


def safe_path(path: Path, kind: str) -> Path:
    path = path.expanduser().absolute()
    # Treat symlinked and junction/reparse-point path components as untrusted.
    for part in (path, *path.parents):
        if part.is_symlink() or (hasattr(part, 'is_junction') and part.is_junction()):
            raise AuditError(f"Refusing symlink or junction in {kind} path")
    return path


def read_key(path: Path) -> bytes:
    path = safe_path(path, "key file")
    try:
        content = path.read_bytes()
    except OSError as exc:
        raise AuditError("Cannot read HMAC key file") from exc
    if len(content) != 32:
        raise AuditError("HMAC key must contain exactly 32 random bytes")
    return content


def read_inventory(folder: Path) -> dict[str, dict]:
    folder = safe_path(folder, "log directory")
    if not folder.is_dir():
        raise AuditError("Log directory not found; create logs by running the EXE first")
    inventory = {}
    for p in folder.iterdir():
        if not PATTERN.fullmatch(p.name):
            continue
        if p.is_symlink() or (hasattr(p, 'is_junction') and p.is_junction()):
            raise AuditError(f"Refusing symlinked or junction log file: {p.name}")
        if not p.is_file():
            raise AuditError(f"Managed log path is not a regular file: {p.name}")
        try:
            before = p.stat()
            if before.st_size > MAX_FILE_BYTES:
                raise AuditError(f"Log file too large for bounded snapshot: {p.name}")
            sha = hashlib.sha256()
            nbytes = 0
            lines = 0
            malformed = 0
            with p.open("rb") as handle:
                for raw_line in handle:
                    nbytes += len(raw_line)
                    if nbytes > MAX_FILE_BYTES:
                        raise AuditError(f"Log file changed beyond snapshot bound: {p.name}")
                    sha.update(raw_line)
                    if raw_line.strip():
                        lines += 1
                        try:
                            record = json.loads(raw_line)
                            if not isinstance(record, dict) or not isinstance(record.get('event'), str):
                                malformed += 1
                        except (UnicodeError, ValueError):
                            malformed += 1
            after = p.stat()
        except OSError as exc:
            raise AuditError(f"Unable to read log file safely: {p.name}") from exc
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns) or nbytes != after.st_size:
            raise AuditError(f"Log changed while being scanned: {p.name}; stop EXE and retry")
        inventory[p.name] = {"bytes": nbytes, "sha256": sha.hexdigest(),
                             "jsonl_records": lines, "malformed_jsonl_records": malformed}
    if not inventory:
        raise AuditError("No managed FirewallAnalyzer log files found")
    return dict(sorted(inventory.items()))


def canonical(payload: dict) -> bytes:
    return json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign(payload: dict, key: bytes) -> str:
    return hmac.new(key, canonical(payload), hashlib.sha256).hexdigest()


def write_new_file(path: Path, data: bytes) -> None:
    path = safe_path(path, "output file")
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        # Avoid silently resetting the anchor by replacing an existing manifest or key.
        with path.open("xb") as out:
            out.write(data)
    except FileExistsError as exc:
        raise AuditError("Output already exists; choose a new filename (existing anchor preserved)") from exc
    except OSError as exc:
        raise AuditError("Cannot create output file") from exc


def init_key(path: Path) -> dict:
    path = safe_path(path, "key file")
    write_new_file(path, secrets.token_bytes(32))
    return {"status": "PASS", "operation": "init-key", "message": "Key created; protect it with NTFS permissions and an offline backup"}


def snapshot(logs: Path, manifest: Path, key_path: Path) -> dict:
    logs = safe_path(logs, "log directory")
    manifest = safe_path(manifest, "manifest")
    if manifest.parent == logs or logs in manifest.parents:
        raise AuditError("Store the manifest outside the logs directory")
    key_path = safe_path(key_path, "key file")
    if key_path.parent == logs or logs in key_path.parents:
        raise AuditError("Store the HMAC key outside the logs directory")
    key = read_key(key_path)
    inventory = read_inventory(logs)
    data = {"schema": SCHEMA,
            "created_utc": datetime.now(timezone.utc).isoformat(timespec='seconds'),
            "files": inventory}
    envelope = {"payload": data, "hmac_sha256": sign(data, key)}
    write_new_file(manifest, canonical(envelope) + b"\n")
    return {"status": "PASS", "operation": "snapshot", "managed_files": len(inventory),
            "malformed_jsonl_records": sum(v['malformed_jsonl_records'] for v in inventory.values()),
            "message": "Signed snapshot created. Copy manifest and key securely off-host; do not share key."}


def verify(logs: Path, manifest: Path, key_path: Path) -> dict:
    key = read_key(key_path)
    manifest = safe_path(manifest, "manifest")
    try:
        raw = manifest.read_bytes()
        if len(raw) > 256_000:
            raise AuditError("Manifest exceeds size limit")
        envelope = json.loads(raw)
    except (OSError, UnicodeError, ValueError, TypeError) as exc:
        raise AuditError("Manifest cannot be read as valid JSON") from exc
    if not isinstance(envelope, dict) or set(envelope) != {"payload", "hmac_sha256"}:
        raise AuditError("Invalid signed manifest structure")
    payload = envelope["payload"]
    signature = envelope["hmac_sha256"]
    if not isinstance(payload, dict) or payload.get("schema") != SCHEMA or not isinstance(signature, str):
        raise AuditError("Manifest schema or signature invalid")
    if not hmac.compare_digest(sign(payload, key), signature):
        return {"status": "FAIL", "operation": "verify", "issue": "MANIFEST_SIGNATURE_INVALID"}
    expected = payload.get("files")
    if not isinstance(expected, dict) or any(not PATTERN.fullmatch(k) for k in expected):
        raise AuditError("Manifest file inventory invalid")
    actual = read_inventory(logs)
    missing = sorted(set(expected) - set(actual))
    added = sorted(set(actual) - set(expected))
    modified = sorted(k for k in set(expected) & set(actual) if expected[k] != actual[k])
    issues = {"missing": missing, "new": added, "modified": modified}
    return {"status": "PASS" if not any(issues.values()) else "FAIL",
            "operation": "verify", "managed_files": len(actual), **issues,
            "message": "Exact offline snapshot comparison; ordinary appends/rotation will cause differences"}


def run_cli(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    key = sub.add_parser("init-key", help="Create a new random 256-bit HMAC key (never overwrites)")
    key.add_argument("--key-file", type=Path, required=True)
    for action in ("snapshot", "verify"):
        p = sub.add_parser(action, help=f"{action} an exact offline log snapshot")
        p.add_argument("--logs-dir", type=Path, default=default_logs())
        p.add_argument("--manifest", type=Path, required=True)
        p.add_argument("--key-file", type=Path, required=True)
        p.add_argument("--out", type=Path, default=None, help="Optional JSON result output (outside logs)")
    args = parser.parse_args(argv)
    try:
        if args.action == "init-key":
            report = init_key(args.key_file)
        elif args.action == "snapshot":
            report = snapshot(args.logs_dir, args.manifest, args.key_file)
        else:
            report = verify(args.logs_dir, args.manifest, args.key_file)
        if getattr(args, "out", None) is not None:
            write_new_file(args.out, canonical(report) + b"\n")
        print(json.dumps(report, indent=2))
        return 0 if report['status'] == 'PASS' else 1
    except AuditError as exc:
        print(json.dumps({"status": "INCOMPLETE", "issue": str(exc)}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(run_cli())
