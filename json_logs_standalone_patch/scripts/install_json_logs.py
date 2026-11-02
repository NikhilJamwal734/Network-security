"""Safely install independent JSON-coloured logs page.

Does NOT touch the existing frontend/src/App.tsx or sidebar. The Logs page
is accessible at http://localhost:5173/logs.html during Vite development.

Adds a single, read-only router to app/api/main.py and only creates
new files; never overwrites customized existing files. Manifested rollback.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import shutil
import sys

HERE = Path(__file__).resolve().parents[1]
PAYLOAD = HERE / "payload"
MANIFEST = Path(".json_logs_standalone_manifest.json")
BACKUP = Path(".json_logs_standalone_backup")
MAIN = Path("app/api/main.py")
PREREQUISITES = (MAIN, Path("app/core/audit_logging.py"), Path("frontend/src/App.tsx"), Path("frontend/src/index.css"))
ADDED = (
    Path("app/api/log_viewer.py"),
    Path("frontend/src/api/logs.ts"),
    Path("frontend/src/pages/Logs.tsx"),
    Path("frontend/src/pages/Logs.css"),
    Path("frontend/src/logs-main.tsx"),
    Path("frontend/logs.html"),
    Path("tools/Watch-FirewallLogs.ps1"),
)
START = "# JSON_LOGS_VIEWER_START"
END = "# JSON_LOGS_VIEWER_END"
PATCH_ID = "json-logs-standalone-v1"


def _sha(data: bytes) -> str:
    return sha256(data).hexdigest()


def _safe(root: Path, relative: Path) -> Path:
    if relative.is_absolute() or any(p in (".", "..") for p in relative.parts):
        raise ValueError("Unsafe project relative path")
    target = root / relative
    if target.is_symlink() or not target.resolve().is_relative_to(root.resolve()):
        raise ValueError(f"Refusing symlink or external path: {relative}")
    return target


def _read(raw: bytes) -> tuple[str, bool, str]:
    bom = raw.startswith(b"\xef\xbb\xbf")
    body = raw.decode("utf-8-sig")
    if "\r" in body.replace("\r\n", "") or ("\r\n" in body and "\n" in body.replace("\r\n", "")):
        raise ValueError("Unsupported mixed line endings in app/api/main.py")
    newline = "\r\n" if "\r\n" in body else "\n"
    return body.replace("\r\n", "\n"), bom, newline


def _patch_main(raw: bytes) -> bytes:
    body, bom, newline = _read(raw)
    if START in body or END in body:
        if body.count(START) == 1 and body.count(END) == 1:
            return raw
        raise ValueError("Partial JSON Logs router integration in main.py")
    if re.search(r"\bfrom\s+app\.api\.log_viewer\s+import\b", body):
        raise ValueError("An existing log viewer import already exists; verify manually")
    if re.search(r"(?m)^\s*app\.include_router\s*\(\s*local_audit_logs_router", body):
        raise ValueError("An existing log viewer router registration already exists")
    # Avoid writing to a module which does not expose a FastAPI app variable.
    if not re.search(r"(?m)^\s*app\s*=\s*FastAPI\s*\(", body):
        raise ValueError("No `app = FastAPI(...)` found in main.py; not changing it")
    if re.search(r"(?m)^\s*if\s+__name__\s*==", body):
        raise ValueError("main.py contains a __main__ block; manual router wiring required")
    insertion = (
        f"\n{START}\n"
        "# Read-only, localhost-restricted structured log viewer.\n"
        "from app.api.log_viewer import router as json_audit_logs_router\n"
        "app.include_router(json_audit_logs_router)\n"
        f"{END}\n"
    )
    result = body.rstrip("\n") + insertion
    return (b"\xef\xbb\xbf" if bom else b"") + result.replace("\n", newline).encode("utf-8")


def _plan(project: Path) -> dict[Path, bytes]:
    for rel in PREREQUISITES:
        if not _safe(project, rel).is_file():
            raise ValueError(f"Required existing project file missing: {rel.as_posix()}")
    changes: dict[Path, bytes] = {}
    original_main = _safe(project, MAIN).read_bytes()
    new_main = _patch_main(original_main)
    if new_main != original_main:
        changes[MAIN] = new_main
    for rel in ADDED:
        source = _safe(PAYLOAD, rel)
        if not source.is_file():
            raise ValueError(f"Installer payload missing: {rel.as_posix()}")
        content = source.read_bytes()
        destination = _safe(project, rel)
        if destination.exists():
            if not destination.is_file() or destination.read_bytes() != content:
                raise ValueError(f"Existing file would be overwritten: {rel.as_posix()}; no changes made")
        else:
            changes[rel] = content
    return changes


def _load_manifest(project: Path) -> dict:
    path = _safe(project, MANIFEST)
    if not path.is_file():
        raise ValueError("JSON Logs installer manifest not found")
    manifest = json.loads(path.read_text(encoding="utf-8"))
    allowed = {MAIN.as_posix()} | {p.as_posix() for p in ADDED}
    if manifest.get("patch") != PATCH_ID or not isinstance(manifest.get("files"), dict) or not set(manifest["files"]).issubset(allowed):
        raise ValueError("Unrecognized or invalid installation manifest")
    for name, meta in manifest["files"].items():
        p = _safe(project, Path(name))
        if not p.is_file() or _sha(p.read_bytes()) != meta.get("after"):
            raise ValueError(f"File changed after installation: {name}")
    return manifest


def install(project: Path) -> list[str]:
    project = project.resolve()
    if not project.is_dir():
        raise ValueError("Project path does not exist")
    if _safe(project, MANIFEST).exists():
        _load_manifest(project)
        return []
    changes = _plan(project)  # All validation before any project writes.
    if _safe(project, BACKUP).exists():
        raise ValueError("Preexisting backup directory; inspect it before retrying")
    if not changes:
        return []
    before: dict[Path, bytes | None] = {}
    for rel in changes:
        target = _safe(project, rel)
        before[rel] = target.read_bytes() if target.exists() else None
    manifest = {rel.as_posix(): {"before": (_sha(before[rel]) if before[rel] is not None else None), "after": _sha(blob)}
                for rel, blob in changes.items()}
    backup = _safe(project, BACKUP)
    backup.mkdir()
    written: list[Path] = []
    try:
        for rel, old in before.items():
            if old is not None:
                dest = _safe(backup, rel)
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(old)
        for rel, content in changes.items():
            dst = _safe(project, rel)
            dst.parent.mkdir(parents=True, exist_ok=True)
            temp = dst.with_name(dst.name + ".json_logs.tmp")
            if temp.exists() or temp.is_symlink():
                raise ValueError(f"Existing temporary installation file: {temp}")
            temp.write_bytes(content)
            os.replace(temp, dst)
            written.append(rel)
        _safe(project, MANIFEST).write_text(json.dumps({"patch": PATCH_ID, "files": manifest}, indent=2) + "\n", encoding="utf-8")
    except Exception:
        for rel in reversed(written):
            target = _safe(project, rel)
            if before[rel] is None:
                target.unlink(missing_ok=True)
            else:
                target.write_bytes(before[rel])
        shutil.rmtree(backup, ignore_errors=True)
        raise
    return [rel.as_posix() for rel in changes]


def rollback(project: Path) -> list[str]:
    project = project.resolve()
    manifest = _load_manifest(project)
    restores: dict[Path, bytes | None] = {}
    for name, info in manifest["files"].items():
        rel = Path(name)
        if info["before"] is None:
            restores[rel] = None
            continue
        bak = _safe(project, BACKUP / rel)
        if not bak.is_file():
            raise ValueError(f"Missing backup for {name}")
        data = bak.read_bytes()
        if _sha(data) != info["before"]:
            raise ValueError(f"Backup checksum mismatch: {name}")
        restores[rel] = data
    for rel, data in restores.items():
        dst = _safe(project, rel)
        if data is None:
            dst.unlink()
        else:
            dst.write_bytes(data)
    shutil.rmtree(_safe(project, BACKUP))
    _safe(project, MANIFEST).unlink()
    return [p.as_posix() for p in restores]


def main() -> int:
    p = argparse.ArgumentParser(description="Install isolated JSON log viewer without touching App.tsx")
    p.add_argument("project", nargs="?", type=Path, default=Path("."))
    p.add_argument("--rollback", action="store_true")
    args = p.parse_args()
    try:
        changed = rollback(args.project) if args.rollback else install(args.project)
    except (OSError, ValueError, UnicodeError, KeyError, json.JSONDecodeError) as exc:
        print("ERROR:", exc, file=sys.stderr)
        return 1
    print(("Restored" if args.rollback else "Installed") + ":")
    for item in changed:
        print(" ", item)
    if not args.rollback:
        print("Your existing App.tsx was NOT changed.")
        print("Start backend and `npm run dev` in frontend/, then open http://localhost:5173/logs.html")
        print("Only JSON-line syntax highlighting is used; original audit logs are unchanged.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
