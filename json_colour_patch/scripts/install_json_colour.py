"""UI-only JSON colour enhancement for FirewallAnalyzer Logs page.

Replaces ONLY Logs.tsx and Logs.css from the previously distributed
Color-Logs-Viewer patch, preserving originals for rollback. Never edits API,
logs, dashboard, security logic, or App.tsx.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import zipfile

HERE = Path(__file__).resolve().parents[1]
PAYLOAD = HERE / "payload"
TARGETS = (
    Path("frontend/src/pages/Logs.tsx"),
    Path("frontend/src/pages/Logs.css"),
)
MANIFEST = Path(".logs_json_colour_manifest.json")
BACKUP_DIR = Path(".logs_json_colour_backup")

# Known hashes of the original Logs files from FirewallAnalyzer-Color-Logs-Viewer.zip.
# These are normalized to LF to support Windows CRLF and optional UTF-8 BOM.
BASELINE_SHA256 = {
    "frontend/src/pages/Logs.tsx": "33d89774103c0bb30eed5930c3626770040f07dc4fd7f6e60433f792ab6d8faa",
    "frontend/src/pages/Logs.css": "6e1f4a2fef69195f6fd9ffbd8d46a4872cddc76c790e31de9e8bc0f3b2d518bc",
}


def _hash(data: bytes) -> str:
    return sha256(data).hexdigest()


def _read_normalized(raw: bytes) -> tuple[bytes, bool, str]:
    bom = raw.startswith(b"\xef\xbb\xbf")
    value = raw.decode("utf-8-sig")
    if "\r" in value.replace("\r\n", "") or ("\r\n" in value and "\n" in value.replace("\r\n", "")):
        raise ValueError("Mixed or invalid line endings; no files changed")
    newline = "\r\n" if "\r\n" in value else "\n"
    return value.replace("\r\n", "\n").encode("utf-8"), bom, newline


def _render(payload: bytes, bom: bool, newline: str) -> bytes:
    normalized, _, _ = _read_normalized(payload)
    text = normalized.decode("utf-8").replace("\n", newline)
    return (b"\xef\xbb\xbf" if bom else b"") + text.encode("utf-8")


def _safe(root: Path, rel: Path) -> Path:
    if rel.is_absolute() or ".." in rel.parts:
        raise ValueError("Unexpected relative path")
    dst = root / rel
    if dst.is_symlink() or not dst.resolve().is_relative_to(root.resolve()):
        raise ValueError("Cannot update symbolic link or path outside project: " + str(rel))
    return dst


def _manifest(project: Path) -> dict:
    f = _safe(project, MANIFEST)
    if not f.is_file():
        raise ValueError("No installed JSON colour patch; nothing to roll back")
    data = json.loads(f.read_text(encoding="utf-8"))
    if data.get("patch") != "json-colour-ui-v1" or set(data.get("files", {})) != {str(p).replace("\\", "/") for p in TARGETS}:
        raise ValueError("Unexpected installer manifest")
    for rel in TARGETS:
        target = _safe(project, rel)
        name = rel.as_posix()
        if not target.is_file() or _hash(target.read_bytes()) != data["files"][name]["after"]:
            raise ValueError("Edited since upgrade; refusing to overwrite: " + name)
    return data


def install(project: Path) -> list[str]:
    project = project.resolve()
    if not project.is_dir():
        raise ValueError("Project folder does not exist")
    if not _safe(project, Path("frontend/src/api/logs.ts")).is_file():
        raise ValueError("The earlier Logs viewer is not installed: frontend/src/api/logs.ts missing")
    if _safe(project, MANIFEST).exists():
        _manifest(project)
        return []
    if _safe(project, BACKUP_DIR).exists():
        raise ValueError("Unknown existing colour patch backup directory")

    changes: dict[Path, bytes] = {}
    originals: dict[Path, bytes] = {}
    for rel in TARGETS:
        dst = _safe(project, rel)
        if not dst.is_file():
            raise ValueError("Install the previous Logs viewer before this UI upgrade: " + rel.as_posix())
        original = dst.read_bytes()
        normalized, bom, newline = _read_normalized(original)
        expected = BASELINE_SHA256[rel.as_posix()]
        if _hash(normalized) != expected:
            raise ValueError("Refusing to replace a customized or unsupported file: " + rel.as_posix())
        source = (PAYLOAD / rel)
        if not source.is_file():
            raise ValueError("Patch payload missing: " + rel.as_posix())
        changes[rel] = _render(source.read_bytes(), bom, newline)
        originals[rel] = original

    backup = _safe(project, BACKUP_DIR)
    backup.mkdir()
    written: list[Path] = []
    try:
        for rel, raw in originals.items():
            p = _safe(backup, rel)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(raw)
        for rel, new in changes.items():
            dst = _safe(project, rel)
            tmp = dst.with_name(dst.name + ".json_colour.tmp")
            if tmp.exists() or tmp.is_symlink():
                raise ValueError("Temporary patch file already exists: " + str(tmp))
            tmp.write_bytes(new)
            os.replace(tmp, dst)
            written.append(rel)
        record = {rel.as_posix(): {"before": _hash(originals[rel]), "after": _hash(changes[rel])} for rel in TARGETS}
        _safe(project, MANIFEST).write_text(json.dumps({"patch": "json-colour-ui-v1", "files": record}, indent=2) + "\n", encoding="utf-8")
    except Exception:
        for rel in written:
            _safe(project, rel).write_bytes(originals[rel])
        for rel in TARGETS:
            f = _safe(project, rel).with_name(rel.name + ".json_colour.tmp")
            if f.exists():
                f.unlink()
        import shutil
        shutil.rmtree(backup, ignore_errors=True)
        raise
    return [p.as_posix() for p in TARGETS]


def rollback(project: Path) -> list[str]:
    project = project.resolve()
    data = _manifest(project)
    restores: dict[Path, bytes] = {}
    for rel in TARGETS:
        raw = _safe(_safe(project, BACKUP_DIR), rel).read_bytes()
        if _hash(raw) != data["files"][rel.as_posix()]["before"]:
            raise ValueError("Backup hash mismatch; refusing rollback")
        restores[rel] = raw
    for rel, raw in restores.items():
        _safe(project, rel).write_bytes(raw)
    for rel in TARGETS:
        _safe(_safe(project, BACKUP_DIR), rel).unlink()
    # Clean known backup folders only.
    import shutil
    shutil.rmtree(_safe(project, BACKUP_DIR))
    _safe(project, MANIFEST).unlink()
    return [p.as_posix() for p in TARGETS]


def main() -> int:
    parser = argparse.ArgumentParser(description="Use JSON-style colour highlighting (UI files only)")
    parser.add_argument("project", nargs="?", type=Path, default=Path("."))
    parser.add_argument("--rollback", action="store_true")
    args = parser.parse_args()
    try:
        updated = rollback(args.project) if args.rollback else install(args.project)
        if updated:
            print(("Restored" if args.rollback else "Updated") + ":")
            for rel in updated:
                print("  " + rel)
        else:
            print("Already installed; no changes needed.")
        return 0
    except (OSError, ValueError, UnicodeError, KeyError, json.JSONDecodeError) as exc:
        print("ERROR: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
