"""Idempotently register the opt-in API-009.9 IDS bundle route.

Run from the project root with .venv-win\\Scripts\\python.exe scripts\\install_api_009_9.py
"""
from __future__ import annotations

from pathlib import Path
import shutil
import sys

ROOT = Path(__file__).resolve().parents[1]
MAIN = ROOT / "app/api/main.py"
IMPORT = "from app.api.ids_bundle import router as ids_bundle_router"
INCLUDE = "app.include_router(ids_bundle_router)"


def patch(text: str) -> str:
    if IMPORT in text and INCLUDE in text:
        return text
    if (IMPORT in text) != (INCLUDE in text):
        raise RuntimeError("Partial IDS bundle registration detected; inspect main.py manually.")
    anchor_import = "from app.api.assessment import router as assessment_router"
    anchor_include = "app.include_router(assessment_router)"
    if text.count(anchor_import) != 1 or text.count(anchor_include) != 1:
        raise RuntimeError("API-009.8 main.py anchors not found; no files changed.")
    return text.replace(anchor_import, anchor_import + "\n" + IMPORT, 1).replace(
        anchor_include, anchor_include + "\n" + INCLUDE, 1
    )


def install() -> str:
    if not MAIN.is_file():
        raise RuntimeError(f"Cannot find backend entrypoint: {MAIN}")
    before = MAIN.read_text(encoding="utf-8-sig")
    after = patch(before)
    if before == after:
        return "Already installed: API-009.9 IDS bundle endpoint"
    backup = MAIN.with_name("main.py.api0098.backup")
    if not backup.exists():
        shutil.copy2(MAIN, backup)
    MAIN.write_text(after, encoding="utf-8")
    return "Installed: POST /api/v1/analyze/ids-bundle (main.py backed up)"


if __name__ == "__main__":
    try:
        print(install())
    except (RuntimeError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
