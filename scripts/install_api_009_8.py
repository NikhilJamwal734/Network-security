r"""Register API-009.8's NEW router without replacing API-009.6 main.py.

From the main project root:
  .\.venv-win\Scripts\python.exe scripts\install_api_009_8.py
"""

from pathlib import Path
import shutil
import sys

ROOT = Path(__file__).resolve().parents[1]
MAIN = ROOT / "app/api/main.py"
IMPORT = "from app.api.assessment import router as assessment_router"
REGISTRATION = "app.include_router(assessment_router)"


def install() -> str:
    new_endpoint = ROOT / "app/api/assessment.py"
    new_core = ROOT / "app/core/advanced_assessment.py"
    if not MAIN.is_file() or not new_endpoint.is_file() or not new_core.is_file():
        raise RuntimeError("Extract the API-009.8 ZIP into the backend project root first")
    source = MAIN.read_text(encoding="utf-8")
    if IMPORT in source and REGISTRATION in source:
        return "Already installed: API-009.8 assessment router"
    if IMPORT in source or REGISTRATION in source:
        raise RuntimeError("Partial API-009.8 router registration detected; inspect main.py manually")
    import_anchor = "from app.api.normalized import router as normalized_router"
    router_anchor = "app.include_router(normalized_router)"
    if import_anchor not in source or router_anchor not in source:
        raise RuntimeError("main.py differs from the expected API-009.6 layout; no files changed")
    updated = source.replace(import_anchor, import_anchor + "\n" + IMPORT, 1)
    updated = updated.replace(router_anchor, router_anchor + "\n" + REGISTRATION, 1)
    backup = MAIN.with_name("main.py.api0097.backup")
    if not backup.exists():
        shutil.copy2(MAIN, backup)
    MAIN.write_text(updated, encoding="utf-8")
    return "Installed: POST /api/v1/analyze/assessment (main.py backed up)"


if __name__ == "__main__":
    try:
        print(install())
    except (RuntimeError, OSError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(1) from None
