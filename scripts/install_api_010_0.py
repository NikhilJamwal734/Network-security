"""Register API-010.0 without replacing the user's app/api/main.py.

Run from project root: .\\.venv-win\\Scripts\\python.exe scripts\\install_api_010_0.py
This script validates all anchors before making any changes, backs up main.py,
and does not modify existing endpoints or analyzer implementations.
"""
from __future__ import annotations

from pathlib import Path
import shutil
import sys

ROOT = Path(__file__).resolve().parents[1]
MAIN = ROOT / "app/api/main.py"
IMPORT = "from app.api.validated import router as validated_router"
REGISTER = "app.include_router(validated_router)"


def prepare(contents: str) -> str:
    if IMPORT in contents and REGISTER in contents:
        return contents
    if (IMPORT in contents) != (REGISTER in contents):
        raise RuntimeError("Partial API-010.0 registration detected; inspect main.py manually")
    if "from app.api.assessment import router as assessment_router" not in contents:
        raise RuntimeError("API-009.8 assessment import not found; first install API-009.8")
    if "app.include_router(assessment_router)" not in contents:
        raise RuntimeError("Assessment router not registered; first install API-009.8")
    if "app = FastAPI(" not in contents:
        raise RuntimeError("Expected main.py FastAPI app not found")
    contents = contents.replace(
        "from app.api.assessment import router as assessment_router",
        "from app.api.assessment import router as assessment_router\n" + IMPORT, 1,
    )
    contents = contents.replace(
        "app.include_router(assessment_router)",
        "app.include_router(assessment_router)\n" + REGISTER, 1,
    )
    return contents


def install() -> str:
    if not MAIN.is_file():
        raise RuntimeError(f"Missing backend main.py: {MAIN}")
    current = MAIN.read_text(encoding="utf-8-sig")
    result = prepare(current)
    if result == current:
        return "Already installed: API-010.0 validated analysis endpoint"
    backup = MAIN.with_name("main.py.before_api0100.bak")
    if not backup.exists():
        shutil.copy2(MAIN, backup)
    MAIN.write_text(result, encoding="utf-8")
    return f"Updated: {MAIN}\nBackup: {backup}"


if __name__ == "__main__":
    try:
        print(install())
    except (OSError, RuntimeError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        sys.exit(1)
