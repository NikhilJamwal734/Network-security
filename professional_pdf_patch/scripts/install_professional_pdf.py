"""Install a professional normalized PDF layout, without changing backend logic.

Run from anywhere:
  .\\.venv-win\\Scripts\\python.exe professional_pdf_patch\\scripts\\install_professional_pdf.py
The installer finds the project based on its own ZIP extraction location.

Can also pass an explicit frontend directory as argv[1].
"""
from __future__ import annotations

from pathlib import Path
import shutil
import sys

PACKAGE = Path(__file__).resolve().parents[1]
PROJECT = PACKAGE.parent
FRONTEND = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else PROJECT / "frontend"
SOURCE = PACKAGE / "frontend_patch/src/utils/normalizedPdf.ts"
DESTINATION = FRONTEND / "src/utils/normalizedPdf.ts"
BACKUP = FRONTEND / "src/utils/normalizedPdf.ts.before_professional_layout.bak"


def install() -> str:
    if not (FRONTEND / "package.json").is_file():
        raise RuntimeError(f"React frontend package.json not found: {FRONTEND}")
    if not DESTINATION.is_file():
        raise RuntimeError(f"Existing normalizedPdf.ts not found: {DESTINATION}")
    if not SOURCE.is_file():
        raise RuntimeError(f"Packaged source file missing: {SOURCE}")
    previous = DESTINATION.read_text(encoding="utf-8-sig")
    required = (
        "downloadNormalizedPdf(",
        "downloadNormalizedJson(",
        "normalizedFilename(",
        'from "../api/universal"',
    )
    if not all(fragment in previous for fragment in required):
        raise RuntimeError("Existing PDF exporter differs from supported layout; no files changed")
    new_bytes = SOURCE.read_bytes()
    if DESTINATION.read_bytes() == new_bytes:
        return f"Already installed: {DESTINATION}"
    if not BACKUP.exists():
        shutil.copy2(DESTINATION, BACKUP)
    DESTINATION.write_bytes(new_bytes)
    return f"Updated: {DESTINATION}\nBackup: {BACKUP}"


if __name__ == "__main__":
    try:
        print(install())
    except (RuntimeError, OSError, UnicodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
