"""Install API-010.2 precision reviews without altering existing endpoint output.

Usage (run from project root):
  .\\.venv-win\\Scripts\\python.exe scripts\\install_api_010_2.py .

The optional directory is resolved from cwd; default is the parent of scripts/.
"""
from __future__ import annotations

from pathlib import Path
import shutil
import sys

ROOT = Path(__file__).resolve().parents[1]
BACKUP = ".before_api0102.bak"


def replace_one(text: str, old: str, new: str, description: str) -> str:
    if new in text:
        return text
    if text.count(old) != 1:
        raise ValueError(f"Unsupported {description} layout (expected one anchor, found {text.count(old)})")
    return text.replace(old, new, 1)


def patch_universal(text: str) -> str:
    text = replace_one(
        text,
        "    _vendor_review: bool = False,\n",
        "    _vendor_review: bool = False,\n    _precision_review: bool = False,\n",
        "universal parameter",
    )
    anchor = '            report = {**report, "vendor_review": vendor_review}\n'
    updated = anchor + '''            if _precision_review:
                from app.core.precision_review import refine_vendor_review
                report["vendor_review"] = refine_vendor_review(
                    selected.platform_id, lines, vendor_review
                )
'''
    return replace_one(text, anchor, updated, "vendor review response")


def patch_main(text: str) -> str:
    text = replace_one(
        text,
        "from app.api.deep_review import router as deep_review_router\n",
        "from app.api.deep_review import router as deep_review_router\n"
        "from app.api.precision_review import router as precision_review_router\n",
        "FastAPI import",
    )
    return replace_one(
        text,
        "app.include_router(deep_review_router)\n",
        "app.include_router(deep_review_router)\n"
        "app.include_router(precision_review_router)\n",
        "FastAPI route registration",
    )


def plan(root: Path) -> dict[Path, bytes]:
    root = root.resolve()
    required = {
        root / "app/api/universal.py": patch_universal,
        root / "app/api/main.py": patch_main,
    }
    updates: dict[Path, bytes] = {}
    for target, transformer in required.items():
        if not target.is_file():
            raise ValueError(f"Expected API-010.1 source not found: {target}")
        original = target.read_text(encoding="utf-8-sig")
        modified = transformer(original)
        if modified != original:
            updates[target] = modified.encode("utf-8")
    for relative in (
        "app/core/precision_review.py",
        "app/api/precision_review.py",
        "tests/test_api_010_2_precision.py",
    ):
        source, destination = ROOT / relative, root / relative
        if not source.is_file():
            raise ValueError(f"Missing package file: {source}")
        data = source.read_bytes()
        if not destination.is_file() or destination.read_bytes() != data:
            updates[destination] = data
    return updates


def install(root: Path) -> list[str]:
    root = root.resolve()
    updates = plan(root)  # validate all changes BEFORE touching a file
    for destination, data in updates.items():
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.is_file():
            backup = destination.with_name(destination.name + BACKUP)
            if not backup.exists():
                shutil.copy2(destination, backup)
        destination.write_bytes(data)
    return [str(target.relative_to(root)) for target in updates]


if __name__ == "__main__":
    project = Path(sys.argv[1]).resolve() if len(sys.argv) == 2 else ROOT
    try:
        changes = install(project)
    except (OSError, ValueError) as e:
        sys.exit(f"ERROR: {e}")
    print("API-010.2 backend updated:" if changes else "API-010.2 backend already installed.")
    for name in changes:
        print("  " + name)
