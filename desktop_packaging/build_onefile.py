"""Build a single-file Windows FirewallAnalyzer.exe without changing the onedir build.

Run at the project root:
    .\\.venv-win\\Scripts\\python.exe .\\desktop_packaging\\build_onefile.py

The EXE bundles frontend/dist and the FastAPI/analysis modules. It does not
include the React source tree, Python project source files as loose files,
reports, saved configurations, venv, node_modules, or patch directories.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess
import sys


def plan(root: Path, python: str) -> list[str]:
    root = root.resolve()
    launcher = root / "desktop_packaging" / "desktop_launcher.py"
    dist = root / "frontend" / "dist"

    if not (root / "app" / "api" / "main.py").is_file():
        raise FileNotFoundError("Missing app/api/main.py. Build from the installed API 12 project root.")
    if not (dist / "index.html").is_file():
        raise FileNotFoundError("Missing frontend/dist/index.html. Run: npm --prefix frontend run build")
    if not launcher.is_file():
        raise FileNotFoundError("Missing desktop_packaging/desktop_launcher.py. Install the desktop build kit first.")

    launcher_text = launcher.read_text(encoding="utf-8-sig")
    if "_MEIPASS" not in launcher_text:
        raise ValueError("Desktop launcher does not resolve bundled files from sys._MEIPASS.")
    if "resolve_api_origin" not in launcher_text:
        raise ValueError("Desktop launcher lacks the localhost API port fix. Apply the desktop API port patch first.")

    return [
        python, "-m", "PyInstaller", "--noconfirm", "--clean", "--onefile",
        "--name", "FirewallAnalyzer", "--paths", str(root),
        "--distpath", str(root / "desktop_release_single"),
        "--workpath", str(root / ".desktop-build-single"),
        "--specpath", str(root / ".desktop-build-single"),
        "--add-data", f"{dist}:frontend/dist",
        "--collect-submodules", "app",
        "--collect-submodules", "uvicorn",
        str(launcher),
    ]


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    if sys.platform != "win32":
        print("ERROR: Build the Windows EXE on Windows.", file=sys.stderr)
        return 2
    for package in ("PyInstaller", "uvicorn"):
        if importlib.util.find_spec(package) is None:
            print(f"ERROR: Missing {package}. Install it with your .venv-win Python.", file=sys.stderr)
            return 2
    try:
        command = plan(root, sys.executable)
    except (FileNotFoundError, UnicodeDecodeError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    print("Building SINGLE-FILE FirewallAnalyzer.exe from:", root, flush=True)
    result = subprocess.run(command, cwd=root, check=False)
    if result.returncode != 0:
        return result.returncode
    output = root / "desktop_release_single" / "FirewallAnalyzer.exe"
    if not output.is_file():
        print(f"ERROR: PyInstaller returned success, but {output} does not exist.", file=sys.stderr)
        return 1
    print("SUCCESS:", output)
    print("Only FirewallAnalyzer.exe is needed for distribution (after runtime validation).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
