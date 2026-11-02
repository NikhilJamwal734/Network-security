"""Build Windows one-folder Firewall Analyzer desktop executable.

Usage (from the project root):
    .\\.venv-win\\Scripts\\python.exe .\\desktop_packaging\\build_exe.py
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
        raise FileNotFoundError("Missing app/api/main.py: install API 12 and run from your project checkout")
    if not (dist / "index.html").is_file():
        raise FileNotFoundError("Missing frontend/dist/index.html: run npm run build in frontend first")
    if not launcher.is_file():
        raise FileNotFoundError(f"Missing launcher: {launcher}")
    return [
        python, "-m", "PyInstaller", "--noconfirm", "--clean", "--onedir",
        "--name", "FirewallAnalyzer", "--paths", str(root),
        "--distpath", str(root / "desktop_release"),
        "--workpath", str(root / ".desktop-build"),
        "--specpath", str(root / ".desktop-build"),
        "--add-data", f"{dist}:frontend/dist",
        "--collect-submodules", "app",
        "--collect-submodules", "uvicorn",
        str(launcher),
    ]


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    if sys.platform != "win32":
        print("ERROR: Build the Windows .exe using Windows Python.", file=sys.stderr)
        return 2
    if importlib.util.find_spec("PyInstaller") is None:
        print("ERROR: PyInstaller is not installed. Run: .\\.venv-win\\Scripts\\python.exe -m pip install pyinstaller", file=sys.stderr)
        return 2
    if importlib.util.find_spec("uvicorn") is None:
        print("ERROR: Uvicorn is not installed. Run: .\\.venv-win\\Scripts\\python.exe -m pip install uvicorn", file=sys.stderr)
        return 2
    try:
        args = plan(root, sys.executable)
    except (FileNotFoundError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    print("Packaging FirewallAnalyzer.exe from:", root, flush=True)
    proc = subprocess.run(args, cwd=root, check=False)
    if proc.returncode:
        return proc.returncode
    exe = root / "desktop_release" / "FirewallAnalyzer" / "FirewallAnalyzer.exe"
    if not exe.is_file():
        print("ERROR: Build returned success but the expected executable is missing.", file=sys.stderr)
        return 1
    print("SUCCESS:", exe)
    print("Distribute the ENTIRE desktop_release\\FirewallAnalyzer folder, not just the .exe")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
