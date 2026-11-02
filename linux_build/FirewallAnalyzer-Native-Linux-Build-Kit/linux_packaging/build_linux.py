"""Build FirewallAnalyzer natively on Linux; never modifies Windows packaging files.

From the root of a FULL Linux checkout (not the ZIP alone):
  .venv-linux/bin/python linux_packaging/build_linux.py --check
  .venv-linux/bin/python linux_packaging/build_linux.py
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import importlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
from typing import Iterator

SUPPORTED_VITE_CONFIGS = ("vite.config.ts", "vite.config.mts", "vite.config.js", "vite.config.mjs")


def check_layout(root: Path) -> dict:
    root = root.resolve()
    required = ["app/api/main.py", "frontend/package.json", "frontend/index.html", "linux_packaging/launcher.py"]
    for relative in required:
        if not (root / relative).is_file():
            raise FileNotFoundError(f"Missing {relative}; transfer the full installed project to Linux")
    has_logs_html = (root / "frontend/logs.html").is_file()
    has_logs_entry = (root / "frontend/src/logs-main.tsx").is_file()
    if has_logs_html != has_logs_entry:
        raise ValueError("Standalone Logs UI is incomplete: frontend/logs.html and src/logs-main.tsx must both exist")
    if has_logs_html and not (root / "app/api/log_viewer.py").is_file():
        raise ValueError("Logs UI exists but app/api/log_viewer.py is missing")
    return {"logs_html": has_logs_html, "python": sys.version.split()[0],
            "machine": platform.machine(), "glibc": platform.libc_ver()[1] or "unknown"}


def check_backend_import(root: Path) -> None:
    """Confirm the existing multi-vendor application imports on Linux.

    This does not prove that every parser or operating-system path works at runtime.
    """
    old_path = sys.path[:]
    try:
        sys.path.insert(0, str(root.resolve()))
        loaded = importlib.import_module("app.api.main")
        if not hasattr(loaded, "app"):
            raise RuntimeError("app.api.main imported but has no FastAPI app")
    except (ImportError, OSError, AttributeError, RuntimeError) as exc:
        raise RuntimeError(f"Linux backend import failed ({type(exc).__name__}): {exc}") from exc
    finally:
        sys.path[:] = old_path


def build_command(root: Path, python: str, *, onefile: bool = True) -> list[str]:
    root = root.resolve()
    dist = root / "frontend/dist"
    if not (dist / "index.html").is_file():
        raise FileNotFoundError("Missing built frontend/dist/index.html")
    if (root / "frontend/logs.html").is_file() and not (dist / "logs.html").is_file():
        raise FileNotFoundError("Missing built frontend/dist/logs.html")
    out = root / ("linux_release_single" if onefile else "linux_release_folder")
    return [python, "-m", "PyInstaller", "--noconfirm", "--clean", "--onefile" if onefile else "--onedir",
            "--console", "--name", "FirewallAnalyzer", "--paths", str(root),
            "--distpath", str(out), "--workpath", str(root / ".linux-pyinstaller" / "work"),
            "--specpath", str(root / ".linux-pyinstaller"),
            "--add-data", f"{dist}{os.pathsep}frontend/dist",
            "--collect-submodules", "app", "--collect-submodules", "uvicorn",
            "--hidden-import", "uvicorn.logging", "--hidden-import", "uvicorn.loops.asyncio",
            "--hidden-import", "uvicorn.protocols.http.h11_impl", "--hidden-import", "uvicorn.lifespan.on",
            str(root / "linux_packaging/launcher.py")]


@contextmanager
def temporary_multipage_config(frontend: Path) -> Iterator[None]:
    if not (frontend / "logs.html").is_file():
        yield
        return
    config = next((x for x in SUPPORTED_VITE_CONFIGS if (frontend / x).is_file()), None)
    if config is None:
        raise FileNotFoundError("Missing supported frontend/vite.config.*")
    destination = frontend / ".firewall-linux-vite.config.mts"
    if destination.exists() or destination.is_symlink():
        raise FileExistsError("Refusing to overwrite existing temporary Linux Vite config")
    content = f'''// Temporary production multipage build (deleted after completion).
import original from "./{config}";
import {{ defineConfig, mergeConfig }} from "vite";
import {{ resolve }} from "node:path";
export default defineConfig(async env => {{
  const current = typeof original === "function" ? await original(env) : await original;
  return mergeConfig(current, {{ build: {{ rollupOptions: {{ input: {{
    main: resolve(process.cwd(), "index.html"),
    logs: resolve(process.cwd(), "logs.html"),
  }} }} }} }});
}});
'''
    destination.write_text(content, encoding="utf-8")
    try:
        yield
    finally:
        destination.unlink(missing_ok=True)


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for part in iter(lambda: f.read(1024 * 1024), b""):
            h.update(part)
    return h.hexdigest()


def write_receipt(root: Path, binary: Path, *, onefile: bool) -> Path:
    if binary.is_symlink() or not binary.is_file():
        raise ValueError("Cannot create receipt for missing or symlinked binary")
    receipt = root / "linux_release_build_receipt.json"
    if receipt.is_symlink():
        raise ValueError("Refusing symlinked release receipt")
    payload = {
        "status": "BUILT_NOT_ACCEPTED", "built_at_utc": datetime.now(timezone.utc).isoformat(),
        "binary_sha256": file_sha256(binary), "binary_name": binary.name,
        "platform": "linux", "architecture": platform.machine(), "glibc": platform.libc_ver()[1],
        "packaging": "onefile" if onefile else "onedir",
        "smoke_and_vendor_acceptance": "PENDING", "clean_machine_acceptance": "PENDING",
    }
    receipt.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return receipt


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--onedir", action="store_true", help="Folder build for easier troubleshooting")
    parser.add_argument("--skip-frontend-build", action="store_true", help="Use already-compiled frontend/dist (advanced)")
    args = parser.parse_args(argv)
    if not sys.platform.startswith("linux"):
        print("ERROR: Build Linux binaries on Linux, not Windows", file=sys.stderr)
        return 2
    if sys.prefix == sys.base_prefix:
        print("WARNING: Python virtual environment not detected; a project venv is recommended", file=sys.stderr)
    root = args.root.resolve()
    try:
        info = check_layout(root)
        for package in ("fastapi", "uvicorn", "PyInstaller"):
            if importlib.util.find_spec(package) is None:
                raise RuntimeError(f"Missing Python package: {package}; install into .venv-linux")
        if not args.skip_frontend_build:
            if shutil.which("npm") is None:
                raise RuntimeError("Missing npm; install Node.js on your Linux builder")
            if not (root / "frontend/node_modules/vite").exists():
                raise FileNotFoundError("Missing Vite dependencies; run cd frontend && npm ci")
        elif not (root / "frontend/dist/index.html").is_file():
            raise FileNotFoundError("--skip-frontend-build requires existing frontend/dist/index.html")
        check_backend_import(root)
        if args.check:
            print("LINUX PREFLIGHT PASS:", json.dumps(info))
            print("Note: this verifies build prerequisites, NOT execution on other Linux systems")
            return 0
        frontend = root / "frontend"
        if not args.skip_frontend_build:
            print("Building React frontend ...", flush=True)
            with temporary_multipage_config(frontend):
                subprocess.run(["npm", "run", "build"], cwd=frontend, check=True)
                if info["logs_html"]:
                    subprocess.run(["npm", "exec", "--", "vite", "build", "--config",
                                    ".firewall-linux-vite.config.mts"], cwd=frontend, check=True)
        cmd = build_command(root, sys.executable, onefile=not args.onedir)
        print("Building native Linux binary ...", flush=True)
        subprocess.run(cmd, cwd=root, check=True)
        binary = (root / "linux_release_folder/FirewallAnalyzer/FirewallAnalyzer" if args.onedir
                  else root / "linux_release_single/FirewallAnalyzer")
        if not binary.is_file() or binary.is_symlink() or not os.access(binary, os.X_OK):
            raise RuntimeError("PyInstaller did not produce an executable Linux binary")
        receipt = write_receipt(root, binary, onefile=not args.onedir)
        print("LINUX BUILD COMPLETE:", binary)
        print("SHA256:", file_sha256(binary))
        print("RECEIPT:", receipt)
        print("NEXT: python linux_packaging/accept_linux.py --root .")
        return 0
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as exc:
        print("LINUX BUILD FAILED:", exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
