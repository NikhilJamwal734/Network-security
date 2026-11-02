"""Windows-only smoke test for the just-created FirewallAnalyzer.exe.

Starts EXE without browser, checks UI/API/optional JSON Logs, then stops it.
The EXE chooses its own loopback port. No fixed 8000 port is required.
"""
from __future__ import annotations

import argparse
import queue
import re
import subprocess
import sys
import threading
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import urlopen


URL_PATTERN = re.compile(r"Open in browser:\s*(http://127\.0\.0\.1:\d+/)")


def _read_lines(stream, output: queue.Queue[str]) -> None:
    for line in iter(stream.readline, ""):
        output.put(line.rstrip("\r\n"))


def _check(url: str, *, label: str) -> bool:
    try:
        with urlopen(url, timeout=3) as response:
            body = response.read(256 * 1024)
            if response.status != 200:
                print("FAIL", label, "HTTP", response.status)
                return False
            print("PASS", label, "HTTP", response.status, "bytes", len(body))
            return True
    except (URLError, HTTPError, TimeoutError) as exc:
        print("FAIL", label, type(exc).__name__, str(exc))
        return False


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", type=Path, default=Path("desktop_release_single/FirewallAnalyzer.exe"))
    parser.add_argument("--timeout", type=int, default=90)
    args = parser.parse_args()
    exe = args.exe.resolve()
    if sys.platform != "win32":
        print("ERROR: Smoke test the Windows binary on Windows.")
        return 2
    if not exe.is_file():
        print("ERROR: Cannot find", exe)
        return 2
    proc = subprocess.Popen([str(exe), "--no-browser"], cwd=exe.parent,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, encoding="utf-8", errors="replace", bufsize=1)
    lines: queue.Queue[str] = queue.Queue()
    assert proc.stdout is not None
    t = threading.Thread(target=_read_lines, args=(proc.stdout, lines), daemon=True)
    t.start()
    try:
        endpoint = None
        deadline = time.monotonic() + args.timeout
        while time.monotonic() < deadline:
            try:
                line = lines.get(timeout=0.3)
                print("EXE:", line)
                match = URL_PATTERN.search(line)
                if match:
                    endpoint = match.group(1)
                    break
            except queue.Empty:
                if proc.poll() is not None:
                    break
        if not endpoint:
            print("FAIL: EXE did not announce an HTTP URL; exit code:", proc.poll())
            return 1
        for _ in range(20):
            if _check(endpoint, label="Dashboard"):
                break
            time.sleep(0.5)
        else:
            return 1
        if not any(_check(endpoint + path, label="API " + path)
                   for path in ("api/v1/release/status", "api/health", "openapi.json")):
            print("FAIL: No API health or OpenAPI endpoint worked")
            return 1
        # In a project with standalone logs viewer, this must be available.
        try:
            with urlopen(endpoint + "logs.html", timeout=3) as r:
                if r.status == 200:
                    print("PASS: Standalone JSON Logs page")
                    if not _check(endpoint + "api/v1/logs?stream=application", label="Logs API"):
                        return 1
        except HTTPError as exc:
            if exc.code == 404:
                print("INFO: Standalone logs.html not installed (optional)")
            else:
                print("FAIL: Logs HTML HTTP", exc.code)
                return 1
        print("SMOKE TEST PASSED. Test actual configuration uploads and PDF export manually.")
        return 0
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)


if __name__ == "__main__":
    raise SystemExit(main())
