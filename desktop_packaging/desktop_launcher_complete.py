"""Windows desktop entry point: bundled FastAPI + built React on one loopback port.

No Node.js, Vite development server or separately running backend is needed on
an end-user PC. The console remains open to make shutdown/errors visible.
"""
from __future__ import annotations

import mimetypes
import os
from pathlib import Path
import socket
import sys
import threading
import time
import webbrowser

from fastapi.responses import FileResponse, Response
from starlette.types import Scope, Receive, Send
import uvicorn
from app.api.main import app as backend_app


def bundle_root() -> Path:
    return Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parents[1])).resolve()


DIST = bundle_root() / "frontend" / "dist"
DEVELOPMENT_ORIGINS = (b"http://127.0.0.1:8000", b"http://localhost:8000")


def replace_development_api_origin(data: bytes, port: int) -> bytes:
    """Rewrite API origins in compiled JS/HTML to the bound desktop port."""
    if not 1 <= port <= 65535:
        raise ValueError("Invalid loopback port")
    bound_origin = f"http://127.0.0.1:{port}".encode("ascii")
    for value in DEVELOPMENT_ORIGINS:
        data = data.replace(value, bound_origin)
    return data


def _asset_path(url_path: str) -> Path | None:
    if not isinstance(url_path, str) or "\\" in url_path or "\x00" in url_path:
        return None
    relative = url_path.lstrip("/") or "index.html"
    root = DIST.resolve()
    candidate = (root / relative).resolve()
    if not candidate.is_relative_to(root):
        return None
    if candidate.is_file():
        return candidate
    # React Router's history paths map to the compiled index, but missing
    # assets must return 404 instead of HTML (which breaks scripts/styles).
    if "." not in relative.rsplit("/", 1)[-1] and (root / "index.html").is_file():
        return root / "index.html"
    return None


def _is_backend_path(path: str) -> bool:
    return (path == "/api" or path.startswith("/api/") or path in {
        "/openapi.json", "/docs", "/redoc", "/docs/oauth2-redirect"
    })


async def application(scope: Scope, receive: Receive, send: Send) -> None:
    if scope["type"] != "http":
        await backend_app(scope, receive, send)
        return
    path = str(scope.get("path", ""))
    if _is_backend_path(path):
        await backend_app(scope, receive, send)
        return
    method = str(scope.get("method", "GET")).upper()
    if method not in {"GET", "HEAD"}:
        await Response(status_code=405)(scope, receive, send)
        return
    # Prevent the server from being accessed through an arbitrary Host value.
    # Only local-origin browser requests are supported.
    headers = dict(scope.get("headers", []))
    host = headers.get(b"host", b"").decode("ascii", errors="ignore").lower()
    if host and not (host.startswith("127.0.0.1:") or host.startswith("localhost:")):
        await Response(status_code=400)(scope, receive, send)
        return
    file = _asset_path(path)
    if file is None:
        await Response(status_code=404, content="Not found")(scope, receive, send)
        return
    if file.suffix.lower() in {".js", ".mjs", ".html"}:
        server = scope.get("server")
        if isinstance(server, (tuple, list)) and len(server) > 1:
            try:
                port = int(server[1])
                raw = file.read_bytes()
                rewritten = replace_development_api_origin(raw, port)
                if rewritten != raw:
                    content_type = "text/html" if file.suffix.lower() == ".html" else "application/javascript"
                    await Response(content=rewritten, media_type=content_type, headers={
                        "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"
                    })(scope, receive, send)
                    return
            except (OSError, ValueError):
                pass
    await FileResponse(file, headers={"X-Content-Type-Options": "nosniff"})(scope, receive, send)


def main() -> int:
    if not (DIST / "index.html").is_file():
        print("ERROR: The compiled React UI is missing from this package.", file=sys.stderr)
        return 2
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        listener.bind(("127.0.0.1", 0))
        listener.listen(128)
        port = listener.getsockname()[1]
        url = f"http://127.0.0.1:{port}/"
        print("Firewall Configuration Analyzer", flush=True)
        print("Open in browser:", url, flush=True)
        if (DIST / "logs.html").is_file():
            print("JSON logs viewer:", f"http://127.0.0.1:{port}/logs.html", flush=True)
        print("Press Ctrl+C in this window to stop the analyzer.", flush=True)
        if "--no-browser" not in sys.argv:
            def _open() -> None:
                time.sleep(1.2)
                webbrowser.open(url)
            threading.Thread(target=_open, daemon=True).start()
        uvicorn.run  # explicit reference for frozen import discovery
        config = uvicorn.Config(application, host="127.0.0.1", port=port,
                                workers=1, loop="asyncio", http="h11", lifespan="on",
                                log_level="warning", access_log=False)
        uvicorn.Server(config).run(sockets=[listener])
        return 0
    except KeyboardInterrupt:
        return 0
    finally:
        listener.close()


if __name__ == "__main__":
    raise SystemExit(main())
