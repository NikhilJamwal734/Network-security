"""Start the existing Firewall Configuration Analyzer API and compiled React UI.

The packaged executable runs on loopback only, and opens the browser at the
bound ephemeral port.  No Vite/Node runtime is required on the target PC.
"""
from __future__ import annotations

import socket
import sys
import threading
import time
import webbrowser
from pathlib import Path

import uvicorn
from fastapi import HTTPException
from fastapi.responses import FileResponse, Response
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.routing import Route

from app.api.main import app as backend_app


def bundle_root() -> Path:
    """PyInstaller stores bundled data in sys._MEIPASS at runtime."""
    return Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parents[1])).resolve()


DIST = bundle_root() / "frontend" / "dist"


# The development dashboard may have absolute API URLs compiled into Vite JS.
# In the packaged build, React and FastAPI are hosted on the same ephemeral
# loopback port. Only rewrite known development API origins in the assets we
# serve; do not mutate the user's source or built files on disk.
DEV_API_ORIGINS = (b"http://127.0.0.1:8000", b"http://localhost:8000")


def resolve_api_origin(data: bytes, port: int) -> bytes:
    if not 1 <= port <= 65535:
        raise ValueError("Invalid bound localhost port")
    target = f"http://127.0.0.1:{port}".encode("ascii")
    for source in DEV_API_ORIGINS:
        data = data.replace(source, target)
    return data


def serve_frontend_asset(path: Path, request: Request):
    """Serve compiled assets with any old dev API origin mapped to this server."""
    if path.suffix.lower() not in {".js", ".mjs", ".html"}:
        return FileResponse(path)
    scope_server = request.scope.get("server")
    if not scope_server or len(scope_server) < 2:
        return FileResponse(path)
    try:
        port = int(scope_server[1])
    except (TypeError, ValueError):
        return FileResponse(path)
    content = path.read_bytes()
    patched = resolve_api_origin(content, port)
    if patched == content:
        return FileResponse(path)
    media_type = "text/html" if path.suffix.lower() == ".html" else "application/javascript"
    return Response(patched, media_type=media_type,
                    headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})


async def frontend_page(request: Request):
    relative = request.path_params.get("path", "")
    if "\\" in relative or "\x00" in relative:
        raise HTTPException(status_code=404)
    root = DIST.resolve()
    requested = (root / relative).resolve()
    if not requested.is_relative_to(root):
        raise HTTPException(status_code=404)
    if requested.is_file():
        return serve_frontend_asset(requested, request)
    # Support client-side navigation, but do not masquerade a missing JS/CSS
    # asset as an HTML document.
    if "." in relative.rsplit("/", 1)[-1]:
        raise HTTPException(status_code=404)
    return serve_frontend_asset(root / "index.html", request)


frontend_app = Starlette(routes=[Route("/{path:path}", frontend_page, methods=["GET", "HEAD"])])


async def combined_app(scope, receive, send):
    """Preserve the API's existing URL paths without rewriting FastAPI routes."""
    if scope["type"] != "http":
        await backend_app(scope, receive, send)
        return
    path = scope.get("path", "")
    if path == "/api" or path.startswith("/api/") or path in {
        "/openapi.json", "/docs", "/redoc", "/docs/oauth2-redirect"
    }:
        await backend_app(scope, receive, send)
    else:
        await frontend_app(scope, receive, send)


def main() -> int:
    if not (DIST / "index.html").is_file():
        print("ERROR: Missing bundled frontend/dist/index.html. Build React before packaging.", file=sys.stderr)
        return 2
    # Hold a bound listening socket to avoid races with other local servers.
    # Packaged assets automatically use this selected port for API fetches.
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        listener.bind(("127.0.0.1", 0))
        listener.listen(128)
        port = listener.getsockname()[1]
        url = f"http://127.0.0.1:{port}/"
        print("Firewall Configuration Analyzer")
        print("Open in browser:", url)
        print("Close the terminal or press Ctrl+C to stop the application.")

        def open_browser():
            time.sleep(0.9)
            webbrowser.open(url)

        threading.Thread(target=open_browser, daemon=True).start()
        config = uvicorn.Config(combined_app, host="127.0.0.1", port=port,
                                log_level="warning", access_log=False,
                                workers=1, loop="asyncio")
        uvicorn.Server(config).run(sockets=[listener])
        return 0
    except KeyboardInterrupt:
        return 0
    finally:
        listener.close()


if __name__ == "__main__":
    raise SystemExit(main())
