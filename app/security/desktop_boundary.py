"""Local-only HTTP/ASGI boundary for the Windows desktop application.

This middleware is NOT an authentication system or a production server policy.
It enforces loopback Host / client / browser Origin for desktop connections,
and a bounded HTTP request body. It does not parse, execute or store uploads.
For centralized deployment, implement a different authenticated server gateway.
"""
from __future__ import annotations

from ipaddress import ip_address
from urllib.parse import urlsplit

MAX_HTTP_REQUEST_BYTES = 16 * 1024 * 1024


def loopback(name: str) -> bool:
    if name in ('localhost', 'testserver'):
        return True
    try:
        address = ip_address(name.strip('[]'))
        return address.is_loopback or (getattr(address, 'ipv4_mapped', None) is not None and address.ipv4_mapped.is_loopback)
    except ValueError:
        return False


def allowed_origin(value: str) -> bool:
    if not value or len(value) > 1024:
        return False
    try:
        origin = urlsplit(value)
        return (origin.scheme in ('http', 'https') and origin.hostname is not None
                and loopback(origin.hostname) and origin.username is None and origin.password is None
                and not origin.path.strip('/') and not origin.query and not origin.fragment
                and origin.port is not None and 1 <= origin.port <= 65535)
    except ValueError:
        return False


class DesktopBoundaryMiddleware:
    """Desktop-only ASGI request guard; no broad or spoofable forwarded-header exceptions."""

    def __init__(self, app, max_bytes: int = MAX_HTTP_REQUEST_BYTES):
        if not 64 * 1024 <= max_bytes <= 128 * 1024 * 1024:
            raise ValueError('Invalid desktop request bound')
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send):
        if scope.get('type') != 'http':
            return await self.app(scope, receive, send)
        headers = [(k.lower(), v) for k, v in scope.get('headers', [])]
        def values(key):
            return [v.decode('latin-1') for k, v in headers if k == key]
        hosts = values(b'host')
        # RFC 9110: one Host field. Refuse authority ambiguity and DNS rebinding.
        try:
            raw_host = hosts[0]
            if not raw_host or len(hosts) != 1 or '/' in raw_host or '@' in raw_host:
                raise ValueError('invalid Host')
            uri = urlsplit('http://' + raw_host)
            if (not uri.hostname or not loopback(uri.hostname) or uri.username or uri.password
                    or uri.path or uri.query or uri.fragment):
                raise ValueError('non-loopback Host')
            if uri.port is not None and not (1 <= uri.port <= 65535):
                raise ValueError('bad port')
        except ValueError:
            return await self._reject(send, 400, 'untrusted_host')
        peer = (scope.get('client') or ('127.0.0.1', 0))[0]
        if peer not in ('testclient',) and not loopback(peer):
            return await self._reject(send, 403, 'nonlocal_client')
        origins = values(b'origin')
        if len(origins) > 1 or (origins and not allowed_origin(origins[0])):
            return await self._reject(send, 403, 'untrusted_origin')
        sizes = values(b'content-length')
        if len(sizes) > 1:
            return await self._reject(send, 400, 'ambiguous_content_length')
        if sizes:
            try:
                content_length = int(sizes[0])
                if content_length < 0:
                    raise ValueError
            except ValueError:
                return await self._reject(send, 400, 'invalid_content_length')
            if content_length > self.max_bytes:
                return await self._reject(send, 413, 'request_too_large')
        # Enforce a total body limit even for chunked clients; do so before
        # invoking any endpoint, preventing partial application side effects.
        # This is deliberately scoped to methods that normally carry payloads.
        if scope.get('method', 'GET').upper() not in ('POST', 'PUT', 'PATCH'):
            return await self.app(scope, receive, send)
        blocks = []
        total = 0
        while True:
            packet = await receive()
            if packet['type'] == 'http.disconnect':
                return
            if packet['type'] != 'http.request':
                continue
            block = packet.get('body', b'')
            total += len(block)
            if total > self.max_bytes:
                return await self._reject(send, 413, 'request_too_large')
            blocks.append(block)
            if not packet.get('more_body', False):
                break
        # Replay the same bytes to Starlette exactly once; no disk writes.
        sent = False
        async def bounded_receive():
            nonlocal sent
            if not sent:
                sent = True
                return {'type': 'http.request', 'body': b''.join(blocks), 'more_body': False}
            return await receive()
        return await self.app(scope, bounded_receive, send)

    @staticmethod
    async def _reject(send, status: int, code: str):
        # Fixed response; never reflect Host, Origin, source data or secrets.
        body = ('{"detail":{"code":"' + code + '","message":"Desktop request rejected"}}').encode('ascii')
        await send({'type': 'http.response.start', 'status': status,
                    'headers': [(b'content-type', b'application/json'),
                                (b'cache-control', b'no-store'),
                                (b'x-content-type-options', b'nosniff'),
                                (b'content-length', str(len(body)).encode('ascii'))]})
        await send({'type': 'http.response.body', 'body': body})
