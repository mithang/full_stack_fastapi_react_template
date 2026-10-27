# Security headers for every HTTP response (API, SPA shell, static assets).
#
# Until now no response carried clickjacking / MIME-sniffing / referrer
# headers, so a browser embedding the app in an iframe (clickjacking) or
# sniffing a JSON error body as executable content was left to browser
# defaults, and full referrer URLs leaked to cross-origin links.
#
# This is a pure ASGI middleware, not a BaseHTTPMiddleware subclass, so
# it only rewrites the response-start headers and never buffers the
# body: the ai-chat SSE stream passes through untouched. It sets a
# header only when the downstream response does not already carry one,
# so the SPA shell's explicit Cache-Control and any future per-route
# header are never overwritten. No Content-Security-Policy is set here:
# the Vite SPA relies on inline styles/scripts, so a CSP would need a
# per-build nonce design of its own.
_SECURITY_HEADERS = {
    b"x-content-type-options": b"nosniff",
    b"x-frame-options": b"DENY",
    b"referrer-policy": b"strict-origin-when-cross-origin",
}


class SecurityHeadersMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message):
            if message.get("type") == "http.response.start":
                headers = list(message.get("headers", []))
                present = {name.lower() for name, _ in headers}
                for name, value in _SECURITY_HEADERS.items():
                    if name not in present:
                        headers.append((name, value))
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_with_headers)
