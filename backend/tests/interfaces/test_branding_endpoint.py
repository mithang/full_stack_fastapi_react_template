import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_post_branding_with_missing_role_returns_404_with_cache_and_security_headers(client: AsyncClient):
    """
        The branding POST:
    """
    # The branding area had no interface test file at all, so
    # deleting the branding router from api/__init__.py — or dropping
    # the central ApiBaseException no-store lines or the
    # security-headers middleware registration — would previously
    # have gone uncaught here even though every other interface
    # area locks its headers in. Branding has no GET route (only
    # POST/PATCH/PUT), so the GET error-path pattern used by the
    # features/audit-logs/SSO/storage tests does not apply cleanly;
    # the POST error path below is the deterministic equivalent.
    # The success path is not asserted here: the POST is
    # permission-gated (FULL_ACCESS via a router-level dependency,
    # with no feature gate in front of it), so it needs a DB role
    # lookup, and the shared conftest client seeds no role. The
    # error path below is deterministic instead: the mocked host
    # user's role_id points at no row in the fresh test database
    # (Role is in the conftest model set), so the permission
    # dependency raises RoleNotFoundException before the handler
    # runs — which matters here because the handler's branding
    # service uses the Branding document, outside the conftest
    # model set, and would fail non-deterministically if reached.
    # The body is {} on purpose: every UpdateBrandingDto field is
    # optional, so body validation passes and cannot mask the 404.
    # That 404 must still carry the error-response headers:
    # branding carries contact info (PII), so a cached error
    # response could otherwise be served to a different admin
    # after an account switch on a shared machine.
    response = await client.post("/brandings/", json={})
    assert response.status_code == 404
    body = response.json()
    assert body["code"] == 404
    assert "Role" in body["error"]
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the storage test: the
    # pure-ASGI middleware stamps every HTTP response with no
    # path exclusions, so the branding POST 404 must carry the
    # same headers as the authenticated GETs, including the
    # exception-handler responses.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the twelve most sensitive directives as disabled, mirroring
    # the storage lock, using substring checks so later additions
    # to the list do not break this test. The full value lives in
    # _SECURITY_HEADERS. Each directive is safe to lock here for
    # the same reasons as on the other routes: the SPA has no
    # camera, microphone, geolocation, payment, clipboard-read,
    # display-capture, fullscreen, motion-sensor, compass, XR, or
    # idle-detection flow (verified by grep in the earlier sweeps
    # and re-verified fresh this run: zero IdleDetector/
    # requestIdleCallback matches and zero case-insensitive idle
    # matches across frontend/app/src, and the remaining flows
    # verified absent).
    permissions_policy = response.headers["permissions-policy"]
    assert "camera=()" in permissions_policy
    assert "microphone=()" in permissions_policy
    assert "geolocation=()" in permissions_policy
    assert "payment=()" in permissions_policy
    assert "clipboard-read=()" in permissions_policy
    assert "display-capture=()" in permissions_policy
    assert "fullscreen=()" in permissions_policy
    assert "accelerometer=()" in permissions_policy
    assert "gyroscope=()" in permissions_policy
    assert "magnetometer=()" in permissions_policy
    assert "xr-spatial-tracking=()" in permissions_policy
    assert "idle-detection=()" in permissions_policy


@pytest.mark.asyncio
async def test_patch_branding_with_missing_role_returns_404_with_cache_and_security_headers(client: AsyncClient):
    """
        The branding PATCH (second-path lock, following the POST
        lock above):
    """
    # The POST test locks the branding area's error path, but a
    # second route could lose its router dependency (or gain a
    # handler change that runs before it) while the POST lock still
    # passes, so each route needs its own lock. PATCH is the
    # deterministic second route: it shares the router-level
    # FULL_ACCESS dependency with the POST (no feature gate in
    # front of it), and the dependency raises
    # RoleNotFoundException before the handler runs — which
    # matters here because the handler's branding service uses
    # the Branding document, outside the conftest model set, and
    # would fail non-deterministically if reached. The mocked
    # host user's role_id points at no row in the fresh test
    # database (Role is in the conftest model set). The body is
    # {} on purpose: every UpdateBrandingDto field is optional,
    # so body validation passes and cannot mask the 404, and the
    # branding_id path param is a plain string, so no path
    # validation can mask it either. PUT /logo was not chosen:
    # it takes a multipart file, not a JSON body, so its error
    # path is not the same deterministic shape. That 404 must
    # still carry the error-response headers: branding carries
    # contact info (PII), so a cached error response could
    # otherwise be served to a different admin after an account
    # switch on a shared machine.
    response = await client.patch("/brandings/68c302ef6bf7a039b7e9b387", json={})
    assert response.status_code == 404
    body = response.json()
    assert body["code"] == 404
    assert "Role" in body["error"]
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the POST test: the
    # pure-ASGI middleware stamps every HTTP response with no
    # path exclusions, so the branding PATCH 404 must carry the
    # same headers as the POST 404, including the
    # exception-handler responses.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the twelve most sensitive directives as disabled, mirroring
    # the POST lock, using substring checks so later additions
    # to the list do not break this test. Each directive is safe
    # to lock here for the same reasons as on the POST route:
    # the SPA has no camera, microphone, geolocation, payment,
    # clipboard-read, display-capture, fullscreen, motion-sensor,
    # compass, XR, or idle-detection flow (re-verified fresh this
    # run: zero case-insensitive idle matches across
    # frontend/app/src).
    permissions_policy = response.headers["permissions-policy"]
    assert "camera=()" in permissions_policy
    assert "microphone=()" in permissions_policy
    assert "geolocation=()" in permissions_policy
    assert "payment=()" in permissions_policy
    assert "clipboard-read=()" in permissions_policy
    assert "display-capture=()" in permissions_policy
    assert "fullscreen=()" in permissions_policy
    assert "accelerometer=()" in permissions_policy
    assert "gyroscope=()" in permissions_policy
    assert "magnetometer=()" in permissions_policy
    assert "xr-spatial-tracking=()" in permissions_policy
    assert "idle-detection=()" in permissions_policy


@pytest.mark.asyncio
async def test_put_branding_logo_with_missing_role_returns_404_with_cache_and_security_headers(client: AsyncClient):
    """
        The branding PUT /logo (third-path lock, completing the
        branding route set: POST, PATCH, PUT /logo):
    """
    # The PATCH test noted PUT /logo was not chosen then because
    # it takes a multipart file, not a JSON body — but that is
    # not a blocker once the file is valid: the request below
    # carries a real (tiny) PNG part, so multipart parsing cannot
    # 422-mask the error whichever order FastAPI resolves the
    # file param versus the router dependency. Either way the
    # outcome is the same 404: the router-level FULL_ACCESS
    # dependency raises RoleNotFoundException (the mocked host
    # user's role_id points at no row in the fresh test database;
    # Role is in the conftest model set) before the handler runs,
    # so no file reaches storage, no branding record is created
    # or updated, and no scope guard is ever evaluated. That
    # matters here because the handler's branding and file
    # services use documents outside the conftest model set and
    # would fail non-deterministically if reached. That 404 must
    # still carry the error-response headers: branding carries
    # contact info (PII), so a cached error response could
    # otherwise be served to a different admin after an account
    # switch on a shared machine.
    png_1x1 = (
        b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01"
        b"\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde\x00\x00"
        b"\x00\x0cIDATx\x9cc\xf8\x0f\x00\x00\x01\x01\x00\x05"
        b"\x18\xd8N\x00\x00\x00\x00IEND\xaeB`\x82"
    )
    response = await client.put(
        "/brandings/logo",
        files={"file": ("logo.png", png_1x1, "image/png")},
    )
    assert response.status_code == 404
    body = response.json()
    assert body["code"] == 404
    assert "Role" in body["error"]
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the POST/PATCH tests: the
    # pure-ASGI middleware stamps every HTTP response with no
    # path exclusions, so the branding PUT 404 must carry the
    # same headers as the POST/PATCH 404s, including the
    # exception-handler responses.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the twelve most sensitive directives as disabled, mirroring
    # the POST/PATCH locks, using substring checks so later
    # additions to the list do not break this test. Each directive
    # is safe to lock here for the same reasons as on the other
    # branding routes: the SPA has no camera, microphone,
    # geolocation, payment, clipboard-read, display-capture,
    # fullscreen, motion-sensor, compass, XR, or idle-detection
    # flow (re-verified fresh this run: zero case-insensitive
    # idle matches and zero IdleDetector/requestIdleCallback
    # matches across frontend/app/src).
    permissions_policy = response.headers["permissions-policy"]
    assert "camera=()" in permissions_policy
    assert "microphone=()" in permissions_policy
    assert "geolocation=()" in permissions_policy
    assert "payment=()" in permissions_policy
    assert "clipboard-read=()" in permissions_policy
    assert "display-capture=()" in permissions_policy
    assert "fullscreen=()" in permissions_policy
    assert "accelerometer=()" in permissions_policy
    assert "gyroscope=()" in permissions_policy
    assert "magnetometer=()" in permissions_policy
    assert "xr-spatial-tracking=()" in permissions_policy
    assert "idle-detection=()" in permissions_policy
