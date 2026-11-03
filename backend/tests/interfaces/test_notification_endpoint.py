import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_get_notification_banner_returns_ok_with_cache_and_security_headers(client: AsyncClient):
    """
        The notification banner GET:
    """
    # The notifications area had no interface test file at all, so
    # deleting the banner router from api/__init__.py — or dropping
    # the no-store lines or the security-headers middleware
    # registration — would previously have gone uncaught here even
    # though every other interface area locks its headers in. This
    # GET needs no new fixture: unlike the banner POST/PUT it carries
    # no permission-check dependency and no tenant-scope assert, and
    # its service returns a default disabled banner when no record
    # exists, so a fresh test database deterministically yields 200.
    response = await client.get("/notifications/banner")
    assert response.status_code == 200
    assert "is_enabled" in response.json()
    # The banner is admin-edited tenant settings data, so it must
    # never be served from a browser or proxy cache: a cached 200
    # could keep showing a disabled/old banner after an update, or
    # show one tenant's banner to another user after an account
    # switch on a shared machine. The handler sets both headers
    # before calling the service, so they hold on the success path.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"
    # Same security-headers lock as the health and unknown-route
    # tests: the pure-ASGI middleware stamps every HTTP response
    # with no path exclusions, so the banner GET must carry the
    # same headers as the authenticated GETs.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the twelve most sensitive directives as disabled, mirroring
    # the health and unknown-route locks, using substring checks so
    # later additions to the list do not break this test. The full
    # value lives in _SECURITY_HEADERS. Each directive is safe to
    # lock here for the same reasons as on the other routes: the
    # SPA has no camera, microphone, geolocation, payment,
    # clipboard-read, display-capture, fullscreen, motion-sensor,
    # compass, XR, or idle-detection flow (verified by grep in the
    # earlier sweeps: zero IdleDetector/requestIdleCallback matches
    # and zero case-insensitive idle matches across
    # frontend/app/src, and the remaining flows verified absent).
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
async def test_post_notification_banner_with_missing_role_returns_404_with_cache_and_security_headers(client: AsyncClient):
    """
        The notification banner POST (second path in this area):
    """
    # The notification area's only test covered the banner GET,
    # which carries no permission dependency, so deleting the
    # POST route — or dropping the central ApiBaseException
    # no-store lines or the security-headers middleware
    # registration — would previously have gone uncaught on the
    # write path. The success path is not asserted here: the POST
    # is permission-gated (FULL_ACCESS via a parameter
    # dependency, evaluated before the handler body and before
    # its tenant-scope guard), so it needs a DB role lookup, and
    # the shared conftest client seeds no role. The error path
    # below is deterministic instead: the mocked host user's
    # role_id points at no row in the fresh test database (Role
    # is in the conftest model set), so the permission dependency
    # raises RoleNotFoundException before the handler runs — which
    # matters here because the handler's banner service would
    # otherwise write a record. The body is valid on purpose:
    # is_enabled is required and a disabled banner needs no
    # message, so body validation passes and cannot mask the 404.
    # That 404 must still carry the error-response headers:
    # banner content is admin-edited tenant settings data, so a
    # cached error response could otherwise be served to a
    # different admin after an account switch on a shared machine.
    response = await client.post("/notifications/banner", json={"is_enabled": False})
    assert response.status_code == 404
    body = response.json()
    assert body["code"] == 404
    assert "Role" in body["error"]
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the banner GET test: the
    # pure-ASGI middleware stamps every HTTP response with no
    # path exclusions, so the banner POST 404 must carry the
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
    # the banner GET lock, using substring checks so later
    # additions to the list do not break this test. The full value
    # lives in _SECURITY_HEADERS. Each directive is safe to lock
    # here for the same reasons as on the other routes: the SPA
    # has no camera, microphone, geolocation, payment,
    # clipboard-read, display-capture, fullscreen, motion-sensor,
    # compass, XR, or idle-detection flow (verified by grep in the
    # earlier sweeps and re-verified fresh this run: zero
    # IdleDetector/requestIdleCallback matches and zero
    # case-insensitive idle matches across frontend/app/src,
    # and the remaining flows verified absent).
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
async def test_put_notification_banner_with_missing_role_returns_404_with_cache_and_security_headers(client: AsyncClient):
    """
        The notification banner PUT (third and last path in this area):
    """
    # The notification area's GET and POST were locked, but the PUT
    # /banner/{id} had no test, so deleting the PUT route — or
    # dropping the central ApiBaseException no-store lines or the
    # security-headers middleware registration — would previously
    # have gone uncaught on the update path. The success path is
    # not asserted here: the PUT is permission-gated (FULL_ACCESS
    # via a parameter dependency, evaluated before the handler body
    # and before its tenant-scope guard), so it needs a DB role
    # lookup, and the shared conftest client seeds no role. The
    # error path below is deterministic instead: the mocked host
    # user's role_id points at no row in the fresh test database
    # (Role is in the conftest model set), so the permission
    # dependency raises RoleNotFoundException before the handler
    # runs — which matters here because the handler's banner
    # service would otherwise overwrite a record. The service
    # factory ahead of it only resolves a singleton and
    # get_tenant_id resolves request state without a lookup, and
    # the path id is never read on this path, so there is no side
    # effect and no unseeded-model lookup beyond the role. The
    # body is valid on purpose: is_enabled is required and a
    # disabled banner needs no message (the DTO normalizes a
    # missing message to None for disabled banners), so body
    # validation passes and cannot mask the 404. That 404 must
    # still carry the error-response headers: banner content is
    # admin-edited tenant settings data, so a cached error
    # response could otherwise be served to a different admin
    # after an account switch on a shared machine.
    response = await client.put("/notifications/banner/68c302ef6bf7a039b7e9b385", json={"is_enabled": False})
    assert response.status_code == 404
    body = response.json()
    assert body["code"] == 404
    assert "Role" in body["error"]
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the banner GET and POST tests:
    # the pure-ASGI middleware stamps every HTTP response with no
    # path exclusions, so the banner PUT 404 must carry the same
    # headers as the authenticated GETs, including the
    # exception-handler responses.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the twelve most sensitive directives as disabled, mirroring
    # the banner GET and POST locks, using substring checks so
    # later additions to the list do not break this test. The full
    # value lives in _SECURITY_HEADERS. Each directive is safe to
    # lock here for the same reasons as on the other routes: the
    # SPA has no camera, microphone, geolocation, payment,
    # clipboard-read, display-capture, fullscreen, motion-sensor,
    # compass, XR, or idle-detection flow (verified by grep in the
    # earlier sweeps and re-verified fresh this run: zero
    # IdleDetector/requestIdleCallback matches and zero
    # case-insensitive idle matches across frontend/app/src,
    # and the remaining flows verified absent).
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
