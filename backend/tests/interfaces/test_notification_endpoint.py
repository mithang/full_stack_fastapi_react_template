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
