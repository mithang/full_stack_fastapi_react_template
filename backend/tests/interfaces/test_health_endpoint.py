import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_health_check_returns_ok_with_security_headers(client: AsyncClient):
    """
        The public liveness check:
    """
    # Absolute URL, as in the unknown-route locks, so this does not
    # depend on how httpx merges the shared client's /api/v1 base_url
    # with a relative path: the request must reach the health router's
    # GET "/" under the /api/v1/health prefix. /health is the one
    # endpoint area with no interface test file at all, so deleting
    # the security-headers middleware registration — or dropping the
    # health router from api/__init__.py — would previously have gone
    # uncaught here even though every other interface area locks its
    # headers in. The health handler carries no auth or tenancy
    # dependencies, so no fixture beyond the shared client is needed.
    response = await client.get("http://test/api/v1/health/")
    assert response.status_code == 200
    assert response.json() == {"status": "Ok"}
    # Same security-headers lock as the unknown-route 404s: the
    # pure-ASGI middleware stamps every HTTP response with no path
    # exclusions, so /health must carry the same headers as the
    # authenticated GETs. No Cache-Control: no-store assert here, by
    # design: /health is the static public check deliberately left
    # cacheable, unlike every other GET in the API.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the twelve most sensitive directives as disabled, mirroring the
    # unknown-route locks, using substring checks so later additions
    # to the list do not break this test. The full value lives in
    # _SECURITY_HEADERS. Each directive is safe to lock here for the
    # same reasons as on the other routes: the SPA has no camera,
    # microphone, geolocation, payment, clipboard-read, display-
    # capture, fullscreen, motion-sensor, compass, XR, or
    # idle-detection flow (verified by grep this run: zero
    # IdleDetector/requestIdleCallback matches and zero
    # case-insensitive idle matches across frontend/app/src, and the
    # earlier sweeps verified the remaining flows absent).
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
