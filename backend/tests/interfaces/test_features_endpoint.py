import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_get_features_with_missing_role_returns_404_with_cache_and_security_headers(client: AsyncClient):
    """
        The features GET:
    """
    # The features area had no interface test file at all, so
    # deleting the features router from api/__init__.py — or
    # dropping the central ApiBaseException no-store lines or the
    # security-headers middleware registration — would previously
    # have gone uncaught here even though every other interface
    # area locks its headers in. The success path is not asserted
    # here: the GET is permission-gated (HOST_MANAGE_TENANTS), so
    # it needs a DB role lookup, and the shared conftest client
    # seeds no role — the dashboard test documents the same
    # exclusion for this endpoint. The error path below is
    # deterministic instead: the mocked host user's role_id
    # points at no row in the fresh test database (Role is in
    # the conftest model set), so the permission dependency
    # raises RoleNotFoundException before the handler runs, and
    # the central ApiBaseException handler turns it into a 404.
    # That 404 must still carry the error-response headers: a
    # cached 404 could otherwise be served to a different user
    # after an account switch on a shared machine.
    response = await client.get("/features/")
    assert response.status_code == 404
    body = response.json()
    assert body["code"] == 404
    assert "Role" in body["error"]
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the notification banner test:
    # the pure-ASGI middleware stamps every HTTP response with no
    # path exclusions, so the features 404 must carry the same
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
    # the notification lock, using substring checks so later
    # additions to the list do not break this test. The full value
    # lives in _SECURITY_HEADERS. Each directive is safe to lock
    # here for the same reasons as on the other routes: the SPA
    # has no camera, microphone, geolocation, payment,
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
