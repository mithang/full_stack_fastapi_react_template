import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_get_dashboard_metrics_returns_ok_with_cache_and_security_headers(client: AsyncClient):
    """
        The dashboard metrics GET:
    """
    # The dashboard area had no interface test file at all, so
    # deleting the dashboard router from api/__init__.py — or
    # dropping the no-store lines or the security-headers middleware
    # registration — would previously have gone uncaught here even
    # though every other interface area locks its headers in. This
    # GET needs no new fixture: unlike the features GET it carries
    # no permission-check dependency and no DB role lookup, and
    # unlike the billing/AI GETs it needs no live external service.
    # Its scope guard passes for the shared mocked user (tenant_id
    # None, so the host global view applies), and its service only
    # aggregates the fresh test database, so an empty database
    # deterministically yields 200 with zero counts and an empty
    # timeseries.
    response = await client.get("/dashboard/")
    assert response.status_code == 200
    body = response.json()
    assert body["filter"] == "all"
    assert body["total_users"] == 0
    assert body["joined_users"] == 0
    assert body["timeseries"] == []
    # Per-tenant metrics are admin-visible counts, so they must
    # never be served from a browser or proxy cache: a cached 200
    # could serve one tenant's metrics to another admin after an
    # account switch, or hide fresh signups. The handler sets both
    # headers before calling the service, so they hold on the
    # success path.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"
    # Same security-headers lock as the notification banner test:
    # the pure-ASGI middleware stamps every HTTP response with no
    # path exclusions, so the dashboard GET must carry the same
    # headers as the authenticated GETs.
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
