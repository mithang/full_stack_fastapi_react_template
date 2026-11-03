import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_account_logout_returns_ok_with_cache_and_security_headers(client: AsyncClient):
    """
        The account logout GET:
    """
    # The account area had no interface test file at all, so
    # deleting the account router from api/__init__.py — or
    # dropping the no-store lines or the security-headers middleware
    # registration — would previously have gone uncaught here even
    # though every other interface area locks its headers in. This
    # GET needs no new fixture and no authenticated user: unlike
    # the /me GET it carries no MeResponseDto role requirement (the
    # shared mocked user has no role object, so /me cannot yield a
    # deterministic 200), and unlike the passkey GET it needs no
    # beanie document outside the conftest model set. Logout takes
    # CurrentUserOptional, and the OAuth2 scheme has auto_error=False,
    # so with no Authorization header the optional-user resolution
    # fails closed to None, the audit write is skipped, and the
    # handler still runs its session-ending act — deleting the
    # refresh cookie — and returns 200. That unauthenticated 200 is
    # by design: logout must succeed even when the access token has
    # already expired or is absent, or the refresh cookie would
    # survive logout and the background worker would refresh it back
    # into a live session.
    response = await client.get("/account/logout")
    assert response.status_code == 200
    # This GET deletes the refresh cookie and ends the session, so
    # it must never be served from a browser or proxy cache: a
    # cached 200 would replay without running the handler, leaving
    # the refresh cookie (and the session it backs) in place while
    # the user believes they logged out. The handler sets both
    # headers before the cookie deletion, so they hold on this path.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"
    # The deletion itself must be present: the Set-Cookie header
    # carries the refresh_token cookie being cleared.
    assert "refresh_token" in response.headers.get("set-cookie", "")
    # Same security-headers lock as the dashboard test: the
    # pure-ASGI middleware stamps every HTTP response with no path
    # exclusions, so the logout GET must carry the same headers as
    # the authenticated GETs.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the twelve most sensitive directives as disabled, mirroring
    # the dashboard lock, using substring checks so later additions
    # to the list do not break this test. The full value lives in
    # _SECURITY_HEADERS. Each directive is safe to lock here for the
    # same reasons as on the other routes: the SPA has no camera,
    # microphone, geolocation, payment, clipboard-read,
    # display-capture, fullscreen, motion-sensor, compass, XR, or
    # idle-detection flow (verified by grep in the earlier sweeps:
    # zero IdleDetector/requestIdleCallback matches and zero
    # case-insensitive idle matches across frontend/app/src, and the
    # remaining flows verified absent).
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
