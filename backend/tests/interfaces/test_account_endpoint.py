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


@pytest.mark.asyncio
async def test_account_refresh_without_cookie_returns_forbidden_with_cache_and_security_headers(client: AsyncClient):
    """
        The account refresh POST without a refresh cookie:
    """
    # The refresh route's missing-cookie branch had no header lock:
    # it raises before any service call, so no fixture, DB row, or
    # live service is needed — the httpx client sends no cookies by
    # default, the Cookies model defaults refresh_token to None, and
    # the handler raises ForbiddenException("Refresh token missing!")
    # before touching the auth service. The central ApiBaseException
    # handler maps ForbiddenException to 403 (api/__init__.py) and
    # stamps Cache-Control: no-store plus Pragma: no-cache on every
    # such error response, so a cached 403 could otherwise be served
    # to a different user after an account switch on a shared machine
    # — the same class as the tenant-create 406 lock. The pure-ASGI
    # security-headers middleware stamps every HTTP response with no
    # path exclusions, so the 403 must carry the same headers as the
    # logout 200 above.
    response = await client.post("/account/refresh")
    assert response.status_code == 403
    assert response.json()["error"] == "Refresh token missing!"
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the twelve most sensitive directives as disabled, mirroring
    # the logout lock, using substring checks so later additions
    # to the list do not break this test. The full value lives in
    # _SECURITY_HEADERS. Each directive is safe to lock here for the
    # same reasons as on the other routes: the SPA has no camera,
    # microphone, geolocation, payment, clipboard-read,
    # display-capture, fullscreen, motion-sensor, compass, XR, or
    # idle-detection flow (verified by grep in the earlier sweeps).
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
async def test_account_passkey_register_options_unknown_email_returns_404_with_cache_and_security_headers(client: AsyncClient):
    """
        The account passkey register-options POST for an unknown email:
    """
    # The passkey register-options route had no header lock: it is the
    # first account route after logout/refresh whose error path needs
    # no authenticated user and no seeded row. It carries no permission
    # dependency and no CurrentUser dependency, so the mocked host user
    # (whose role_id points at no row) cannot interfere here — unlike
    # the permission-gated routes, no role lookup runs at all. The
    # handler resolves the auth service from the container (no lookup),
    # then calls user_service.find_by_email before the try block — the
    # comment on the handler says so explicitly, so an unknown email
    # keeps its 404 instead of being wrapped into the 406
    # PassKeyException. Against the fresh test DB the lookup finds no
    # User row and raises UserNotFoundException (core/exceptions.py),
    # a NotFoundException subclass, which the central ApiBaseException
    # handler maps to 404 with Cache-Control: no-store and Pragma:
    # no-cache (api/__init__.py). No passkey record is created, no
    # webauthn options are generated, and no email is sent on this
    # path: the failure happens before passkey_service is ever called.
    # The body is a bare JSON string because the endpoint declares
    # email as EmailStr = Body(...), not a DTO object.
    response = await client.post(
        "/account/passkey/register_options", json="unknown@example.com"
    )
    assert response.status_code == 404
    assert response.json()["code"] == 404
    assert "User" in response.json()["error"]
    assert "unknown@example.com" in response.json()["error"]
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"
    # Same security-headers lock as the logout/refresh tests: the
    # pure-ASGI middleware stamps every HTTP response with no path
    # exclusions, so the 404 must carry the same headers.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the twelve most sensitive directives as disabled, mirroring
    # the logout lock, using substring checks so later additions
    # to the list do not break this test. Each directive is safe to
    # lock here for the same reasons as on the other routes: the SPA
    # has no camera, microphone, geolocation, payment, clipboard-read,
    # display-capture, fullscreen, motion-sensor, compass, XR, or
    # idle-detection flow (verified by grep in the earlier sweeps).
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
