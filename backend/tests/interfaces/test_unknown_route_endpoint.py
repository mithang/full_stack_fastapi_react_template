import pytest
from httpx import AsyncClient

import api


@pytest.mark.asyncio
async def test_unknown_api_route_returns_no_store_404(client: AsyncClient):
    """
        An unmatched /api/v1 route:
    """
    # Absolute URL, so this does not depend on how httpx merges the
    # shared client's /api/v1 base_url with a relative path: the
    # request must reach the app's catch-all react_router with
    # full_path "api/v1/does-not-exist", which returns the
    # {"detail": "API route not found"} 404.
    response = await client.get("http://test/api/v1/does-not-exist")
    assert response.status_code == 404
    assert response.json() == {"detail": "API route not found"}
    # This 404 bypasses the central ApiBaseException handler (it is a
    # routing fallback, not a raised exception), so the no-store
    # headers added to that handler in iteration 1810 did not cover
    # it: without this lock, a cached 404 for a mistyped or removed
    # route could be served to a different user after an account
    # switch on a shared machine, the same class as the success-path
    # and ApiBaseException GET hardening.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"
    # The security-headers middleware (security_headers_middleware.py)
    # must stamp every response, but only the permissions, roles,
    # users, app-configuration, and tenants GETs locked its headers
    # in (iterations 1820-1824) — deleting the middleware
    # registration would have gone uncaught on this route too. The
    # test client runs the real app over ASGI transport, so the
    # pure-ASGI middleware applies here exactly as in production.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the twelve most sensitive directives as disabled, mirroring the
    # user/role paginated locks, using substring checks so later
    # additions to the list do not break this test. The full value
    # lives in _SECURITY_HEADERS. The fifth, clipboard-read, is safe
    # to lock here: the SPA never reads the clipboard (only writeText
    # calls, verified by grep in iteration 1914 and re-verified this
    # run). The sixth, display-capture, is safe to lock here: the
    # SPA has no screen-sharing flow (zero getDisplayMedia calls,
    # verified by grep this run). The seventh, fullscreen, is safe
    # to lock here: the SPA has no fullscreen flow (zero
    # requestFullscreen calls and zero <video>/<audio> elements,
    # verified by grep this run). The eighth, accelerometer, is safe
    # to lock here: the SPA has no motion-sensor flow (zero
    # DeviceMotion/DeviceOrientation/Accelerometer/Gyroscope/
    # Magnetometer matches, verified by grep this run). The ninth,
    # gyroscope, is safe to lock here for the same reason: the SPA
    # has no gyroscope flow (zero Gyroscope/DeviceOrientation
    # matches, verified by grep this run). The tenth, magnetometer,
    # is safe to lock here for the same reason: the SPA has no
    # compass flow (zero Magnetometer matches, verified by grep
    # this run). The eleventh, xr-spatial-tracking, is safe to lock
    # here for the same reason: the SPA has no XR flow (zero
    # navigator.xr/XRSession/XRSystem/immersive-ar/immersive-vr/
    # requestSession matches and no webxr/three dependency,
    # verified by grep this run). The twelfth, idle-detection, is safe
    # to lock here for the same reason: the SPA has no idle-detection
    # flow (zero IdleDetector/requestIdleCallback matches and zero
    # case-insensitive idle matches, verified by grep this run).
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
async def test_spa_shell_returns_no_store_headers(client: AsyncClient):
    """
        An unmatched SPA route:
    """
    # Absolute URL, as in the iteration-1816 lock, so this does not
    # depend on how httpx merges the shared client's /api/v1 base_url:
    # the request must reach the catch-all react_router with a
    # non-api full_path, which serves the committed UI build's
    # index.html. The shell previously set only Cache-Control:
    # no-store, unlike every other no-store site in api/__init__.py,
    # so an HTTP/1.0 cache honouring only Pragma could serve a stale
    # shell from before a deploy, referencing asset files the new
    # build no longer ships.
    response = await client.get("http://test/spa-route-that-does-not-exist")
    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"
    # Same security-headers lock as the unknown-API-route 404 above
    # (iteration 1825): the middleware must stamp every response,
    # including the SPA shell, or deleting its registration would go
    # uncaught on this route too.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the twelve most sensitive directives as disabled, mirroring the
    # unknown-API-route 404 lock above, using substring checks so
    # later additions to the list do not break this test. The full
    # value lives in _SECURITY_HEADERS. The fifth, clipboard-read,
    # is safe to lock here: the SPA never reads the clipboard (only
    # writeText calls, verified by grep in iteration 1914 and
    # re-verified this run). The sixth, display-capture, is safe
    # to lock here: the SPA has no screen-sharing flow (zero
    # getDisplayMedia calls, verified by grep this run). The seventh,
    # fullscreen, is safe to lock here: the SPA has no fullscreen
    # flow (zero requestFullscreen calls and zero video/audio
    # elements, verified by grep this run). The eighth, accelerometer,
    # is safe to lock here: the SPA has no motion-sensor flow (zero
    # DeviceMotion/DeviceOrientation/Accelerometer/Gyroscope/
    # Magnetometer matches, verified by grep this run). The ninth,
    # gyroscope, is safe to lock here for the same reason: the SPA
    # has no gyroscope flow (zero Gyroscope/DeviceOrientation
    # matches, verified by grep this run).
    # The tenth, magnetometer, is safe to lock here for the same
    # reason: the SPA has no compass flow (zero Magnetometer
    # matches, verified by grep this run). The eleventh,
    # xr-spatial-tracking, is safe to lock here for the same reason:
    # the SPA has no XR flow (zero navigator.xr/XRSession/XRSystem/
    # immersive-ar/immersive-vr/requestSession matches and no
    # webxr/three dependency, verified by grep this run). The twelfth,
    # idle-detection, is safe to lock here for the same reason: the
    # SPA has no idle-detection flow (zero IdleDetector/
    # requestIdleCallback matches and zero case-insensitive idle
    # matches, verified by grep this run).
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
async def test_bare_api_path_returns_no_store_404(client: AsyncClient):
    """
        A bare /api GET:
    """
    # The catch-all's api/ branch has two spellings: full_path == "api"
    # and full_path.startswith("api/"). The iteration-1816 lock covered
    # only the startswith spelling (/api/v1/does-not-exist); this locks
    # the bare spelling too, which returns the same 404 body and the
    # same no-store headers from the same return site.
    response = await client.get("http://test/api")
    assert response.status_code == 404
    assert response.json() == {"detail": "API route not found"}
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"
    # Same security-headers lock as the /api/v1/does-not-exist 404
    # above (iteration 1825) and the SPA shell (iteration 1826):
    # the middleware must stamp every response, including this bare
    # /api spelling, or deleting its registration would go uncaught
    # on this route too.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the twelve most sensitive directives as disabled, mirroring the
    # SPA shell lock above, using substring checks so later
    # additions to the list do not break this test. The full value
    # lives in _SECURITY_HEADERS. The fifth, clipboard-read, is safe
    # to lock here: the SPA never reads the clipboard (only writeText
    # calls, verified by grep in iteration 1914 and re-verified this
    # run). The sixth, display-capture, is safe to lock here: the
    # SPA has no screen-sharing flow (zero getDisplayMedia calls,
    # verified by grep this run). The seventh, fullscreen, is safe
    # to lock here: the SPA has no fullscreen flow (zero
    # requestFullscreen calls and zero <video>/<audio> elements,
    # verified by grep this run). The eighth, accelerometer, is safe
    # to lock here: the SPA has no motion-sensor flow (zero
    # DeviceMotion/DeviceOrientation/Accelerometer/Gyroscope/
    # Magnetometer matches, verified by grep this run). The ninth,
    # gyroscope, is safe to lock here for the same reason: the SPA
    # has no gyroscope flow (zero Gyroscope/DeviceOrientation
    # matches, verified by grep this run). The tenth, magnetometer,
    # is safe to lock here for the same reason: the SPA has no
    # compass flow (zero Magnetometer matches, verified by grep
    # this run). The eleventh, xr-spatial-tracking, is safe to lock
    # here for the same reason: the SPA has no XR flow (zero
    # navigator.xr/XRSession/XRSystem/immersive-ar/immersive-vr/
    # requestSession matches and no webxr/three dependency,
    # verified by grep this run). The twelfth, idle-detection, is safe
    # to lock here for the same reason: the SPA has no idle-detection
    # flow (zero IdleDetector/requestIdleCallback matches and zero
    # case-insensitive idle matches, verified by grep this run).
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
async def test_no_build_404_returns_no_store_headers(client: AsyncClient, monkeypatch, tmp_path):
    """
        An unmatched SPA route with no UI build:
    """
    # The committed UI build exists in this checkout, so the no-build
    # branch is unreachable without redirecting it: react_router
    # reads the module-level build_path at request time (the
    # StaticFiles mount reads it only at import), so pointing it
    # at an empty directory reaches the else branch without
    # touching the mounted assets. monkeypatch reverts it after
    # the test, so no other test sees the redirected path.
    monkeypatch.setattr(api, "build_path", str(tmp_path))
    response = await client.get("http://test/spa-route-that-does-not-exist")
    assert response.status_code == 404
    assert response.json() == {"detail": "UI build not found"}
    # This was the only JSON error return site in react_router
    # without any cache directive, while the API 404 and the SPA
    # shell above it both set no-store plus Pragma: without this
    # lock, a cached 404 could keep answering SPA routes after a
    # build is deployed, until the cached entry expires.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"
    # Same security-headers lock as the other tests in this file:
    # the middleware is pure ASGI, so it also applies to this
    # no-build 404 response.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the eleven most sensitive directives as disabled, mirroring the
    # bare /api 404 lock above, using substring checks so later
    # additions to the list do not break this test. The full value
    # lives in _SECURITY_HEADERS. The fifth, clipboard-read, is safe
    # to lock: the SPA only writes to the clipboard, never reads it.
    # The sixth, display-capture, is safe to lock here: the SPA has
    # no screen-sharing flow (no getDisplayMedia calls in the app).
    # The seventh, fullscreen, is safe to lock here: the SPA has no
    # fullscreen flow (no requestFullscreen calls and no video or
    # audio elements in the app). The eighth, accelerometer, is safe
    # to lock here: the SPA has no motion-sensor flow (zero
    # DeviceMotion/DeviceOrientation/Accelerometer/Gyroscope/
    # Magnetometer matches, verified by grep this run). The ninth,
    # gyroscope, is safe to lock here for the same reason: the SPA
    # has no gyroscope flow (zero Gyroscope/DeviceOrientation
    # matches, verified by grep this run). The tenth, magnetometer,
    # is safe to lock here for the same reason: the SPA has no
    # compass flow (zero Magnetometer matches, verified by grep
    # this run). The eleventh, xr-spatial-tracking, is safe to lock
    # here for the same reason: the SPA has no XR flow (zero
    # navigator.xr/XRSession/XRSystem/immersive-ar/immersive-vr/
    # requestSession matches and no webxr/three dependency,
    # verified by grep this run).
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
