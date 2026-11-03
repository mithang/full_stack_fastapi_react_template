import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_get_sso_settings_with_missing_role_returns_404_with_cache_and_security_headers(client: AsyncClient):
    """
        The SSO settings GET:
    """
    # The SSO settings area had no interface test file at all, so
    # deleting the ssos router from api/__init__.py — or dropping
    # the central ApiBaseException no-store lines or the
    # security-headers middleware registration — would previously
    # have gone uncaught here even though every other interface
    # area locks its headers in. The success path is not asserted
    # here: the GET is permission-gated (FULL_ACCESS via a
    # router-level dependency), so it needs a DB role lookup,
    # and the shared conftest client seeds no role — the
    # audit-logs test documents the same exclusion for its
    # endpoint. The error path below is deterministic instead:
    # the mocked host user's role_id points at no row in the
    # fresh test database (Role is in the conftest model set),
    # so the permission dependency raises RoleNotFoundException
    # before the handler runs, and the central ApiBaseException
    # handler turns it into a 404. That 404 must still carry
    # the error-response headers: SSO settings are sensitive
    # auth configuration, so a cached 404 could otherwise be
    # served to a different admin after an account switch on a
    # shared machine.
    response = await client.get("/ssos/")
    assert response.status_code == 404
    body = response.json()
    assert body["code"] == 404
    assert "Role" in body["error"]
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the audit-logs test: the
    # pure-ASGI middleware stamps every HTTP response with no
    # path exclusions, so the SSO settings 404 must carry the
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
    # the audit-logs lock, using substring checks so later additions
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
async def test_get_sso_available_providers_with_missing_role_returns_404_with_cache_and_security_headers(client: AsyncClient):
    """
        The SSO available-providers GET:
    """
    # Second-path lock for the SSO area, whose only test covered
    # the settings list GET: the static provider catalogue GET had
    # no header lock, so dropping that route — or weakening the
    # central error-response headers — would previously have gone
    # uncaught. The route is defined before /{sso_id}, so it is
    # not shadowed by the detail route, and it carries the same
    # router-level FULL_ACCESS dependency as the list GET: the
    # mocked host user's role_id points at no row in the fresh
    # test database (Role is in the conftest model set), so the
    # permission dependency raises RoleNotFoundException before
    # the handler runs and before get_available_sso_providers is
    # ever called — no service call, no side effect. The central
    # ApiBaseException handler turns it into a 404. That 404 must
    # still carry the error-response headers: SSO configuration
    # is sensitive auth configuration, so a cached 404 could
    # otherwise be served to a different admin after an account
    # switch on a shared machine, mirroring the list GET lock.
    response = await client.get("/ssos/available-providers")
    assert response.status_code == 404
    body = response.json()
    assert body["code"] == 404
    assert "Role" in body["error"]
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the list test: the pure-ASGI
    # middleware stamps every HTTP response with no path
    # exclusions, so the catalogue 404 must carry the same headers
    # as the authenticated GETs, including the exception-handler
    # responses.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the twelve most sensitive directives as disabled, mirroring
    # the list lock, using substring checks so later additions
    # to the list do not break this test. The full value lives in
    # _SECURITY_HEADERS. Each directive is safe to lock here for
    # the same reasons as on the other routes: the SPA has no
    # camera, microphone, geolocation, payment, clipboard-read,
    # display-capture, fullscreen, motion-sensor, compass, XR, or
    # idle-detection flow (verified by grep in the earlier sweeps
    # and re-verified fresh this run: zero case-insensitive idle
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
async def test_get_sso_settings_by_id_with_missing_role_returns_404_with_cache_and_security_headers(client: AsyncClient):
    """
        The SSO settings detail GET:
    """
    # Third-path lock for the SSO area, whose tests covered only
    # the settings list GET and the available-providers catalogue
    # GET: the single-record detail GET had no header lock, so
    # dropping that route — or weakening the central
    # error-response headers — would previously have gone
    # uncaught. It carries the same router-level FULL_ACCESS
    # dependency as the list GET: the mocked host user's role_id
    # points at no row in the fresh test database (Role is in
    # the conftest model set), so the permission dependency
    # raises RoleNotFoundException before the handler runs and
    # before get_sso_settings_by_id is ever called — no service
    # call, no side effect, and the path sso_id is never read,
    # so any well-formed id works. The central ApiBaseException
    # handler turns it into a 404. That 404 must still carry the
    # error-response headers: a single SSO record is sensitive
    # auth configuration, so a cached 404 could otherwise be
    # served to a different admin after an account switch on a
    # shared machine, mirroring the list GET lock.
    response = await client.get("/ssos/68c302ef6bf7a039b7e9b385")
    assert response.status_code == 404
    body = response.json()
    assert body["code"] == 404
    assert "Role" in body["error"]
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the list test: the pure-ASGI
    # middleware stamps every HTTP response with no path
    # exclusions, so the detail 404 must carry the same headers
    # as the authenticated GETs, including the
    # exception-handler responses.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the twelve most sensitive directives as disabled, mirroring
    # the list lock, using substring checks so later additions
    # to the list do not break this test. The full value lives in
    # _SECURITY_HEADERS. Each directive is safe to lock here for
    # the same reasons as on the other routes: the SPA has no
    # camera, microphone, geolocation, payment, clipboard-read,
    # display-capture, fullscreen, motion-sensor, compass, XR, or
    # idle-detection flow (verified by grep in the earlier sweeps
    # and re-verified fresh this run: zero case-insensitive idle
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
async def test_create_sso_settings_with_missing_role_returns_404_with_cache_and_security_headers(client: AsyncClient):
    """
        The SSO settings create POST:
    """
    # Fourth-path lock for the SSO area, whose tests covered only
    # the settings list GET, the available-providers catalogue
    # GET, and the single-record detail GET: the create POST had
    # no header lock, so dropping that route — or weakening the
    # central error-response headers — would previously have gone
    # uncaught. It carries the same router-level FULL_ACCESS
    # dependency as the GETs: the mocked host user's role_id
    # points at no row in the fresh test database (Role is in
    # the conftest model set), so the permission dependency
    # raises RoleNotFoundException before the handler runs and
    # before create_sso_settings is ever called — no service
    # call, no record created, no side effect. The body below
    # is a valid CreateSSOSettingsDto (enabled, a literal
    # provider value, a non-blank client_id), so body validation
    # cannot mask the 404 with a 422 whichever order FastAPI
    # resolves the body and the router dependency in; the dummy
    # client_id is never persisted because the dependency raises
    # first. The central ApiBaseException handler turns it into
    # a 404. That 404 must still carry the error-response
    # headers: SSO configuration is sensitive auth
    # configuration, so a cached 404 could otherwise be served
    # to a different admin after an account switch on a shared
    # machine, mirroring the list GET lock.
    response = await client.post(
        "/ssos/",
        json={
            "enabled": False,
            "provider": "google",
            "client_id": "test-client-id",
            "client_secret": None,
            "scopes": [],
            "redirect_uris": [],
        },
    )
    assert response.status_code == 404
    body = response.json()
    assert body["code"] == 404
    assert "Role" in body["error"]
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the list test: the pure-ASGI
    # middleware stamps every HTTP response with no path
    # exclusions, so the create 404 must carry the same headers
    # as the authenticated GETs, including the
    # exception-handler responses.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the twelve most sensitive directives as disabled, mirroring
    # the list lock, using substring checks so later additions
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
