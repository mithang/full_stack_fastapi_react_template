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


@pytest.mark.asyncio
async def test_delete_sso_settings_with_missing_role_returns_404_with_cache_and_security_headers(client: AsyncClient):
    """
        The SSO settings delete DELETE:
    """
    # Fifth-path lock for the SSO area, whose tests covered only
    # the settings list GET, the available-providers catalogue
    # GET, the single-record detail GET, and the create POST:
    # the delete DELETE had no header lock, so dropping that
    # route — or weakening the central error-response headers —
    # would previously have gone uncaught. It carries the same
    # router-level FULL_ACCESS dependency as the other routes:
    # the mocked host user's role_id points at no row in the
    # fresh test database (Role is in the conftest model set),
    # so the permission dependency raises RoleNotFoundException
    # before the handler runs and before delete_sso_settings is
    # ever called — no service call, no record deleted, no side
    # effect, and the path sso_id is never read, so any
    # well-formed id works. The DELETE takes no body or query
    # params, so no 422 can mask the 404. The central
    # ApiBaseException handler turns it into a 404. That 404
    # must still carry the error-response headers: SSO
    # configuration is sensitive auth configuration, so a cached
    # 404 could otherwise be served to a different admin after
    # an account switch on a shared machine, mirroring the list
    # GET lock.
    response = await client.delete(
        "/ssos/68c302ef6bf7a039b7e9b385",
    )
    assert response.status_code == 404
    body = response.json()
    assert body["code"] == 404
    assert "Role" in body["error"]
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the list test: the pure-ASGI
    # middleware stamps every HTTP response with no path
    # exclusions, so the delete 404 must carry the same headers
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
async def test_update_sso_settings_with_missing_role_returns_404_with_cache_and_security_headers(client: AsyncClient):
    """
        The SSO settings update PATCH:
    """
    # Sixth-path lock for the SSO area, whose tests covered only
    # the settings list GET, the available-providers catalogue
    # GET, the single-record detail GET, the create POST, and
    # the delete DELETE: the update PATCH had no header lock, so
    # dropping that route — or weakening the central
    # error-response headers — would previously have gone
    # uncaught. It carries the same router-level FULL_ACCESS
    # dependency as the other routes: the mocked host user's
    # role_id points at no row in the fresh test database (Role
    # is in the conftest model set), so the permission
    # dependency raises RoleNotFoundException before the
    # handler runs, before the scope guard, and before
    # update_sso_settings is ever called — no service call, no
    # record updated, no side effect, and the path sso_id is
    # never read, so any well-formed id works. The body below
    # is a valid UpdateSSOSettingsDto (every field optional, so
    # a single boolean field validates), so body validation
    # cannot mask the 404 with a 422 whichever order FastAPI
    # resolves the body and the router dependency in. The
    # central ApiBaseException handler turns it into a 404.
    # That 404 must still carry the error-response headers: SSO
    # configuration is sensitive auth configuration, so a
    # cached 404 could otherwise be served to a different admin
    # after an account switch on a shared machine, mirroring
    # the list GET lock.
    response = await client.patch(
        "/ssos/68c302ef6bf7a039b7e9b385",
        json={
            "enabled": False,
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
    # exclusions, so the update 404 must carry the same headers
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
async def test_create_sso_settings_outside_tenant_scope_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        The SSO settings create POST scope-guard error path: the
        six missing-role 404 locks cover the router-level
        FULL_ACCESS permission dependency, but no test asserted
        a 403 on POST /ssos/ via the create scope guard -
        function-name grep count 0 for
        create_sso_settings_outside_tenant_scope, verified
        fresh this run. Deleting _assert_create_scope
        (sso_settings_endpoint.py:19-35) would previously have
        gone uncaught, and a tenant caller creating on the host
        DB would then plant an SSO configuration - attacker-
        chosen client id/secret and redirect URI - that host
        SSO logins could pick up for that provider if the host
        has no setting for it yet (the guard's own comment:
        sso_settings_service.get_provider resolves by first
        match in the current DB with no tenant filter). The
        guard runs first in the handler body, before any
        service call, so no record is created. Unlike the
        products/prices locks, the ssos router carries no
        feature gate, so no tenant row needs seeding: the
        TenantMiddleware only sets request.state.tenant_id
        from the X-Tenant-ID header and initialises the tenant
        DB, with no tenant lookup before the handler. The lock
        still uses the mismatched scope the guard is written
        for, mirroring the POST products scope lock: the caller
        is tenant-scoped to 68c302ef6bf7a039b7e9b387 while the
        request carries X-Tenant-ID
        68c302ef6bf7a039b7e9b388, so the guard raises
        ForbiddenException before any create. The router-level
        FULL_ACCESS permission dependency runs before the
        handler body, so the seeded role (id
        68c302ef6bf7a039b7e9b386) must carry FULL_ACCESS:
        get_role_detail calls get_role_by_id with no tenant
        argument (user_access_management.py), so
        _caller_may_access sees a None caller tenant and
        returns True (role_service.py:18-19), and the seeded
        row is visible regardless of the caller's tenant scope
        - the same mechanism the products scope lock relies
        on. The override's RoleDto carries the same
        permission, and the caller override mirrors the
        products lock's pattern (per-test MeResponseDto,
        restored in finally). The body is valid on purpose,
        not {}: CreateSSOSettingsDto requires a non-blank
        client_id (min_length=1, stripped by the model
        validator) and a provider value - the same body as
        the create 404 lock - so an invalid body cannot fail
        validation with 422 and mask the 403 whichever order
        FastAPI resolves the body and the router dependency
        in. The central ApiBaseException handler maps
        ForbiddenException to 403 (api/__init__.py:98-103)
        with {"error": ..., "code": 403} and the no-store/Pragma
        error headers. A future change that drops the guard
        would break this lock while leaving the create 404
        lock green, so the paths are locked separately.
    """
    from beanie import PydanticObjectId

    from api import app
    from api.common.enums.gender import Gender
    from api.domain.dtos.auth_dto import MeResponseDto
    from api.domain.dtos.role_dto import RoleDto
    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission
    from api.infrastructure.security.current_user import get_current_user

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Tenant SSO administrator",
        description="Role carrying FULL_ACCESS for the mocked caller",
        permissions=[Permission.FULL_ACCESS],
    ).insert()

    async def override_get_current_user_tenant_scoped():
        return MeResponseDto(
            first_name="Admin",
            last_name="User",
            id="68c302ef6bf7a039b7e9b385",
            email="admin@example.com",
            gender=Gender.OTHER,
            is_active=True,
            role_id="68c302ef6bf7a039b7e9b386",
            tenant_id="68c302ef6bf7a039b7e9b387",
            created_at="2024-10-01T00:00:00Z",
            updated_at="2024-10-01T00:00:00Z",
            role=RoleDto(
                id="68c302ef6bf7a039b7e9b386",
                name="Tenant SSO administrator",
                description="Role carrying FULL_ACCESS for the mocked caller",
                created_at="2024-10-01T00:00:00Z",
                updated_at="2024-10-01T00:00:00Z",
                permissions=[Permission.FULL_ACCESS],
            ),
            subscription=None,
        )

    original_override = app.dependency_overrides.get(get_current_user)
    app.dependency_overrides[get_current_user] = override_get_current_user_tenant_scoped
    try:
        response = await client.post(
            "/ssos/",
            headers={"X-Tenant-ID": "68c302ef6bf7a039b7e9b388"},
            json={
                "enabled": False,
                "provider": "google",
                "client_id": "test-client-id",
                "client_secret": None,
                "scopes": [],
                "redirect_uris": [],
            },
        )
    finally:
        if original_override is None:
            app.dependency_overrides.pop(get_current_user, None)
        else:
            app.dependency_overrides[get_current_user] = original_override
    assert response.status_code == 403
    body = response.json()
    assert body["code"] == 403
    assert "outside your tenant's scope" in body["error"]
    assert "refresh_token" not in response.headers.get("set-cookie", "")
    # The 403 must still carry the error-response headers: the
    # create handler takes no Response param and sets no-store
    # only on its success-adjacent paths, so on this path they
    # come from the central ApiBaseException handler, and a
    # cached 403 could otherwise be served to a different user
    # after an account switch on a shared machine.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the SSO list test: the
    # pure-ASGI middleware stamps every HTTP response with no
    # path exclusions, so the SSO create POST 403 must carry
    # the same headers as the authenticated GETs, including the
    # exception-handler responses.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened:
    # lock the twelve most sensitive directives as disabled,
    # mirroring the SSO list lock, using substring checks
    # so later additions to the list do not break this test.
    # The full value lives in _SECURITY_HEADERS. Each directive
    # is safe to lock here for the same reasons as on the other
    # routes: the SPA has no camera, microphone, geolocation,
    # payment, clipboard-read, display-capture, fullscreen,
    # motion-sensor, compass, XR, or idle-detection flow
    # (verified by grep in the earlier sweeps and re-verified
    # fresh this run: zero case-insensitive idle matches
    # across frontend/app/src, and the remaining flows
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
    # Postconditions: the guard fires before any SSO-settings
    # service call, so the create is side-effect free - the
    # seeded role is still there with FULL_ACCESS. No
    # SSOSettings row is asserted: SSOSettings is not in the
    # conftest model set, so it cannot be queried from this
    # test, and the guard firing before the service call is
    # what guarantees nothing was created - the role row is
    # the observable postcondition.
    stored_role = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored_role is not None
    assert stored_role.permissions == [Permission.FULL_ACCESS]


@pytest.mark.asyncio
async def test_list_sso_settings_outside_tenant_scope_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        The SSO settings list GET scope-guard error path: the
        six missing-role 404 locks cover the router-level
        FULL_ACCESS permission dependency, and the previous
        run locked the POST create scope guard, but no test
        asserted a 403 on GET /ssos/ via the read scope guard
        - function-name grep count 0 for
        list_sso_settings_outside_tenant_scope, verified fresh
        this run. Deleting _assert_read_scope
        (sso_settings_endpoint.py:36-52) would previously have
        gone uncaught, and a tenant caller reading on the host
        DB would then read tenant-stamped SSO settings sitting
        in the host DB (e.g. planted before the create guard)
        - masked client ids, redirect URIs, and scopes - and
        would also leak an existence signal via the 404, since
        the guard fails closed before any read. The guard runs
        first in the handler body, before any service call, so
        no read happens. Unlike the products/prices locks, the
        ssos router carries no feature gate, so no tenant row
        needs seeding: the TenantMiddleware only sets
        request.state.tenant_id from the X-Tenant-ID header
        and initialises the tenant DB, with no tenant lookup
        before the handler. The lock still uses the mismatched
        scope the guard is written for, mirroring the POST
        create scope lock: the caller is tenant-scoped to
        68c302ef6bf7a039b7e9b387 while the request carries
        X-Tenant-ID 68c302ef6bf7a039b7e9b388, so the guard
        raises ForbiddenException before any read. The
        router-level FULL_ACCESS permission dependency runs
        before the handler body, so the seeded role (id
        68c302ef6bf7a039b7e9b386) must carry FULL_ACCESS:
        get_role_detail calls get_role_by_id with no tenant
        argument (user_access_management.py), so
        _caller_may_access sees a None caller tenant and
        returns True (role_service.py:18-19), and the seeded
        row is visible regardless of the caller's tenant scope
        - the same mechanism the products scope lock relies
        on. The override's RoleDto carries the same
        permission, and the caller override mirrors the
        create lock's pattern (per-test MeResponseDto,
        restored in finally). The GET takes no body or query
        params, so no 422 can mask the 403. The central
        ApiBaseException handler maps ForbiddenException to
        403 (api/__init__.py:98-103) with {"error": ...,
        "code": 403} and the no-store/Pragma error headers.
        A future change that drops the guard would break this
        lock while leaving the list 404 lock green, so the
        paths are locked separately.
    """
    from beanie import PydanticObjectId

    from api import app
    from api.common.enums.gender import Gender
    from api.domain.dtos.auth_dto import MeResponseDto
    from api.domain.dtos.role_dto import RoleDto
    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission
    from api.infrastructure.security.current_user import get_current_user

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Tenant SSO administrator",
        description="Role carrying FULL_ACCESS for the mocked caller",
        permissions=[Permission.FULL_ACCESS],
    ).insert()

    async def override_get_current_user_tenant_scoped():
        return MeResponseDto(
            first_name="Admin",
            last_name="User",
            id="68c302ef6bf7a039b7e9b385",
            email="admin@example.com",
            gender=Gender.OTHER,
            is_active=True,
            role_id="68c302ef6bf7a039b7e9b386",
            tenant_id="68c302ef6bf7a039b7e9b387",
            created_at="2024-10-01T00:00:00Z",
            updated_at="2024-10-01T00:00:00Z",
            role=RoleDto(
                id="68c302ef6bf7a039b7e9b386",
                name="Tenant SSO administrator",
                description="Role carrying FULL_ACCESS for the mocked caller",
                created_at="2024-10-01T00:00:00Z",
                updated_at="2024-10-01T00:00:00Z",
                permissions=[Permission.FULL_ACCESS],
            ),
            subscription=None,
        )

    original_override = app.dependency_overrides.get(get_current_user)
    app.dependency_overrides[get_current_user] = override_get_current_user_tenant_scoped
    try:
        response = await client.get(
            "/ssos/",
            headers={"X-Tenant-ID": "68c302ef6bf7a039b7e9b388"},
        )
    finally:
        if original_override is None:
            app.dependency_overrides.pop(get_current_user, None)
        else:
            app.dependency_overrides[get_current_user] = original_override
    assert response.status_code == 403
    body = response.json()
    assert body["code"] == 403
    assert "outside your tenant's scope" in body["error"]
    assert "refresh_token" not in response.headers.get("set-cookie", "")
    # The 403 must still carry the error-response headers: the
    # list handler sets no-store only after the guard, so on this
    # path they come from the central ApiBaseException handler,
    # and a cached 403 could otherwise be served to a different
    # user after an account switch on a shared machine.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the SSO list test: the
    # pure-ASGI middleware stamps every HTTP response with no
    # path exclusions, so the SSO list GET 403 must carry
    # the same headers as the authenticated GETs, including the
    # exception-handler responses.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened:
    # lock the twelve most sensitive directives as disabled,
    # mirroring the SSO list lock, using substring checks
    # so later additions to the list do not break this test.
    # The full value lives in _SECURITY_HEADERS. Each directive
    # is safe to lock here for the same reasons as on the other
    # routes: the SPA has no camera, microphone, geolocation,
    # payment, clipboard-read, display-capture, fullscreen,
    # motion-sensor, compass, XR, or idle-detection flow
    # (verified by grep in the earlier sweeps and re-verified
    # fresh this run: zero case-insensitive idle matches
    # across frontend/app/src, and the remaining flows
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
    # Postconditions: the guard fires before any SSO-settings
    # service call, so the read is side-effect free - the
    # seeded role is still there with FULL_ACCESS. No
    # SSOSettings row is asserted: SSOSettings is not in the
    # conftest model set, so it cannot be queried from this
    # test, and the guard firing before the service call is
    # what guarantees nothing was read - the role row is
    # the observable postcondition.
    stored_role = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored_role is not None
    assert stored_role.permissions == [Permission.FULL_ACCESS]


@pytest.mark.asyncio
async def test_get_sso_settings_by_id_outside_tenant_scope_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        The SSO settings detail GET scope-guard error path: the
        six missing-role 404 locks cover the router-level
        FULL_ACCESS permission dependency, and the previous
        runs locked the POST create and GET list scope guards,
        but no test asserted a 403 on GET /ssos/{id} via the
        read scope guard - function-name grep count 0 for
        get_sso_settings_by_id_outside_tenant_scope, verified
        fresh this run. Deleting _assert_read_scope
        (sso_settings_endpoint.py:36-52) would previously have
        gone uncaught, and a tenant caller reading on the host
        DB would then read a tenant-stamped SSO setting sitting
        in the host DB (e.g. planted before the create guard)
        - masked client id, redirect URIs, and scopes - and
        would also leak an existence signal via the 404, since
        the guard fails closed before any read. The guard runs
        first in the handler body, before any service call, so
        no read happens, and the path sso_id is never read, so
        any well-formed id works (the detail 404 lock uses the
        same id). Unlike the products/prices locks, the ssos
        router carries no feature gate, so no tenant row needs
        seeding: the TenantMiddleware only sets
        request.state.tenant_id from the X-Tenant-ID header
        and initialises the tenant DB, with no tenant lookup
        before the handler. The lock still uses the mismatched
        scope the guard is written for, mirroring the list
        scope lock: the caller is tenant-scoped to
        68c302ef6bf7a039b7e9b387 while the request carries
        X-Tenant-ID 68c302ef6bf7a039b7e9b388, so the guard
        raises ForbiddenException before any read. The
        router-level FULL_ACCESS permission dependency runs
        before the handler body, so the seeded role (id
        68c302ef6bf7a039b7e9b386) must carry FULL_ACCESS:
        get_role_detail calls get_role_by_id with no tenant
        argument (user_access_management.py), so
        _caller_may_access sees a None caller tenant and
        returns True (role_service.py:18-19), and the seeded
        row is visible regardless of the caller's tenant scope
        - the same mechanism the products scope lock relies
        on. The override's RoleDto carries the same
        permission, and the caller override mirrors the
        list lock's pattern (per-test MeResponseDto,
        restored in finally). The GET takes no body or query
        params, so no 422 can mask the 403. The central
        ApiBaseException handler maps ForbiddenException to
        403 (api/__init__.py:98-103) with {"error": ...,
        "code": 403} and the no-store/Pragma error headers.
        A future change that drops the guard would break this
        lock while leaving the detail 404 lock green, so the
        paths are locked separately.
    """
    from beanie import PydanticObjectId

    from api import app
    from api.common.enums.gender import Gender
    from api.domain.dtos.auth_dto import MeResponseDto
    from api.domain.dtos.role_dto import RoleDto
    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission
    from api.infrastructure.security.current_user import get_current_user

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Tenant SSO administrator",
        description="Role carrying FULL_ACCESS for the mocked caller",
        permissions=[Permission.FULL_ACCESS],
    ).insert()

    async def override_get_current_user_tenant_scoped():
        return MeResponseDto(
            first_name="Admin",
            last_name="User",
            id="68c302ef6bf7a039b7e9b385",
            email="admin@example.com",
            gender=Gender.OTHER,
            is_active=True,
            role_id="68c302ef6bf7a039b7e9b386",
            tenant_id="68c302ef6bf7a039b7e9b387",
            created_at="2024-10-01T00:00:00Z",
            updated_at="2024-10-01T00:00:00Z",
            role=RoleDto(
                id="68c302ef6bf7a039b7e9b386",
                name="Tenant SSO administrator",
                description="Role carrying FULL_ACCESS for the mocked caller",
                created_at="2024-10-01T00:00:00Z",
                updated_at="2024-10-01T00:00:00Z",
                permissions=[Permission.FULL_ACCESS],
            ),
            subscription=None,
        )

    original_override = app.dependency_overrides.get(get_current_user)
    app.dependency_overrides[get_current_user] = override_get_current_user_tenant_scoped
    try:
        response = await client.get(
            "/ssos/68c302ef6bf7a039b7e9b385",
            headers={"X-Tenant-ID": "68c302ef6bf7a039b7e9b388"},
        )
    finally:
        if original_override is None:
            app.dependency_overrides.pop(get_current_user, None)
        else:
            app.dependency_overrides[get_current_user] = original_override
    assert response.status_code == 403
    body = response.json()
    assert body["code"] == 403
    assert "outside your tenant's scope" in body["error"]
    assert "refresh_token" not in response.headers.get("set-cookie", "")
    # The 403 must still carry the error-response headers: the
    # detail handler sets no-store only after the guard, so on
    # this path they come from the central ApiBaseException
    # handler, and a cached 403 could otherwise be served to a
    # different user after an account switch on a shared machine.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the SSO list test: the
    # pure-ASGI middleware stamps every HTTP response with no
    # path exclusions, so the SSO detail GET 403 must carry
    # the same headers as the authenticated GETs, including the
    # exception-handler responses.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened:
    # lock the twelve most sensitive directives as disabled,
    # mirroring the SSO list lock, using substring checks
    # so later additions to the list do not break this test.
    # The full value lives in _SECURITY_HEADERS. Each directive
    # is safe to lock here for the same reasons as on the other
    # routes: the SPA has no camera, microphone, geolocation,
    # payment, clipboard-read, display-capture, fullscreen,
    # motion-sensor, compass, XR, or idle-detection flow
    # (verified by grep in the earlier sweeps and re-verified
    # fresh this run: zero case-insensitive idle matches
    # across frontend/app/src, and the remaining flows
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
    # Postconditions: the guard fires before any SSO-settings
    # service call, so the read is side-effect free - the
    # seeded role is still there with FULL_ACCESS. No
    # SSOSettings row is asserted: SSOSettings is not in the
    # conftest model set, so it cannot be queried from this
    # test, and the guard firing before the service call is
    # what guarantees nothing was read - the role row is
    # the observable postcondition.
    stored_role = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored_role is not None
    assert stored_role.permissions == [Permission.FULL_ACCESS]


@pytest.mark.asyncio
async def test_update_sso_settings_outside_tenant_scope_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        The SSO settings update PATCH scope-guard error path: the
        six missing-role 404 locks cover the router-level
        FULL_ACCESS permission dependency, and the previous
        runs locked the POST create, GET list, and GET detail
        scope guards, but no test asserted a 403 on PATCH
        /ssos/{id} via the update scope guard - function-name
        grep count 0 for
        update_sso_settings_outside_tenant_scope, verified
        fresh this run. Deleting _assert_update_scope
        (sso_settings_endpoint.py:53-77) would previously have
        gone uncaught, and a tenant caller updating on the host
        DB would then overwrite a tenant-stamped SSO setting
        sitting in the host DB (e.g. planted before the create
        guard) - edited credentials host SSO logins could pick
        up, or a deleted provider. The guard runs first in the
        handler body, before any service call, so no write
        happens, and the path sso_id is never read, so any
        well-formed id works (the update 404 lock uses the same
        id). Unlike the products/prices locks, the ssos router
        carries no feature gate, so no tenant row needs
        seeding: the TenantMiddleware only sets
        request.state.tenant_id from the X-Tenant-ID header
        and initialises the tenant DB, with no tenant lookup
        before the handler. The lock still uses the mismatched
        scope the guard is written for, mirroring the detail
        scope lock: the caller is tenant-scoped to
        68c302ef6bf7a039b7e9b387 while the request carries
        X-Tenant-ID 68c302ef6bf7a039b7e9b388, so the guard
        raises ForbiddenException before any write. The
        router-level FULL_ACCESS permission dependency runs
        before the handler body, so the seeded role (id
        68c302ef6bf7a039b7e9b386) must carry FULL_ACCESS:
        get_role_detail calls get_role_by_id with no tenant
        argument (user_access_management.py), so
        _caller_may_access sees a None caller tenant and
        returns True (role_service.py:18-19), and the seeded
        row is visible regardless of the caller's tenant scope
        - the same mechanism the products scope lock relies
        on. The override's RoleDto carries the same
        permission, and the caller override mirrors the
        detail lock's pattern (per-test MeResponseDto,
        restored in finally). The body below is a valid
        UpdateSSOSettingsDto (every field optional, so a
        single boolean field validates), so body validation
        cannot mask the 403 with a 422. The central
        ApiBaseException handler maps ForbiddenException to
        403 (api/__init__.py:98-103) with {"error": ...,
        "code": 403} and the no-store/Pragma error headers.
        A future change that drops the guard would break this
        lock while leaving the update 404 lock green, so the
        paths are locked separately.
    """
    from beanie import PydanticObjectId

    from api import app
    from api.common.enums.gender import Gender
    from api.domain.dtos.auth_dto import MeResponseDto
    from api.domain.dtos.role_dto import RoleDto
    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission
    from api.infrastructure.security.current_user import get_current_user

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Tenant SSO administrator",
        description="Role carrying FULL_ACCESS for the mocked caller",
        permissions=[Permission.FULL_ACCESS],
    ).insert()

    async def override_get_current_user_tenant_scoped():
        return MeResponseDto(
            first_name="Admin",
            last_name="User",
            id="68c302ef6bf7a039b7e9b385",
            email="admin@example.com",
            gender=Gender.OTHER,
            is_active=True,
            role_id="68c302ef6bf7a039b7e9b386",
            tenant_id="68c302ef6bf7a039b7e9b387",
            created_at="2024-10-01T00:00:00Z",
            updated_at="2024-10-01T00:00:00Z",
            role=RoleDto(
                id="68c302ef6bf7a039b7e9b386",
                name="Tenant SSO administrator",
                description="Role carrying FULL_ACCESS for the mocked caller",
                created_at="2024-10-01T00:00:00Z",
                updated_at="2024-10-01T00:00:00Z",
                permissions=[Permission.FULL_ACCESS],
            ),
            subscription=None,
        )

    original_override = app.dependency_overrides.get(get_current_user)
    app.dependency_overrides[get_current_user] = override_get_current_user_tenant_scoped
    try:
        response = await client.patch(
            "/ssos/68c302ef6bf7a039b7e9b385",
            json={
                "enabled": False,
            },
            headers={"X-Tenant-ID": "68c302ef6bf7a039b7e9b388"},
        )
    finally:
        if original_override is None:
            app.dependency_overrides.pop(get_current_user, None)
        else:
            app.dependency_overrides[get_current_user] = original_override
    assert response.status_code == 403
    body = response.json()
    assert body["code"] == 403
    assert "outside your tenant's scope" in body["error"]
    assert "refresh_token" not in response.headers.get("set-cookie", "")
    # The 403 must still carry the error-response headers: the
    # update handler takes no Response param and sets no-store
    # only on the success path, so on this path they come from
    # the central ApiBaseException handler, and a cached 403
    # could otherwise be served to a different user after an
    # account switch on a shared machine.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the SSO list test: the
    # pure-ASGI middleware stamps every HTTP response with no
    # path exclusions, so the SSO update PATCH 403 must carry
    # the same headers as the authenticated GETs, including the
    # exception-handler responses.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened:
    # lock the twelve most sensitive directives as disabled,
    # mirroring the SSO list lock, using substring checks
    # so later additions to the list do not break this test.
    # The full value lives in _SECURITY_HEADERS. Each directive
    # is safe to lock here for the same reasons as on the other
    # routes: the SPA has no camera, microphone, geolocation,
    # payment, clipboard-read, display-capture, fullscreen,
    # motion-sensor, compass, XR, or idle-detection flow
    # (verified by grep in the earlier sweeps and re-verified
    # fresh this run: zero case-insensitive idle matches
    # across frontend/app/src, and the remaining flows
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
    # Postconditions: the guard fires before any SSO-settings
    # service call, so the update is side-effect free - the
    # seeded role is still there with FULL_ACCESS. No
    # SSOSettings row is asserted: SSOSettings is not in the
    # conftest model set, so it cannot be queried from this
    # test, and the guard firing before the service call is
    # what guarantees nothing was updated - the role row is
    # the observable postcondition.
    stored_role = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored_role is not None
    assert stored_role.permissions == [Permission.FULL_ACCESS]


@pytest.mark.asyncio
async def test_delete_sso_settings_outside_tenant_scope_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        The SSO settings delete DELETE scope-guard error path: the
        six missing-role 404 locks cover the router-level
        FULL_ACCESS permission dependency, and the previous
        runs locked the POST create, GET list, GET detail, and
        PATCH update scope guards, but no test asserted a 403
        on DELETE /ssos/{id} via the update scope guard -
        function-name grep count 0 for
        delete_sso_settings_outside_tenant_scope, verified
        fresh this run. Dropping _assert_update_scope
        (sso_settings_endpoint.py:60-77) would previously have
        gone uncaught on the delete route, and a tenant caller
        deleting on the host DB would then remove a
        tenant-stamped SSO setting sitting in the host DB (e.g.
        planted before the create guard) - a provider host SSO
        logins could lose. The guard runs first in the handler
        body (sso_settings_endpoint.py:151-159), before any
        service call, so no delete happens, and the path
        sso_id is never read, so any well-formed id works (the
        delete 404 lock uses the same id). The DELETE takes no
        body or query params, so no 422 can mask the 403.
        Unlike the products/prices locks, the ssos router
        carries no feature gate, so no tenant row needs
        seeding: the TenantMiddleware only sets
        request.state.tenant_id from the X-Tenant-ID header
        and initialises the tenant DB, with no tenant lookup
        before the handler. The lock still uses the mismatched
        scope the guard is written for, mirroring the update
        scope lock: the caller is tenant-scoped to
        68c302ef6bf7a039b7e9b387 while the request carries
        X-Tenant-ID 68c302ef6bf7a039b7e9b388, so the guard
        raises ForbiddenException before any delete. The
        router-level FULL_ACCESS permission dependency runs
        before the handler body, so the seeded role (id
        68c302ef6bf7a039b7e9b386) must carry FULL_ACCESS:
        get_role_detail calls get_role_by_id with no tenant
        argument (user_access_management.py), so
        _caller_may_access sees a None caller tenant and
        returns True (role_service.py:18-19), and the seeded
        row is visible regardless of the caller's tenant scope
        - the same mechanism the products scope lock relies
        on. The override's RoleDto carries the same
        permission, and the caller override mirrors the
        update lock's pattern (per-test MeResponseDto,
        restored in finally). The central
        ApiBaseException handler maps ForbiddenException to
        403 (api/__init__.py:98-103) with {"error": ...,
        "code": 403} and the no-store/Pragma error headers.
        A future change that drops the guard would break this
        lock while leaving the delete 404 lock green, so the
        paths are locked separately.
    """
    from beanie import PydanticObjectId

    from api import app
    from api.common.enums.gender import Gender
    from api.domain.dtos.auth_dto import MeResponseDto
    from api.domain.dtos.role_dto import RoleDto
    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission
    from api.infrastructure.security.current_user import get_current_user

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Tenant SSO administrator",
        description="Role carrying FULL_ACCESS for the mocked caller",
        permissions=[Permission.FULL_ACCESS],
    ).insert()

    async def override_get_current_user_tenant_scoped():
        return MeResponseDto(
            first_name="Admin",
            last_name="User",
            id="68c302ef6bf7a039b7e9b385",
            email="admin@example.com",
            gender=Gender.OTHER,
            is_active=True,
            role_id="68c302ef6bf7a039b7e9b386",
            tenant_id="68c302ef6bf7a039b7e9b387",
            created_at="2024-10-01T00:00:00Z",
            updated_at="2024-10-01T00:00:00Z",
            role=RoleDto(
                id="68c302ef6bf7a039b7e9b386",
                name="Tenant SSO administrator",
                description="Role carrying FULL_ACCESS for the mocked caller",
                created_at="2024-10-01T00:00:00Z",
                updated_at="2024-10-01T00:00:00Z",
                permissions=[Permission.FULL_ACCESS],
            ),
            subscription=None,
        )

    original_override = app.dependency_overrides.get(get_current_user)
    app.dependency_overrides[get_current_user] = override_get_current_user_tenant_scoped
    try:
        response = await client.delete(
            "/ssos/68c302ef6bf7a039b7e9b385",
            headers={"X-Tenant-ID": "68c302ef6bf7a039b7e9b388"},
        )
    finally:
        if original_override is None:
            app.dependency_overrides.pop(get_current_user, None)
        else:
            app.dependency_overrides[get_current_user] = original_override
    assert response.status_code == 403
    body = response.json()
    assert body["code"] == 403
    assert "outside your tenant's scope" in body["error"]
    assert "refresh_token" not in response.headers.get("set-cookie", "")
    # The 403 must still carry the error-response headers: the
    # delete handler takes no Response param and sets no-store
    # only on the success path, so on this path they come from
    # the central ApiBaseException handler, and a cached 403
    # could otherwise be served to a different user after an
    # account switch on a shared machine.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the SSO list test: the
    # pure-ASGI middleware stamps every HTTP response with no
    # path exclusions, so the SSO delete DELETE 403 must carry
    # the same headers as the authenticated GETs, including the
    # exception-handler responses.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened:
    # lock the twelve most sensitive directives as disabled,
    # mirroring the SSO list lock, using substring checks
    # so later additions to the list do not break this test.
    # The full value lives in _SECURITY_HEADERS. Each directive
    # is safe to lock here for the same reasons as on the other
    # routes: the SPA has no camera, microphone, geolocation,
    # payment, clipboard-read, display-capture, fullscreen,
    # motion-sensor, compass, XR, or idle-detection flow
    # (verified by grep in the earlier sweeps and re-verified
    # fresh this run: zero case-insensitive idle matches
    # across frontend/app/src, and the remaining flows
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
    # Postconditions: the guard fires before any SSO-settings
    # service call, so the delete is side-effect free - the
    # seeded role is still there with FULL_ACCESS. No
    # SSOSettings row is asserted: SSOSettings is not in the
    # conftest model set, so it cannot be queried from this
    # test, and the guard firing before the service call is
    # what guarantees nothing was deleted - the role row is
    # the observable postcondition.
    stored_role = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored_role is not None
    assert stored_role.permissions == [Permission.FULL_ACCESS]


@pytest.mark.asyncio
async def test_create_sso_settings_non_bool_enabled_returns_422_with_security_headers(client: AsyncClient):
    """
    The SSO settings create POST with a non-bool
    `enabled` (a JSON list):
    `enabled` is a required `bool` field of
    SSOSettingsDto (inherited by CreateSSOSettingsDto),
    and Pydantic v2 does not coerce lists to bool, so
    request validation rejects the body with 422 before
    the handler body runs.
    """
    # Function-name grep count 0 for
    # create_sso_settings_non_bool_enabled
    # before appending, verified fresh this run, not
    # assumed. This is the FIRST lock of the SSO
    # settings create per-field validation sweep:
    # CreateSSOSettingsDto has seven fields (enabled,
    # provider, client_id, client_secret, scopes,
    # redirect_uris, tenant_id) and this run locks
    # enabled; six remain for future runs. The other
    # fields are sent valid alongside the bad value:
    # provider "google" (a member of the SSOProvider
    # Literal), client_id "test-client-id" (a non-blank
    # str, min_length=1), client_secret None, scopes []
    # and redirect_uris [] -- nothing else can mask
    # the 422. A list is used as the non-bool payload
    # because Pydantic v2 lax mode coerces strings
    # ("true"/"false"/"yes"/"no") and ints (0/1) to
    # bool, so neither pins the non-bool class, exactly
    # as in the billing plan-update active lock. The
    # normalize_credentials model_validator runs only
    # after field validation and only touches
    # client_id/client_secret/scopes when they are
    # already str/list, so it cannot mask the 422. The
    # ssos router carries a FULL_ACCESS permission
    # dependency at router level and no feature gate;
    # FastAPI solves dependencies before validating the
    # endpoint's own body, so the caller role must carry
    # FULL_ACCESS -- otherwise the permission 403/404
    # would mask the 422, exactly as the MANAGE_BILLING
    # requirement in the billing locks. The Role row
    # (id 68c302ef6bf7a039b7e9b386) is seeded for that
    # dependency, mirroring the SSO scope locks, and
    # the override's RoleDto carries the same
    # permission. The _assert_create_scope guard runs
    # inside the handler body, after validation, so it
    # cannot mask the 422 either; the caller tenant_id
    # still matches the X-Tenant-ID header
    # (68c302ef6bf7a039b7e9b388) so the request is
    # otherwise legitimate, and no tenant row needs
    # seeding -- the ssos router has no feature gate
    # and the TenantMiddleware only sets
    # request.state.tenant_id from the header, as in
    # the SSO scope locks. The endpoint sets
    # sso_settings.tenant_id from the caller after
    # validation, so no tenant_id is sent in the body.
    # Deliberately no exact error-type assertion,
    # mirroring the checkout non-string email 422 lock.
    # Deliberately no Cache-Control/Pragma assertion: a
    # 422 is FastAPI request validation, not an
    # ApiBaseException, so the central handler's
    # no-store headers do not apply to it, mirroring
    # the billing 422 locks. The security headers ARE
    # locked: the pure-ASGI middleware stamps every
    # HTTP response, including validation errors, with
    # no path exclusions.
    from beanie import PydanticObjectId

    from api import app
    from api.common.enums.gender import Gender
    from api.domain.dtos.auth_dto import MeResponseDto
    from api.domain.dtos.role_dto import RoleDto
    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission
    from api.infrastructure.security.current_user import get_current_user

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Tenant SSO administrator",
        description="Role carrying FULL_ACCESS for the mocked caller",
        permissions=[Permission.FULL_ACCESS],
    ).insert()

    async def override_get_current_user_tenant_scoped():
        return MeResponseDto(
            first_name="Admin",
            last_name="User",
            id="68c302ef6bf7a039b7e9b385",
            email="admin@example.com",
            gender=Gender.OTHER,
            is_active=True,
            role_id="68c302ef6bf7a039b7e9b386",
            tenant_id="68c302ef6bf7a039b7e9b388",
            created_at="2024-10-01T00:00:00Z",
            updated_at="2024-10-01T00:00:00Z",
            role=RoleDto(
                id="68c302ef6bf7a039b7e9b386",
                name="Tenant SSO administrator",
                description="Role carrying FULL_ACCESS for the mocked caller",
                created_at="2024-10-01T00:00:00Z",
                updated_at="2024-10-01T00:00:00Z",
                permissions=[Permission.FULL_ACCESS],
            ),
            subscription=None,
        )

    original_override = app.dependency_overrides.get(get_current_user)
    app.dependency_overrides[get_current_user] = override_get_current_user_tenant_scoped
    try:
        response = await client.post(
            "/ssos/",
            headers={"X-Tenant-ID": "68c302ef6bf7a039b7e9b388"},
            json={
                "enabled": [True],
                "provider": "google",
                "client_id": "test-client-id",
                "client_secret": None,
                "scopes": [],
                "redirect_uris": [],
            },
        )
    finally:
        if original_override is None:
            app.dependency_overrides.pop(get_current_user, None)
        else:
            app.dependency_overrides[get_current_user] = original_override
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "enabled" in [str(part) for part in err.get("loc", [])]
        for err in detail
    )
    assert "refresh_token" not in response.headers.get("set-cookie", "")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Lock the twelve most sensitive directives as disabled,
    # mirroring the SSO scope locks, using substring checks
    # so later additions to the list do not break this test.
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
    # Postconditions: validation fails before the handler
    # runs, so no SSO-settings service call is made and no
    # record is created -- the seeded role is still there
    # with FULL_ACCESS. No SSOSettings row is asserted:
    # SSOSettings is not in the conftest model set, so it
    # cannot be queried from this test, and validation
    # failing before the handler is what guarantees
    # nothing was created -- the role row is the
    # observable postcondition, as in the SSO scope locks.
    stored_role = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored_role is not None
    assert stored_role.permissions == [Permission.FULL_ACCESS]


@pytest.mark.asyncio
async def test_create_sso_settings_non_string_provider_returns_422_with_security_headers(client: AsyncClient):
    """
    The SSO settings create POST with a non-string
    `provider` (a JSON list):
    `provider` is a required `SSOProvider` Literal field
    of SSOSettingsDto (inherited by
    CreateSSOSettingsDto), and Pydantic v2 does not
    coerce lists to a Literal member, so request
    validation rejects the body with 422 before the
    handler body runs.
    """
    # Function-name grep count 0 for
    # create_sso_settings_non_string_provider
    # before appending, verified fresh this run, not
    # assumed. This is the SECOND lock of the SSO
    # settings create per-field validation sweep:
    # CreateSSOSettingsDto has seven fields (enabled,
    # provider, client_id, client_secret, scopes,
    # redirect_uris, tenant_id) and this run locks
    # provider; five remain for future runs. The other
    # fields are sent valid alongside the bad value:
    # enabled True, client_id "test-client-id" (a
    # non-blank str, min_length=1), client_secret None,
    # scopes [] and redirect_uris [] -- nothing else
    # can mask the 422. A list is used as the
    # non-string payload because a non-member string
    # such as "bogus" would also 422 but would pin the
    # invalid-member class, not the non-string class,
    # and Pydantic v2 lax mode has no list-to-Literal
    # coercion path, exactly as the list payloads in
    # the billing locks. The normalize_credentials
    # model_validator runs only after field validation
    # and only touches client_id/client_secret/scopes
    # when they are already str/list, so it cannot
    # mask the 422. The ssos router carries a
    # FULL_ACCESS permission dependency at router level
    # and no feature gate; FastAPI solves dependencies
    # before validating the endpoint's own body, so the
    # caller role must carry FULL_ACCESS -- otherwise
    # the permission 403/404 would mask the 422,
    # exactly as the MANAGE_BILLING requirement in the
    # billing locks. The Role row (id
    # 68c302ef6bf7a039b7e9b386) is seeded for that
    # dependency, mirroring the SSO scope locks, and
    # the override's RoleDto carries the same
    # permission. The _assert_create_scope guard runs
    # inside the handler body, after validation, so it
    # cannot mask the 422 either; the caller tenant_id
    # still matches the X-Tenant-ID header
    # (68c302ef6bf7a039b7e9b388) so the request is
    # otherwise legitimate, and no tenant row needs
    # seeding -- the ssos router has no feature gate
    # and the TenantMiddleware only sets
    # request.state.tenant_id from the header, as in
    # the SSO scope locks. The endpoint sets
    # sso_settings.tenant_id from the caller after
    # validation, so no tenant_id is sent in the body.
    # Deliberately no exact error-type assertion,
    # mirroring the checkout non-string email 422 lock.
    # Deliberately no Cache-Control/Pragma assertion: a
    # 422 is FastAPI request validation, not an
    # ApiBaseException, so the central handler's
    # no-store headers do not apply to it, mirroring
    # the billing 422 locks. The security headers ARE
    # locked: the pure-ASGI middleware stamps every
    # HTTP response, including validation errors, with
    # no path exclusions.
    from beanie import PydanticObjectId

    from api import app
    from api.common.enums.gender import Gender
    from api.domain.dtos.auth_dto import MeResponseDto
    from api.domain.dtos.role_dto import RoleDto
    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission
    from api.infrastructure.security.current_user import get_current_user

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Tenant SSO administrator",
        description="Role carrying FULL_ACCESS for the mocked caller",
        permissions=[Permission.FULL_ACCESS],
    ).insert()

    async def override_get_current_user_tenant_scoped():
        return MeResponseDto(
            first_name="Admin",
            last_name="User",
            id="68c302ef6bf7a039b7e9b385",
            email="admin@example.com",
            gender=Gender.OTHER,
            is_active=True,
            role_id="68c302ef6bf7a039b7e9b386",
            tenant_id="68c302ef6bf7a039b7e9b388",
            created_at="2024-10-01T00:00:00Z",
            updated_at="2024-10-01T00:00:00Z",
            role=RoleDto(
                id="68c302ef6bf7a039b7e9b386",
                name="Tenant SSO administrator",
                description="Role carrying FULL_ACCESS for the mocked caller",
                created_at="2024-10-01T00:00:00Z",
                updated_at="2024-10-01T00:00:00Z",
                permissions=[Permission.FULL_ACCESS],
            ),
            subscription=None,
        )

    original_override = app.dependency_overrides.get(get_current_user)
    app.dependency_overrides[get_current_user] = override_get_current_user_tenant_scoped
    try:
        response = await client.post(
            "/ssos/",
            headers={"X-Tenant-ID": "68c302ef6bf7a039b7e9b388"},
            json={
                "enabled": True,
                "provider": ["google"],
                "client_id": "test-client-id",
                "client_secret": None,
                "scopes": [],
                "redirect_uris": [],
            },
        )
    finally:
        if original_override is None:
            app.dependency_overrides.pop(get_current_user, None)
        else:
            app.dependency_overrides[get_current_user] = original_override
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "provider" in [str(part) for part in err.get("loc", [])]
        for err in detail
    )
    assert "refresh_token" not in response.headers.get("set-cookie", "")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Lock the twelve most sensitive directives as disabled,
    # mirroring the SSO scope locks, using substring checks
    # so later additions to the list do not break this test.
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
    # Postconditions: validation fails before the handler
    # runs, so no SSO-settings service call is made and no
    # record is created -- the seeded role is still there
    # with FULL_ACCESS. No SSOSettings row is asserted:
    # SSOSettings is not in the conftest model set, so it
    # cannot be queried from this test, and validation
    # failing before the handler is what guarantees
    # nothing was created -- the role row is the
    # observable postcondition, as in the SSO scope locks.
    stored_role = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored_role is not None
    assert stored_role.permissions == [Permission.FULL_ACCESS]


async def test_create_sso_settings_non_string_client_id_returns_422_with_security_headers(client: AsyncClient):
    """
    The SSO settings create POST with a non-string
    `client_id` (a JSON list):
    `client_id` is a required `str` field with
    min_length=1 of CreateSSOSettingsDto, and Pydantic
    v2 does not coerce lists to str, so request
    validation rejects the body with 422 before the
    handler body runs.
    """
    # Function-name grep count 0 for
    # create_sso_settings_non_string_client_id
    # before appending, verified fresh this run, not
    # assumed. This is the THIRD lock of the SSO
    # settings create per-field validation sweep:
    # CreateSSOSettingsDto has seven fields (enabled,
    # provider, client_id, client_secret, scopes,
    # redirect_uris, tenant_id) and this run locks
    # client_id; four remain for future runs. The other
    # fields are sent valid alongside the bad value:
    # enabled True, provider "google" (a valid
    # SSOProvider member), client_secret None, scopes []
    # and redirect_uris [] -- nothing else can mask
    # the 422. A list is used as the non-string payload
    # because a blank string would also 422 but would
    # pin the blank-value class, not the non-string
    # class, and Pydantic v2 lax mode has no
    # list-to-str coercion path, exactly as the list
    # payloads in the billing locks. The
    # normalize_credentials model_validator runs only
    # after field validation and only touches
    # client_id when it is already a str, so it cannot
    # mask the 422. The ssos router carries a
    # FULL_ACCESS permission dependency at router level
    # and no feature gate; FastAPI solves dependencies
    # before validating the endpoint's own body, so the
    # caller role must carry FULL_ACCESS -- otherwise
    # the permission 403/404 would mask the 422,
    # exactly as the MANAGE_BILLING requirement in the
    # billing locks. The Role row (id
    # 68c302ef6bf7a039b7e9b386) is seeded for that
    # dependency, mirroring the SSO scope locks, and
    # the override's RoleDto carries the same
    # permission. The _assert_create_scope guard runs
    # inside the handler body, after validation, so it
    # cannot mask the 422 either; the caller tenant_id
    # still matches the X-Tenant-ID header
    # (68c302ef6bf7a039b7e9b388) so the request is
    # otherwise legitimate, and no tenant row needs
    # seeding -- the ssos router has no feature gate
    # and the TenantMiddleware only sets
    # request.state.tenant_id from the header, as in
    # the SSO scope locks. The endpoint sets
    # sso_settings.tenant_id from the caller after
    # validation, so no tenant_id is sent in the body.
    # Deliberately no exact error-type assertion,
    # mirroring the checkout non-string email 422 lock.
    # Deliberately no Cache-Control/Pragma assertion: a
    # 422 is FastAPI request validation, not an
    # ApiBaseException, so the central handler's
    # no-store headers do not apply to it, mirroring
    # the billing 422 locks. The security headers ARE
    # locked: the pure-ASGI middleware stamps every
    # HTTP response, including validation errors, with
    # no path exclusions.
    from beanie import PydanticObjectId

    from api import app
    from api.common.enums.gender import Gender
    from api.domain.dtos.auth_dto import MeResponseDto
    from api.domain.dtos.role_dto import RoleDto
    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission
    from api.infrastructure.security.current_user import get_current_user

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Tenant SSO administrator",
        description="Role carrying FULL_ACCESS for the mocked caller",
        permissions=[Permission.FULL_ACCESS],
    ).insert()

    async def override_get_current_user_tenant_scoped():
        return MeResponseDto(
            first_name="Admin",
            last_name="User",
            id="68c302ef6bf7a039b7e9b385",
            email="admin@example.com",
            gender=Gender.OTHER,
            is_active=True,
            role_id="68c302ef6bf7a039b7e9b386",
            tenant_id="68c302ef6bf7a039b7e9b388",
            created_at="2024-10-01T00:00:00Z",
            updated_at="2024-10-01T00:00:00Z",
            role=RoleDto(
                id="68c302ef6bf7a039b7e9b386",
                name="Tenant SSO administrator",
                description="Role carrying FULL_ACCESS for the mocked caller",
                created_at="2024-10-01T00:00:00Z",
                updated_at="2024-10-01T00:00:00Z",
                permissions=[Permission.FULL_ACCESS],
            ),
            subscription=None,
        )

    original_override = app.dependency_overrides.get(get_current_user)
    app.dependency_overrides[get_current_user] = override_get_current_user_tenant_scoped
    try:
        response = await client.post(
            "/ssos/",
            headers={"X-Tenant-ID": "68c302ef6bf7a039b7e9b388"},
            json={
                "enabled": True,
                "provider": "google",
                "client_id": ["test-client-id"],
                "client_secret": None,
                "scopes": [],
                "redirect_uris": [],
            },
        )
    finally:
        if original_override is None:
            app.dependency_overrides.pop(get_current_user, None)
        else:
            app.dependency_overrides[get_current_user] = original_override
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "client_id" in [str(part) for part in err.get("loc", [])]
        for err in detail
    )
    assert "refresh_token" not in response.headers.get("set-cookie", "")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Lock the twelve most sensitive directives as disabled,
    # mirroring the SSO scope locks, using substring checks
    # so later additions to the list do not break this test.
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
    # Postconditions: validation fails before the handler
    # runs, so no SSO-settings service call is made and no
    # record is created -- the seeded role is still there
    # with FULL_ACCESS. No SSOSettings row is asserted:
    # SSOSettings is not in the conftest model set, so it
    # cannot be queried from this test, and validation
    # failing before the handler is what guarantees
    # nothing was created -- the role row is the
    # observable postcondition, as in the SSO scope locks.
    stored_role = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored_role is not None
    assert stored_role.permissions == [Permission.FULL_ACCESS]

async def test_create_sso_settings_non_string_client_secret_returns_422_with_security_headers(client: AsyncClient):
    """
    The SSO settings create POST with a non-string
    `client_secret` (a JSON list):
    `client_secret` is an `Optional[str]` field of
    CreateSSOSettingsDto, and Pydantic v2 does not
    coerce lists to str, so request validation
    rejects the body with 422 before the handler body
    runs.
    """
    # Function-name grep count 0 for
    # create_sso_settings_non_string_client_secret
    # before appending, verified fresh this run, not
    # assumed. This is the FOURTH lock of the SSO
    # settings create per-field validation sweep:
    # CreateSSOSettingsDto has seven fields (enabled,
    # provider, client_id, client_secret, scopes,
    # redirect_uris, tenant_id) and this run locks
    # client_secret; three remain for future runs. The
    # other fields are sent valid alongside the bad
    # value: enabled True, provider "google" (a valid
    # SSOProvider member), client_id "test-client-id",
    # scopes [] and redirect_uris [] -- nothing else
    # can mask the 422. A list is used as the
    # non-string payload because a blank string would
    # also 422 but would pin the blank-value class,
    # not the non-string class, and Pydantic v2 lax
    # mode has no list-to-str coercion path, exactly
    # as the list payloads in the billing locks. Note
    # client_secret is Optional, so None is a valid
    # value -- only the non-string type is being
    # locked here. The normalize_credentials
    # model_validator runs only after field validation
    # and only touches client_secret when it is
    # already a str, so it cannot mask the 422. The
    # ssos router carries a FULL_ACCESS permission
    # dependency at router level and no feature gate;
    # FastAPI solves dependencies before validating
    # the endpoint's own body, so the caller role must
    # carry FULL_ACCESS -- otherwise the permission
    # 403/404 would mask the 422, exactly as the
    # MANAGE_BILLING requirement in the billing
    # locks. The Role row (id
    # 68c302ef6bf7a039b7e9b386) is seeded for that
    # dependency, mirroring the SSO scope locks, and
    # the override's RoleDto carries the same
    # permission. The _assert_create_scope guard runs
    # inside the handler body, after validation, so it
    # cannot mask the 422 either; the caller tenant_id
    # still matches the X-Tenant-ID header
    # (68c302ef6bf7a039b7e9b388) so the request is
    # otherwise legitimate, and no tenant row needs
    # seeding -- the ssos router has no feature gate
    # and the TenantMiddleware only sets
    # request.state.tenant_id from the header, as in
    # the SSO scope locks. The endpoint sets
    # sso_settings.tenant_id from the caller after
    # validation, so no tenant_id is sent in the body.
    # Deliberately no exact error-type assertion,
    # mirroring the checkout non-string email 422 lock.
    # Deliberately no Cache-Control/Pragma assertion: a
    # 422 is FastAPI request validation, not an
    # ApiBaseException, so the central handler's
    # no-store headers do not apply to it, mirroring
    # the billing 422 locks. The security headers ARE
    # locked: the pure-ASGI middleware stamps every
    # HTTP response, including validation errors, with
    # no path exclusions.
    from beanie import PydanticObjectId

    from api import app
    from api.common.enums.gender import Gender
    from api.domain.dtos.auth_dto import MeResponseDto
    from api.domain.dtos.role_dto import RoleDto
    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission
    from api.infrastructure.security.current_user import get_current_user

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Tenant SSO administrator",
        description="Role carrying FULL_ACCESS for the mocked caller",
        permissions=[Permission.FULL_ACCESS],
    ).insert()

    async def override_get_current_user_tenant_scoped():
        return MeResponseDto(
            first_name="Admin",
            last_name="User",
            id="68c302ef6bf7a039b7e9b385",
            email="admin@example.com",
            gender=Gender.OTHER,
            is_active=True,
            role_id="68c302ef6bf7a039b7e9b386",
            tenant_id="68c302ef6bf7a039b7e9b388",
            created_at="2024-10-01T00:00:00Z",
            updated_at="2024-10-01T00:00:00Z",
            role=RoleDto(
                id="68c302ef6bf7a039b7e9b386",
                name="Tenant SSO administrator",
                description="Role carrying FULL_ACCESS for the mocked caller",
                created_at="2024-10-01T00:00:00Z",
                updated_at="2024-10-01T00:00:00Z",
                permissions=[Permission.FULL_ACCESS],
            ),
            subscription=None,
        )

    original_override = app.dependency_overrides.get(get_current_user)
    app.dependency_overrides[get_current_user] = override_get_current_user_tenant_scoped
    try:
        response = await client.post(
            "/ssos/",
            headers={"X-Tenant-ID": "68c302ef6bf7a039b7e9b388"},
            json={
                "enabled": True,
                "provider": "google",
                "client_id": "test-client-id",
                "client_secret": ["test-client-secret"],
                "scopes": [],
                "redirect_uris": [],
            },
        )
    finally:
        if original_override is None:
            app.dependency_overrides.pop(get_current_user, None)
        else:
            app.dependency_overrides[get_current_user] = original_override
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "client_secret" in [str(part) for part in err.get("loc", [])]
        for err in detail
    )
    assert "refresh_token" not in response.headers.get("set-cookie", "")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Lock the twelve most sensitive directives as disabled,
    # mirroring the SSO scope locks, using substring checks
    # so later additions to the list do not break this test.
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
    # Postconditions: validation fails before the handler
    # runs, so no SSO-settings service call is made and no
    # record is created -- the seeded role is still there
    # with FULL_ACCESS. No SSOSettings row is asserted:
    # SSOSettings is not in the conftest model set, so it
    # cannot be queried from this test, and validation
    # failing before the handler is what guarantees
    # nothing was created -- the role row is the
    # observable postcondition, as in the SSO scope locks.
    stored_role = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored_role is not None
    assert stored_role.permissions == [Permission.FULL_ACCESS]

async def test_create_sso_settings_non_list_scopes_returns_422_with_security_headers(client: AsyncClient):
    """
    The SSO settings create POST with a non-list
    `scopes` (a JSON string):
    `scopes` is an `Optional[list[str]]` field of
    CreateSSOSettingsDto, and Pydantic v2 does not
    coerce strings to lists, so request validation
    rejects the body with 422 before the handler body
    runs.
    """
    # Function-name grep count 0 for
    # create_sso_settings_non_list_scopes
    # before appending, verified fresh this run, not
    # assumed. This is the FIFTH lock of the SSO
    # settings create per-field validation sweep:
    # CreateSSOSettingsDto has seven fields (enabled,
    # provider, client_id, client_secret, scopes,
    # redirect_uris, tenant_id) and this run locks
    # scopes; two remain for future runs. The
    # other fields are sent valid alongside the bad
    # value: enabled True, provider "google" (a valid
    # SSOProvider member), client_id "test-client-id",
    # client_secret "test-client-secret" and
    # redirect_uris [] -- nothing else can mask the
    # 422. A string is used as the non-list payload
    # because a JSON string cannot be coerced to a
    # list under any Pydantic version, exactly as the
    # string payload in the role-update non-string
    # permissions lock (iteration 2817). Note scopes
    # is Optional with default [], so None is a valid
    # value -- only the non-list type is being locked
    # here. The normalize_credentials model_validator
    # runs only after field validation and only
    # touches scopes when it is already a list, so it
    # cannot mask the 422. The ssos router carries a
    # FULL_ACCESS permission dependency at router
    # level and no feature gate; FastAPI solves
    # dependencies before validating the endpoint's
    # own body, so the caller role must carry
    # FULL_ACCESS -- otherwise the permission 403/404
    # would mask the 422, exactly as the MANAGE_BILLING
    # requirement in the billing locks. The Role row (id
    # 68c302ef6bf7a039b7e9b386) is seeded for that
    # dependency, mirroring the SSO scope locks, and
    # the override's RoleDto carries the same
    # permission. The _assert_create_scope guard runs
    # inside the handler body, after validation, so it
    # cannot mask the 422 either; the caller tenant_id
    # still matches the X-Tenant-ID header
    # (68c302ef6bf7a039b7e9b388) so the request is
    # otherwise legitimate, and no tenant row needs
    # seeding -- the ssos router has no feature gate
    # and the TenantMiddleware only sets
    # request.state.tenant_id from the header, as in
    # the SSO scope locks. The endpoint sets
    # sso_settings.tenant_id from the caller after
    # validation, so no tenant_id is sent in the body.
    # Deliberately no exact error-type assertion,
    # mirroring the checkout non-string email 422 lock.
    # Deliberately no Cache-Control/Pragma assertion: a
    # 422 is FastAPI request validation, not an
    # ApiBaseException, so the central handler's
    # no-store headers do not apply to it, mirroring
    # the billing 422 locks. The security headers ARE
    # locked: the pure-ASGI middleware stamps every
    # HTTP response, including validation errors, with
    # no path exclusions.
    from beanie import PydanticObjectId

    from api import app
    from api.common.enums.gender import Gender
    from api.domain.dtos.auth_dto import MeResponseDto
    from api.domain.dtos.role_dto import RoleDto
    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission
    from api.infrastructure.security.current_user import get_current_user

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Tenant SSO administrator",
        description="Role carrying FULL_ACCESS for the mocked caller",
        permissions=[Permission.FULL_ACCESS],
    ).insert()

    async def override_get_current_user_tenant_scoped():
        return MeResponseDto(
            first_name="Admin",
            last_name="User",
            id="68c302ef6bf7a039b7e9b385",
            email="admin@example.com",
            gender=Gender.OTHER,
            is_active=True,
            role_id="68c302ef6bf7a039b7e9b386",
            tenant_id="68c302ef6bf7a039b7e9b388",
            created_at="2024-10-01T00:00:00Z",
            updated_at="2024-10-01T00:00:00Z",
            role=RoleDto(
                id="68c302ef6bf7a039b7e9b386",
                name="Tenant SSO administrator",
                description="Role carrying FULL_ACCESS for the mocked caller",
                created_at="2024-10-01T00:00:00Z",
                updated_at="2024-10-01T00:00:00Z",
                permissions=[Permission.FULL_ACCESS],
            ),
            subscription=None,
        )

    original_override = app.dependency_overrides.get(get_current_user)
    app.dependency_overrides[get_current_user] = override_get_current_user_tenant_scoped
    try:
        response = await client.post(
            "/ssos/",
            headers={"X-Tenant-ID": "68c302ef6bf7a039b7e9b388"},
            json={
                "enabled": True,
                "provider": "google",
                "client_id": "test-client-id",
                "client_secret": "test-client-secret",
                "scopes": "openid",
                "redirect_uris": [],
            },
        )
    finally:
        if original_override is None:
            app.dependency_overrides.pop(get_current_user, None)
        else:
            app.dependency_overrides[get_current_user] = original_override
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "scopes" in [str(part) for part in err.get("loc", [])]
        for err in detail
    )
    assert "refresh_token" not in response.headers.get("set-cookie", "")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Lock the twelve most sensitive directives as disabled,
    # mirroring the SSO scope locks, using substring checks
    # so later additions to the list do not break this test.
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
    # Postconditions: validation fails before the handler
    # runs, so no SSO-settings service call is made and no
    # record is created -- the seeded role is still there
    # with FULL_ACCESS. No SSOSettings row is asserted:
    # SSOSettings is not in the conftest model set, so it
    # cannot be queried from this test, and validation
    # failing before the handler is what guarantees
    # nothing was created -- the role row is the
    # observable postcondition, as in the SSO scope locks.
    stored_role = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored_role is not None
    assert stored_role.permissions == [Permission.FULL_ACCESS]
