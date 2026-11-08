import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_get_storage_settings_with_missing_role_returns_404_with_cache_and_security_headers(client: AsyncClient):
    """
        The storage settings GET:
    """
    # The storage settings area had no interface test file at all, so
    # deleting the storage router from api/__init__.py — or dropping
    # the central ApiBaseException no-store lines or the
    # security-headers middleware registration — would previously
    # have gone uncaught here even though every other interface
    # area locks its headers in. The success path is not asserted
    # here: the GET is permission-gated (MANAGE_STORAGE_SETTINGS
    # via a router-level dependency, with no feature gate in
    # front of it), so it needs a DB role lookup, and the shared
    # conftest client seeds no role — the SSO settings test
    # documents the same exclusion for its endpoint. The error
    # path below is deterministic instead: the mocked host user's
    # role_id points at no row in the fresh test database (Role
    # is in the conftest model set), so the permission dependency
    # raises RoleNotFoundException before the handler runs, and
    # the central ApiBaseException handler turns it into a 404.
    # That 404 must still carry the error-response headers:
    # storage settings carry masked secrets, so a cached 404
    # could otherwise be served to a different admin after an
    # account switch on a shared machine.
    response = await client.get("/storage/")
    assert response.status_code == 404
    body = response.json()
    assert body["code"] == 404
    assert "Role" in body["error"]
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the SSO settings test: the
    # pure-ASGI middleware stamps every HTTP response with no
    # path exclusions, so the storage settings 404 must carry the
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
    # the SSO settings lock, using substring checks so later additions
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
async def test_get_storage_available_providers_with_missing_role_returns_404_with_cache_and_security_headers(client: AsyncClient):
    """
        The storage available-providers GET:
    """
    # Second-path lock for the storage area, whose only test covered
    # the settings list GET: the static provider catalogue GET had
    # no header lock, so dropping that route — or weakening the
    # central error-response headers — would previously have gone
    # uncaught. The route is a distinct GET path (no GET param
    # route exists to shadow it), and it carries the same
    # router-level MANAGE_STORAGE_SETTINGS dependency as the list
    # GET: the mocked host user's role_id points at no row in the
    # fresh test database (Role is in the conftest model set), so
    # the permission dependency raises RoleNotFoundException
    # before the handler runs — no service call, no side effect.
    # The central ApiBaseException handler turns it into a 404.
    # That 404 must still carry the error-response headers:
    # storage settings carry masked secrets, so a cached 404
    # could otherwise be served to a different admin after an
    # account switch on a shared machine, mirroring the list
    # GET lock.
    response = await client.get("/storage/available")
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
async def test_post_storage_configure_with_missing_role_returns_404_with_cache_and_security_headers(client: AsyncClient):
    """
        The storage configure POST:
    """
    # Third-path lock for the storage area, whose tests covered only
    # the settings list GET and the available-providers catalogue
    # GET: the configure POST had no header lock, so dropping that
    # route — or weakening the central error-response headers —
    # would previously have gone uncaught. It carries the same
    # router-level MANAGE_STORAGE_SETTINGS dependency as the two
    # GETs: the mocked host user's role_id points at no row in the
    # fresh test database (Role is in the conftest model set), so
    # the permission dependency raises RoleNotFoundException
    # before the handler runs, before the scope guard, and before
    # configure_storage is ever called — no service call, no
    # record written, no credential persisted, no side effect.
    # The body below is a valid ConfigureStorageSettingsDto
    # (a disabled s3 config, for which the enabled-provider
    # validator requires no region, bucket, or keys), so body
    # validation cannot mask the 404 with a 422 whichever order
    # FastAPI resolves the body and the router dependency in, and
    # it carries no secret values. The central ApiBaseException
    # handler turns it into a 404. That 404 must still carry the
    # error-response headers: storage settings carry masked
    # secrets, so a cached 404 could otherwise be served to a
    # different admin after an account switch on a shared machine,
    # mirroring the list GET lock.
    response = await client.post(
        "/storage/configure",
        json={
            "provider": "s3",
            "is_enabled": False,
            "region": "",
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
    # exclusions, so the configure 404 must carry the same headers
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
async def test_patch_storage_reset_with_missing_role_returns_404_with_cache_and_security_headers(client: AsyncClient):
    """
        The storage reset PATCH:
    """
    # Last storage route with no header lock (list GET,
    # available-providers GET, and configure POST were already
    # locked): dropping that route — or weakening the central
    # error-response headers — would previously have gone
    # uncaught. It carries the same router-level
    # MANAGE_STORAGE_SETTINGS dependency as the other storage
    # routes: the mocked host user's role_id points at no row in
    # the fresh test database (Role is in the conftest model
    # set), so the permission dependency raises
    # RoleNotFoundException before the handler runs, before the
    # scope guard, and before reset_storage is ever called — no
    # service call, no record reset, no credential cleared, no
    # side effect, and the path storage_id is never read. The
    # PATCH takes no body/query params, so no 422 can mask the
    # 404. The central ApiBaseException handler turns it into a
    # 404. That 404 must still carry the error-response headers:
    # storage settings carry masked secrets, so a cached 404
    # could otherwise be served to a different admin after an
    # account switch on a shared machine, mirroring the list
    # GET lock.
    response = await client.patch(
        "/storage/68c302ef6bf7a039b7e9b385/reset",
    )
    assert response.status_code == 404
    body = response.json()
    assert body["code"] == 404
    assert "Role" in body["error"]
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the list test: the pure-ASGI
    # middleware stamps every HTTP response with no path
    # exclusions, so the reset 404 must carry the same headers
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
    # and re-verified fresh this run: no IdleDetector/
    # requestIdleCallback matches and no case-insensitive idle
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
async def test_get_storage_settings_outside_tenant_scope_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        The storage settings list GET scope-guard error path: the
        four missing-role 404 locks cover the router-level
        MANAGE_STORAGE_SETTINGS permission dependency, but no
        test asserted a 403 on GET /storage/ via the read scope
        guard - function-name grep count 0 for
        get_storage_settings_outside_tenant_scope, verified
        fresh this run. Dropping _assert_read_scope
        (storage_endpoint.py:33-51) would previously have gone
        uncaught, and a tenant caller reading on the host DB
        would then read a tenant-stamped storage record sitting
        in the host DB (e.g. planted before the configure
        guard) - masked secrets included. The guard runs first
        in the handler body (storage_endpoint.py:60), before
        any service call, so no read happens and no settings
        leak. The GET takes no body or query params, so no 422
        can mask the 403. Unlike the products/prices locks,
        the storage router carries no feature gate, so no
        tenant row needs seeding: the TenantMiddleware only
        sets request.state.tenant_id from the X-Tenant-ID
        header and initialises the tenant DB, with no tenant
        lookup before the handler. The lock still uses the
        mismatched scope the guard is written for, mirroring
        the SSO settings scope locks: the caller is
        tenant-scoped to 68c302ef6bf7a039b7e9b387 while the
        request carries X-Tenant-ID
        68c302ef6bf7a039b7e9b388, so the guard raises
        ForbiddenException before any read. The router-level
        MANAGE_STORAGE_SETTINGS permission dependency runs
        before the handler body, so the seeded role (id
        68c302ef6bf7a039b7e9b386) must carry that permission:
        get_role_detail calls get_role_by_id with no tenant
        argument (user_access_management.py), so
        _caller_may_access sees a None caller tenant and
        returns True (role_service.py:18-19), and the seeded
        row is visible regardless of the caller's tenant scope
        - the same mechanism the SSO settings scope locks rely
        on. The override's RoleDto carries the same
        permission, and the caller override mirrors the SSO
        locks' pattern (per-test MeResponseDto, restored in
        finally). The central ApiBaseException handler maps
        ForbiddenException to 403 (api/__init__.py:98-103)
        with {"error": ..., "code": 403} and the no-store/
        Pragma error headers. A future change that drops the
        guard would break this lock while leaving the list
        404 lock green, so the paths are locked separately.
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
        name="Tenant storage administrator",
        description="Role carrying MANAGE_STORAGE_SETTINGS for the mocked caller",
        permissions=[Permission.MANAGE_STORAGE_SETTINGS],
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
                name="Tenant storage administrator",
                description="Role carrying MANAGE_STORAGE_SETTINGS for the mocked caller",
                created_at="2024-10-01T00:00:00Z",
                updated_at="2024-10-01T00:00:00Z",
                permissions=[Permission.MANAGE_STORAGE_SETTINGS],
            ),
            subscription=None,
        )

    original_override = app.dependency_overrides.get(get_current_user)
    app.dependency_overrides[get_current_user] = override_get_current_user_tenant_scoped
    try:
        response = await client.get(
            "/storage/",
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
    # list handler takes a Response param and sets no-store only
    # on the success path, so on this path they come from the
    # central ApiBaseException handler, and a cached 403 could
    # otherwise be served to a different user after an account
    # switch on a shared machine.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the storage list test: the
    # pure-ASGI middleware stamps every HTTP response with no
    # path exclusions, so the storage list GET 403 must carry
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
    # mirroring the list lock, using substring checks so later
    # additions to the list do not break this test. The full
    # value lives in _SECURITY_HEADERS. Each directive is safe
    # to lock here for the same reasons as on the other routes:
    # the SPA has no camera, microphone, geolocation, payment,
    # clipboard-read, display-capture, fullscreen,
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
    # Postconditions: the guard fires before any storage
    # service call, so the read is side-effect free - the
    # seeded role is still there with
    # MANAGE_STORAGE_SETTINGS. No StorageSettings row is
    # asserted: StorageSettings is not in the conftest model
    # set, so it cannot be queried from this test, and the
    # guard firing before the service call is what guarantees
    # nothing was read - the role row is the observable
    # postcondition.
    stored_role = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored_role is not None
    assert stored_role.permissions == [Permission.MANAGE_STORAGE_SETTINGS]


@pytest.mark.asyncio
async def test_post_storage_configure_outside_tenant_scope_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        The storage configure POST scope-guard error path: the
        four missing-role 404 locks cover the router-level
        MANAGE_STORAGE_SETTINGS permission dependency and the
        GET scope lock covers _assert_read_scope, but no test
        asserted a 403 on POST /storage/configure via the
        create scope guard - function-name grep count 0 for
        configure_storage_outside_tenant_scope, verified
        fresh this run. Dropping _assert_create_scope
        (storage_endpoint.py:88-111) would previously have
        gone uncaught, and a tenant caller configuring on
        the host DB would then disable the host DB's active
        storages and plant a record stamped with their own
        tenant_id in the host DB - invisible to their own
        tenant DB, visible in the host global list. The guard
        runs first in the handler body
        (storage_endpoint.py:127), before the try block, so
        no write happens, no credential is persisted, and
        the ForbiddenException is not degraded to a 400 by
        the generic except below. The body below is a valid
        ConfigureStorageSettingsDto (a disabled s3 config,
        for which the enabled-provider validator requires no
        region, bucket, or keys, and it carries no secret
        values), so body validation cannot mask the 403 with
        a 422 whichever order FastAPI resolves the body and
        the router dependency in. Unlike the products/prices
        locks, the storage router carries no feature gate, so
        no tenant row needs seeding: the TenantMiddleware
        only sets request.state.tenant_id from the X-Tenant-ID
        header and initialises the tenant DB, with no tenant
        lookup before the handler. The lock still uses the
        mismatched scope the guard is written for, mirroring
        the GET scope lock and the SSO settings scope locks:
        the caller is tenant-scoped to
        68c302ef6bf7a039b7e9b387 while the request carries
        X-Tenant-ID 68c302ef6bf7a039b7e9b388, so the guard
        raises ForbiddenException before any write. The
        router-level MANAGE_STORAGE_SETTINGS permission
        dependency runs before the handler body, so the
        seeded role (id 68c302ef6bf7a039b7e9b386) must carry
        that permission: get_role_detail calls get_role_by_id
        with no tenant argument
        (user_access_management.py), so _caller_may_access
        sees a None caller tenant and returns True
        (role_service.py:18-19), and the seeded row is
        visible regardless of the caller's tenant scope -
        the same mechanism the GET scope lock relies on. The
        override's RoleDto carries the same permission, and
        the caller override mirrors the GET lock's pattern
        (per-test MeResponseDto, restored in finally). The
        central ApiBaseException handler maps
        ForbiddenException to 403 (api/__init__.py:98-103)
        with {"error": ..., "code": 403} and the no-store/
        Pragma error headers. A future change that drops the
        guard would break this lock while leaving the
        configure 404 lock green, so the paths are locked
        separately.
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
        name="Tenant storage administrator",
        description="Role carrying MANAGE_STORAGE_SETTINGS for the mocked caller",
        permissions=[Permission.MANAGE_STORAGE_SETTINGS],
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
                name="Tenant storage administrator",
                description="Role carrying MANAGE_STORAGE_SETTINGS for the mocked caller",
                created_at="2024-10-01T00:00:00Z",
                updated_at="2024-10-01T00:00:00Z",
                permissions=[Permission.MANAGE_STORAGE_SETTINGS],
            ),
            subscription=None,
        )

    original_override = app.dependency_overrides.get(get_current_user)
    app.dependency_overrides[get_current_user] = override_get_current_user_tenant_scoped
    try:
        response = await client.post(
            "/storage/configure",
            json={
                "provider": "s3",
                "is_enabled": False,
                "region": "",
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
    # configure handler takes no Response param and sets no
    # cache headers at all, so on this path they come from the
    # central ApiBaseException handler, and a cached 403 could
    # otherwise be served to a different user after an account
    # switch on a shared machine.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the storage list test: the
    # pure-ASGI middleware stamps every HTTP response with no
    # path exclusions, so the storage configure POST 403 must
    # carry the same headers as the authenticated GETs,
    # including the exception-handler responses.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened:
    # lock the twelve most sensitive directives as disabled,
    # mirroring the list lock, using substring checks so later
    # additions to the list do not break this test. The full
    # value lives in _SECURITY_HEADERS. Each directive is safe
    # to lock here for the same reasons as on the other routes:
    # the SPA has no camera, microphone, geolocation, payment,
    # clipboard-read, display-capture, fullscreen,
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
    # Postconditions: the guard fires before any storage
    # service call, so the configure is side-effect free - the
    # seeded role is still there with
    # MANAGE_STORAGE_SETTINGS. No StorageSettings row is
    # asserted: StorageSettings is not in the conftest model
    # set, so it cannot be queried from this test, and the
    # guard firing before the service call is what guarantees
    # nothing was written - the role row is the observable
    # postcondition.
    stored_role = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored_role is not None
    assert stored_role.permissions == [Permission.MANAGE_STORAGE_SETTINGS]


@pytest.mark.asyncio
async def test_patch_storage_reset_outside_tenant_scope_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        The storage reset PATCH scope-guard error path: the
        four missing-role 404 locks cover the router-level
        MANAGE_STORAGE_SETTINGS permission dependency, the
        GET scope lock covers _assert_read_scope and the
        configure POST scope lock covers
        _assert_create_scope, but no test asserted a 403 on
        PATCH /storage/{id}/reset via the reset scope guard
        - function-name grep count 0 for
        reset_storage_outside_tenant_scope, verified fresh
        this run. Dropping _assert_reset_scope
        (storage_endpoint.py:145-170) would previously have
        gone uncaught, and a tenant caller resetting on the
        host DB would then disable and clear the credentials
        of a tenant-stamped storage record sitting in the
        host DB (e.g. planted before the create guard) - the
        stamp check in the service passes because the record
        carries the caller's own tenant_id. The guard runs
        first in the handler body
        (storage_endpoint.py:177), before the try block, so
        no reset happens, no credential is cleared, and the
        ForbiddenException is not degraded by the generic
        except below. The PATCH takes no body or query params,
        so no 422 can mask the 403 whichever order FastAPI
        resolves the path param and the router dependency in.
        Unlike the products/prices locks, the storage router
        carries no feature gate, so no tenant row needs
        seeding: the TenantMiddleware only sets
        request.state.tenant_id from the X-Tenant-ID header
        and initialises the tenant DB, with no tenant lookup
        before the handler. The lock still uses the mismatched
        scope the guard is written for, mirroring the GET and
        configure scope locks and the SSO settings scope
        locks: the caller is tenant-scoped to
        68c302ef6bf7a039b7e9b387 while the request carries
        X-Tenant-ID 68c302ef6bf7a039b7e9b388, so the guard
        raises ForbiddenException before any reset. The
        router-level MANAGE_STORAGE_SETTINGS permission
        dependency runs before the handler body, so the
        seeded role (id 68c302ef6bf7a039b7e9b386) must carry
        that permission: get_role_detail calls get_role_by_id
        with no tenant argument
        (user_access_management.py), so _caller_may_access
        sees a None caller tenant and returns True
        (role_service.py:18-19), and the seeded row is
        visible regardless of the caller's tenant scope -
        the same mechanism the GET and configure scope locks
        rely on. The override's RoleDto carries the same
        permission, and the caller override mirrors the GET
        and configure locks' pattern (per-test
        MeResponseDto, restored in finally). The central
        ApiBaseException handler maps ForbiddenException to
        403 (api/__init__.py:98-103) with {"error": ...,
        "code": 403} and the no-store/Pragma error headers.
        A future change that drops the guard would break this
        lock while leaving the reset 404 lock green, so the
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
        name="Tenant storage administrator",
        description="Role carrying MANAGE_STORAGE_SETTINGS for the mocked caller",
        permissions=[Permission.MANAGE_STORAGE_SETTINGS],
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
                name="Tenant storage administrator",
                description="Role carrying MANAGE_STORAGE_SETTINGS for the mocked caller",
                created_at="2024-10-01T00:00:00Z",
                updated_at="2024-10-01T00:00:00Z",
                permissions=[Permission.MANAGE_STORAGE_SETTINGS],
            ),
            subscription=None,
        )

    original_override = app.dependency_overrides.get(get_current_user)
    app.dependency_overrides[get_current_user] = override_get_current_user_tenant_scoped
    try:
        response = await client.patch(
            "/storage/68c302ef6bf7a039b7e9b385/reset",
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
    # reset handler takes no Response param and sets no cache
    # headers at all, so on this path they come from the
    # central ApiBaseException handler, and a cached 403 could
    # otherwise be served to a different user after an account
    # switch on a shared machine.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the storage list test: the
    # pure-ASGI middleware stamps every HTTP response with no
    # path exclusions, so the storage reset PATCH 403 must
    # carry the same headers as the authenticated GETs,
    # including the exception-handler responses.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened:
    # lock the twelve most sensitive directives as disabled,
    # mirroring the list lock, using substring checks so later
    # additions to the list do not break this test. The full
    # value lives in _SECURITY_HEADERS. Each directive is safe
    # to lock here for the same reasons as on the other routes:
    # the SPA has no camera, microphone, geolocation, payment,
    # clipboard-read, display-capture, fullscreen,
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
    # Postconditions: the guard fires before any storage
    # service call, so the reset is side-effect free - the
    # seeded role is still there with
    # MANAGE_STORAGE_SETTINGS. No StorageSettings row is
    # asserted: StorageSettings is not in the conftest model
    # set, so it cannot be queried from this test, and the
    # guard firing before the service call is what guarantees
    # nothing was reset - the role row is the observable
    # postcondition.
    stored_role = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored_role is not None
    assert stored_role.permissions == [Permission.MANAGE_STORAGE_SETTINGS]


@pytest.mark.asyncio
async def test_configure_storage_preserves_created_at_on_update(client: AsyncClient):
    """
        The storage-settings re-configure created_at rewrite, not
        yet locked: function-name grep count 0 for
        configure_storage_preserves_created_at_on_update across
        backend/tests source (verified fresh this run).
        StorageSettingsRepository.configure_storage builds its
        update from a fresh entity the service constructs from
        the DTO, so that entity's created_at is "now"; the update
        branch then passed a full model_dump() to
        BaseRepository.update(), which $sets every key it is
        given - so every re-configure silently rewrote the row's
        creation time to the save time (same class as the
        user-preference update fix). The repository is called
        directly here, bypassing the endpoint on purpose: only a
        direct call seeds a row with a known old created_at,
        which no endpoint path can produce deterministically.
        The client fixture is only used to initialise the
        per-test database (conftest.py, db.drop() after); no HTTP
        call is made. StorageSettings is outside the conftest
        model set (conftest.py:25), so the test initializes it
        on the test DB first: init_beanie on the same URI/db
        name the conftest fixture uses
        (mongodb://localhost:27012/test_db, api_test_db),
        mirroring the branding/app-configuration tests'
        second-init precedent. The seeded row is disabled, so
        disable_all_active_storages is a no-op and the update
        branch is the only write. The old code would return the
        same row id but with created_at rewritten to now; the
        fix carries existing.created_at onto the fresh entity,
        so the stored row keeps 2024-01-01 while the region,
        keys and enabled flag still update and updated_at is
        still stamped centrally. A future change that drops the
        preservation would break this lock while leaving the
        configure 403/404 locks green, so the paths are locked
        separately.
    """
    from datetime import datetime, timezone

    from beanie import PydanticObjectId, init_beanie
    from pymongo import AsyncMongoClient

    from api.domain.entities.storage_settings import StorageProvider, StorageSettings
    from api.infrastructure.persistence.repositories.storage_settings_repository_impl import (
        StorageSettingsRepository,
    )

    mongo_client = AsyncMongoClient("mongodb://localhost:27012/test_db")
    await init_beanie(
        mongo_client["api_test_db"],
        document_models=[StorageSettings],
    )

    repository = StorageSettingsRepository()
    tenant_id = PydanticObjectId()
    seeded_created_at = datetime(2024, 1, 1, tzinfo=timezone.utc)
    seeded = StorageSettings(
        provider=StorageProvider.AWS_S3,
        is_enabled=False,
        region="us-east-1",
        aws_access_key="old-access-key",
        aws_secret_key="old-secret-key",
        aws_bucket_name="old-bucket",
        tenant_id=tenant_id,
        created_at=seeded_created_at,
        updated_by_user_id="68c302ef6bf7a039b7e9b385",
    )
    created = await repository.create(data=seeded.model_dump())

    result_id = await repository.configure_storage(
        setting=StorageSettings(
            provider=StorageProvider.AWS_S3,
            is_enabled=True,
            region="eu-west-1",
            aws_access_key="new-access-key",
            aws_secret_key="new-secret-key",
            aws_bucket_name="new-bucket",
            tenant_id=tenant_id,
            updated_by_user_id="68c302ef6bf7a039b7e9b385",
        )
    )

    # The update branch ran on the seeded row (not a second create).
    assert result_id == created.id
    stored = await repository.single_or_none(provider=StorageProvider.AWS_S3.value)
    assert stored is not None
    assert stored.region == "eu-west-1"
    assert stored.is_enabled is True
    assert stored.aws_bucket_name == "new-bucket"
    assert stored.aws_access_key == "new-access-key"
    assert stored.tenant_id == tenant_id
    # Mongo returns datetimes naive (UTC); normalise before comparing
    # so the assertion holds whether Beanie hands back naive or aware.
    assert stored.created_at.replace(tzinfo=timezone.utc) == seeded_created_at
    assert stored.updated_at.replace(tzinfo=timezone.utc) > seeded_created_at


@pytest.mark.asyncio
async def test_configure_storage_non_string_provider_returns_422_with_security_headers(client: AsyncClient):
    """
    The storage configure POST with a non-string `provider` (a JSON
    list): `provider` is a `Literal["s3", "azure_blob"]` field of
    ConfigureStorageSettingsDto, which the POST /storage/configure
    endpoint takes as its body, and Pydantic v2 does not coerce
    lists to a literal member, so request validation rejects the
    body with 422 before the handler body runs.
    """
    # Function-name grep count 0 for
    # configure_storage_non_string_provider before appending,
    # verified fresh this run, not assumed. This is the FIRST
    # lock of the storage configure per-field validation sweep:
    # ConfigureStorageSettingsDto has nine fields (provider,
    # is_enabled, region, aws_access_key, aws_secret_key,
    # aws_bucket_name, azure_connection_string,
    # azure_container_name, updated_by_user_id); this run locks
    # provider and eight locks remain for future runs. The other
    # fields are sent valid -- a disabled s3 config, for which
    # the enabled-provider model_validator requires no region,
    # bucket, or keys (mirroring the configure 404 lock's valid
    # body), so nothing else can mask the 422. A list is used as
    # the non-string payload because Pydantic v2 lax mode has no
    # list-to-literal coercion path, and a string outside the
    # literal (e.g. "gcs") would pin the invalid-value class, not
    # the non-string class. Note the model_validator runs only
    # after field validation, so it cannot mask the 422 for a
    # list payload either. Verified from
    # backend/api/domain/dtos/storage_settings_dto.py that
    # provider is Literal["s3", "azure_blob"] and that the
    # validator only raises for enabled configs with blank
    # required fields; verified from
    # backend/api/interfaces/api_controllers/storage_endpoint.py
    # that the POST takes ConfigureStorageSettingsDto as its body
    # (line 109) under the router-level MANAGE_STORAGE_SETTINGS
    # dependency (line 24), and that the _assert_create_scope
    # guard and the tenant check both run inside the handler
    # body, after validation, so neither can mask the 422. The
    # POST carries a router-level MANAGE_STORAGE_SETTINGS
    # permission dependency (a parameter dependency, solved
    # before the endpoint's own body is validated), so the caller
    # role must carry MANAGE_STORAGE_SETTINGS -- otherwise the
    # permission 404 would mask the 422, exactly as in the
    # branding FULL_ACCESS locks. The Role row (id
    # 68c302ef6bf7a039b7e9b386) is seeded for that dependency,
    # mirroring the branding scope locks: the dependency looks
    # the role up by the mocked caller's role_id
    # (user_access_management.py get_role_detail), so the default
    # host caller needs no override -- the host scope (no
    # X-Tenant-ID header) is legitimate here because validation
    # fails before the handler's create-scope guard ever runs.
    # Deliberately no exact error-type assertion, mirroring the
    # checkout non-string email 422 lock. Deliberately no
    # Cache-Control/Pragma assertion: a 422 is FastAPI request
    # validation, not an ApiBaseException, so the central
    # handler's no-store headers do not apply to it, mirroring
    # the billing 422 locks. The security headers ARE locked:
    # the pure-ASGI middleware stamps every HTTP response,
    # including validation errors, with no path exclusions.
    from beanie import PydanticObjectId, init_beanie
    from pymongo import AsyncMongoClient

    from api.domain.entities.role import Role
    from api.domain.entities.storage_settings import StorageSettings
    from api.domain.enum.permission import Permission

    mongo_client = AsyncMongoClient("mongodb://localhost:27012/test_db")
    await init_beanie(
        mongo_client["api_test_db"], document_models=[StorageSettings]
    )

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Storage administrator",
        description="Role carrying MANAGE_STORAGE_SETTINGS for the mocked caller",
        permissions=[Permission.MANAGE_STORAGE_SETTINGS],
    ).insert()

    response = await client.post(
        "/storage/configure",
        json={
            "provider": ["s3"],
            "is_enabled": False,
            "region": "",
        },
    )
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
    # mirroring the storage POST 404 lock, using substring
    # checks so later additions to the list do not break
    # this test.
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
    # runs, so no storage service call is made and no record
    # is created -- the seeded role is still there with
    # MANAGE_STORAGE_SETTINGS and no storage settings record
    # exists in the test DB, mirroring the branding scope
    # locks (the init_beanie call above registers
    # StorageSettings, which is not in the conftest model set,
    # so the row can be queried here).
    stored_role = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored_role is not None
    assert stored_role.permissions == [Permission.MANAGE_STORAGE_SETTINGS]
    assert await StorageSettings.find_one() is None
    await mongo_client.close()


@pytest.mark.asyncio
async def test_configure_storage_non_bool_is_enabled_returns_422_with_security_headers(client: AsyncClient):
    """
    The storage configure POST with a non-bool `is_enabled` (a JSON
    list): `is_enabled` is a `bool` field of
    ConfigureStorageSettingsDto, which the POST /storage/configure
    endpoint takes as its body, and Pydantic v2 does not coerce
    lists to bool, so request validation rejects the body with
    422 before the handler body runs.
    """
    # Function-name grep count 0 for
    # configure_storage_non_bool_is_enabled before appending,
    # verified fresh this run, not assumed. This is the SECOND
    # lock of the storage configure per-field validation sweep:
    # ConfigureStorageSettingsDto has nine fields (provider,
    # is_enabled, region, aws_access_key, aws_secret_key,
    # aws_bucket_name, azure_connection_string,
    # azure_container_name, updated_by_user_id); provider was
    # locked in the previous run and this run locks is_enabled,
    # so seven locks remain for future runs. The other fields
    # are sent valid -- a disabled s3 config, for which the
    # enabled-provider model_validator requires no region,
    # bucket, or keys (mirroring the configure 404 lock's valid
    # body), so nothing else can mask the 422. A list is used as
    # the non-bool payload because Pydantic v2 lax mode coerces
    # "true"/"false" strings and 1/0 ints to bool, so neither
    # would pin the non-bool class, while it has no
    # list-to-bool coercion path. Note the model_validator runs
    # only after field validation, so it cannot mask the 422
    # for a list payload either. Verified from
    # backend/api/domain/dtos/storage_settings_dto.py that
    # is_enabled is bool and that the validator only raises for
    # enabled configs with blank required fields; verified from
    # backend/api/interfaces/api_controllers/storage_endpoint.py
    # that the POST takes ConfigureStorageSettingsDto as its body
    # (line 109) under the router-level MANAGE_STORAGE_SETTINGS
    # dependency (line 24), and that the _assert_create_scope
    # guard and the tenant check both run inside the handler
    # body, after validation, so neither can mask the 422. The
    # POST carries a router-level MANAGE_STORAGE_SETTINGS
    # permission dependency (a parameter dependency, solved
    # before the endpoint's own body is validated), so the caller
    # role must carry MANAGE_STORAGE_SETTINGS -- otherwise the
    # permission 404 would mask the 422, exactly as in the
    # branding FULL_ACCESS locks. The Role row (id
    # 68c302ef6bf7a039b7e9b386) is seeded for that dependency,
    # mirroring the branding scope locks: the dependency looks
    # the role up by the mocked caller's role_id
    # (user_access_management.py get_role_detail), so the default
    # host caller needs no override -- the host scope (no
    # X-Tenant-ID header) is legitimate here because validation
    # fails before the handler's create-scope guard ever runs.
    # Deliberately no exact error-type assertion, mirroring the
    # checkout non-string email 422 lock. Deliberately no
    # Cache-Control/Pragma assertion: a 422 is FastAPI request
    # validation, not an ApiBaseException, so the central
    # handler's no-store headers do not apply to it, mirroring
    # the billing 422 locks. The security headers ARE locked:
    # the pure-ASGI middleware stamps every HTTP response,
    # including validation errors, with no path exclusions.
    from beanie import PydanticObjectId, init_beanie
    from pymongo import AsyncMongoClient

    from api.domain.entities.role import Role
    from api.domain.entities.storage_settings import StorageSettings
    from api.domain.enum.permission import Permission

    mongo_client = AsyncMongoClient("mongodb://localhost:27012/test_db")
    await init_beanie(
        mongo_client["api_test_db"], document_models=[StorageSettings]
    )

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Storage administrator",
        description="Role carrying MANAGE_STORAGE_SETTINGS for the mocked caller",
        permissions=[Permission.MANAGE_STORAGE_SETTINGS],
    ).insert()

    response = await client.post(
        "/storage/configure",
        json={
            "provider": "s3",
            "is_enabled": ["true"],
            "region": "",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "is_enabled" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the storage POST 404 lock, using substring
    # checks so later additions to the list do not break
    # this test.
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
    # runs, so no storage service call is made and no record
    # is created -- the seeded role is still there with
    # MANAGE_STORAGE_SETTINGS and no storage settings record
    # exists in the test DB, mirroring the branding scope
    # locks (the init_beanie call above registers
    # StorageSettings, which is not in the conftest model set,
    # so the row can be queried here).
    stored_role = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored_role is not None
    assert stored_role.permissions == [Permission.MANAGE_STORAGE_SETTINGS]
    assert await StorageSettings.find_one() is None


async def test_configure_storage_non_string_region_returns_422_with_security_headers(client: AsyncClient):
    """
    The storage configure POST with a non-string `region` (a JSON
    list): `region` is a `str` field of
    ConfigureStorageSettingsDto, which the POST /storage/configure
    endpoint takes as its body, and Pydantic v2 does not coerce
    lists to str, so request validation rejects the body with
    422 before the handler body runs.
    """
    # Function-name grep count 0 for
    # configure_storage_non_string_region before appending,
    # verified fresh this run, not assumed. This is the THIRD
    # lock of the storage configure per-field validation sweep:
    # ConfigureStorageSettingsDto has nine fields (provider,
    # is_enabled, region, aws_access_key, aws_secret_key,
    # aws_bucket_name, azure_connection_string,
    # azure_container_name, updated_by_user_id); provider and
    # is_enabled were locked in the previous two runs and this
    # run locks region, so six locks remain for future runs. The
    # other fields are sent valid -- a disabled s3 config, for
    # which the enabled-provider model_validator requires no
    # region, bucket, or keys (mirroring the configure 404
    # lock's valid body), so nothing else can mask the 422. A
    # list is used as the non-string payload because Pydantic v2
    # lax mode has no list-to-str coercion path. Note the
    # model_validator runs only after field validation, so it
    # cannot mask the 422 for a list payload either. Verified
    # from backend/api/domain/dtos/storage_settings_dto.py that
    # region is str and that the validator only raises for
    # enabled configs with blank required fields; verified from
    # backend/api/interfaces/api_controllers/storage_endpoint.py
    # that the POST takes ConfigureStorageSettingsDto as its body
    # (line 109) under the router-level MANAGE_STORAGE_SETTINGS
    # dependency (line 24), and that the _assert_create_scope
    # guard and the tenant check both run inside the handler
    # body, after validation, so neither can mask the 422. The
    # POST carries a router-level MANAGE_STORAGE_SETTINGS
    # permission dependency (a parameter dependency, solved
    # before the endpoint's own body is validated), so the caller
    # role must carry MANAGE_STORAGE_SETTINGS -- otherwise the
    # permission 404 would mask the 422, exactly as in the
    # branding FULL_ACCESS locks. The Role row (id
    # 68c302ef6bf7a039b7e9b386) is seeded for that dependency,
    # mirroring the branding scope locks: the dependency looks
    # the role up by the mocked caller's role_id
    # (user_access_management.py get_role_detail), so the default
    # host caller needs no override -- the host scope (no
    # X-Tenant-ID header) is legitimate here because validation
    # fails before the handler's create-scope guard ever runs.
    # Deliberately no exact error-type assertion, mirroring the
    # checkout non-string email 422 lock. Deliberately no
    # Cache-Control/Pragma assertion: a 422 is FastAPI request
    # validation, not an ApiBaseException, so the central
    # handler's no-store headers do not apply to it, mirroring
    # the billing 422 locks. The security headers ARE locked:
    # the pure-ASGI middleware stamps every HTTP response,
    # including validation errors, with no path exclusions.
    from beanie import PydanticObjectId, init_beanie
    from pymongo import AsyncMongoClient

    from api.domain.entities.role import Role
    from api.domain.entities.storage_settings import StorageSettings
    from api.domain.enum.permission import Permission

    mongo_client = AsyncMongoClient("mongodb://localhost:27012/test_db")
    await init_beanie(
        mongo_client["api_test_db"], document_models=[StorageSettings]
    )

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Storage administrator",
        description="Role carrying MANAGE_STORAGE_SETTINGS for the mocked caller",
        permissions=[Permission.MANAGE_STORAGE_SETTINGS],
    ).insert()

    response = await client.post(
        "/storage/configure",
        json={
            "provider": "s3",
            "is_enabled": False,
            "region": ["us-east-1"],
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "region" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the storage POST 404 lock, using substring
    # checks so later additions to the list do not break
    # this test.
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
    # runs, so no storage service call is made and no record
    # is created -- the seeded role is still there with
    # MANAGE_STORAGE_SETTINGS and no storage settings record
    # exists in the test DB, mirroring the branding scope
    # locks (the init_beanie call above registers
    # StorageSettings, which is not in the conftest model set,
    # so the row can be queried here).
    stored_role = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored_role is not None
    assert stored_role.permissions == [Permission.MANAGE_STORAGE_SETTINGS]
    assert await StorageSettings.find_one() is None


async def test_configure_storage_non_string_aws_access_key_returns_422_with_security_headers(client: AsyncClient):
    """
    The storage configure POST with a non-string `aws_access_key`
    (a JSON list): `aws_access_key` is an `Optional[str]` field
    of ConfigureStorageSettingsDto, which the POST
    /storage/configure endpoint takes as its body, and Pydantic
    v2 does not coerce lists to str, so request validation
    rejects the body with 422 before the handler body runs.
    """
    # Function-name grep count 0 for
    # configure_storage_non_string_aws_access_key before
    # appending, verified fresh this run, not assumed. This is
    # the FOURTH lock of the storage configure per-field
    # validation sweep: ConfigureStorageSettingsDto has nine
    # fields (provider, is_enabled, region, aws_access_key,
    # aws_secret_key, aws_bucket_name, azure_connection_string,
    # azure_container_name, updated_by_user_id); provider,
    # is_enabled, and region were locked in the previous three
    # runs and this run locks aws_access_key, so five locks
    # remain for future runs. The other fields are sent valid --
    # a disabled s3 config, for which the enabled-provider
    # model_validator requires no region, bucket, or keys
    # (mirroring the configure 404 lock's valid body), so
    # nothing else can mask the 422. A list is used as the
    # non-string payload because Pydantic v2 lax mode has no
    # list-to-str coercion path. Note the model_validator runs
    # only after field validation, so it cannot mask the 422
    # for a list payload either, and the field_serializer that
    # masks aws_access_key on output runs on serialization,
    # not validation. Verified from
    # backend/api/domain/dtos/storage_settings_dto.py that
    # aws_access_key is Optional[str] (line 9) and that the
    # validator only raises for enabled configs with blank
    # required fields; verified from
    # backend/api/interfaces/api_controllers/storage_endpoint.py
    # that the POST takes ConfigureStorageSettingsDto as its
    # body (line 109) under the router-level
    # MANAGE_STORAGE_SETTINGS dependency (line 24), and that
    # the _assert_create_scope guard and the tenant check both
    # run inside the handler body, after validation, so neither
    # can mask the 422. The POST carries a router-level
    # MANAGE_STORAGE_SETTINGS permission dependency (a
    # parameter dependency, solved before the endpoint's own
    # body is validated), so the caller role must carry
    # MANAGE_STORAGE_SETTINGS -- otherwise the permission 404
    # would mask the 422, exactly as in the branding
    # FULL_ACCESS locks. The Role row (id
    # 68c302ef6bf7a039b7e9b386) is seeded for that dependency,
    # mirroring the branding scope locks: the dependency looks
    # the role up by the mocked caller's role_id
    # (user_access_management.py get_role_detail), so the
    # default host caller needs no override -- the host scope
    # (no X-Tenant-ID header) is legitimate here because
    # validation fails before the handler's create-scope guard
    # ever runs. Deliberately no exact error-type assertion,
    # mirroring the checkout non-string email 422 lock.
    # Deliberately no Cache-Control/Pragma assertion: a 422 is
    # FastAPI request validation, not an ApiBaseException, so
    # the central handler's no-store headers do not apply to
    # it, mirroring the billing 422 locks. The security headers
    # ARE locked: the pure-ASGI middleware stamps every HTTP
    # response, including validation errors, with no path
    # exclusions.
    from beanie import PydanticObjectId, init_beanie
    from pymongo import AsyncMongoClient

    from api.domain.entities.role import Role
    from api.domain.entities.storage_settings import StorageSettings
    from api.domain.enum.permission import Permission

    mongo_client = AsyncMongoClient("mongodb://localhost:27012/test_db")
    await init_beanie(
        mongo_client["api_test_db"], document_models=[StorageSettings]
    )

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Storage administrator",
        description="Role carrying MANAGE_STORAGE_SETTINGS for the mocked caller",
        permissions=[Permission.MANAGE_STORAGE_SETTINGS],
    ).insert()

    response = await client.post(
        "/storage/configure",
        json={
            "provider": "s3",
            "is_enabled": False,
            "region": "",
            "aws_access_key": ["AKIAIOSFODNN7EXAMPLE"],
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "aws_access_key" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the storage POST 404 lock, using substring
    # checks so later additions to the list do not break
    # this test.
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
    # runs, so no storage service call is made and no record
    # is created -- the seeded role is still there with
    # MANAGE_STORAGE_SETTINGS and no storage settings record
    # exists in the test DB, mirroring the branding scope
    # locks (the init_beanie call above registers
    # StorageSettings, which is not in the conftest model set,
    # so the row can be queried here).
    stored_role = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored_role is not None
    assert stored_role.permissions == [Permission.MANAGE_STORAGE_SETTINGS]
    assert await StorageSettings.find_one() is None


async def test_configure_storage_non_string_aws_secret_key_returns_422_with_security_headers(client: AsyncClient):
    """
    The storage configure POST with a non-string `aws_secret_key`
    (a JSON list): `aws_secret_key` is an `Optional[str]` field
    of ConfigureStorageSettingsDto, which the POST
    /storage/configure endpoint takes as its body, and Pydantic
    v2 does not coerce lists to str, so request validation
    rejects the body with 422 before the handler body runs.
    """
    # Function-name grep count 0 for
    # configure_storage_non_string_aws_secret_key before
    # appending, verified fresh this run, not assumed. This is
    # the FIFTH lock of the storage configure per-field
    # validation sweep: ConfigureStorageSettingsDto has nine
    # fields (provider, is_enabled, region, aws_access_key,
    # aws_secret_key, aws_bucket_name, azure_connection_string,
    # azure_container_name, updated_by_user_id); provider,
    # is_enabled, region, and aws_access_key were locked in the
    # previous four runs and this run locks aws_secret_key, so
    # four locks remain for future runs. The other fields are
    # sent valid -- a disabled s3 config, for which the
    # enabled-provider model_validator requires no region,
    # bucket, or keys (mirroring the configure 404 lock's valid
    # body), so nothing else can mask the 422. A list is used
    # as the non-string payload because Pydantic v2 lax mode
    # has no list-to-str coercion path. Note the
    # model_validator runs only after field validation, so it
    # cannot mask the 422 for a list payload either, and the
    # field_serializer that masks aws_secret_key on output
    # lives on AvailableStorageProviderDto and runs on
    # serialization, not validation. Verified from
    # backend/api/domain/dtos/storage_settings_dto.py that
    # aws_secret_key is Optional[str] (line 9) and that the
    # validator only raises for enabled configs with blank
    # required fields; verified from
    # backend/api/interfaces/api_controllers/storage_endpoint.py
    # that the POST takes ConfigureStorageSettingsDto as its
    # body (line 109) under the router-level
    # MANAGE_STORAGE_SETTINGS dependency (line 28), and that
    # the _assert_create_scope guard and the tenant check both
    # run inside the handler body, after validation, so neither
    # can mask the 422. The POST carries a router-level
    # MANAGE_STORAGE_SETTINGS permission dependency (a
    # parameter dependency, solved before the endpoint's own
    # body is validated), so the caller role must carry
    # MANAGE_STORAGE_SETTINGS -- otherwise the permission 404
    # would mask the 422, exactly as in the branding
    # FULL_ACCESS locks. The Role row (id
    # 68c302ef6bf7a039b7e9b386) is seeded for that dependency,
    # mirroring the branding scope locks: the dependency looks
    # the role up by the mocked caller's role_id
    # (user_access_management.py get_role_detail), so the
    # default host caller needs no override -- the host scope
    # (no X-Tenant-ID header) is legitimate here because
    # validation fails before the handler's create-scope guard
    # ever runs. Deliberately no exact error-type assertion,
    # mirroring the checkout non-string email 422 lock.
    # Deliberately no Cache-Control/Pragma assertion: a 422 is
    # FastAPI request validation, not an ApiBaseException, so
    # the central handler's no-store headers do not apply to
    # it, mirroring the billing 422 locks. The security headers
    # ARE locked: the pure-ASGI middleware stamps every HTTP
    # response, including validation errors, with no path
    # exclusions.
    from beanie import PydanticObjectId, init_beanie
    from pymongo import AsyncMongoClient

    from api.domain.entities.role import Role
    from api.domain.entities.storage_settings import StorageSettings
    from api.domain.enum.permission import Permission

    mongo_client = AsyncMongoClient("mongodb://localhost:27012/test_db")
    await init_beanie(
        mongo_client["api_test_db"], document_models=[StorageSettings]
    )

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Storage administrator",
        description="Role carrying MANAGE_STORAGE_SETTINGS for the mocked caller",
        permissions=[Permission.MANAGE_STORAGE_SETTINGS],
    ).insert()

    response = await client.post(
        "/storage/configure",
        json={
            "provider": "s3",
            "is_enabled": False,
            "region": "",
            "aws_secret_key": ["<redacted>"],
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "aws_secret_key" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the storage POST 404 lock, using substring
    # checks so later additions to the list do not break
    # this test.
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
    # runs, so no storage service call is made and no record
    # is created -- the seeded role is still there with
    # MANAGE_STORAGE_SETTINGS and no storage settings record
    # exists in the test DB, mirroring the branding scope
    # locks (the init_beanie call above registers
    # StorageSettings, which is not in the conftest model set,
    # so the row can be queried here).
    stored_role = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored_role is not None
    assert stored_role.permissions == [Permission.MANAGE_STORAGE_SETTINGS]
    assert await StorageSettings.find_one() is None
