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


@pytest.mark.asyncio
async def test_post_notification_banner_with_missing_role_returns_404_with_cache_and_security_headers(client: AsyncClient):
    """
        The notification banner POST (second path in this area):
    """
    # The notification area's only test covered the banner GET,
    # which carries no permission dependency, so deleting the
    # POST route — or dropping the central ApiBaseException
    # no-store lines or the security-headers middleware
    # registration — would previously have gone uncaught on the
    # write path. The success path is not asserted here: the POST
    # is permission-gated (FULL_ACCESS via a parameter
    # dependency, evaluated before the handler body and before
    # its tenant-scope guard), so it needs a DB role lookup, and
    # the shared conftest client seeds no role. The error path
    # below is deterministic instead: the mocked host user's
    # role_id points at no row in the fresh test database (Role
    # is in the conftest model set), so the permission dependency
    # raises RoleNotFoundException before the handler runs — which
    # matters here because the handler's banner service would
    # otherwise write a record. The body is valid on purpose:
    # is_enabled is required and a disabled banner needs no
    # message, so body validation passes and cannot mask the 404.
    # That 404 must still carry the error-response headers:
    # banner content is admin-edited tenant settings data, so a
    # cached error response could otherwise be served to a
    # different admin after an account switch on a shared machine.
    response = await client.post("/notifications/banner", json={"is_enabled": False})
    assert response.status_code == 404
    body = response.json()
    assert body["code"] == 404
    assert "Role" in body["error"]
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the banner GET test: the
    # pure-ASGI middleware stamps every HTTP response with no
    # path exclusions, so the banner POST 404 must carry the
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
    # the banner GET lock, using substring checks so later
    # additions to the list do not break this test. The full value
    # lives in _SECURITY_HEADERS. Each directive is safe to lock
    # here for the same reasons as on the other routes: the SPA
    # has no camera, microphone, geolocation, payment,
    # clipboard-read, display-capture, fullscreen, motion-sensor,
    # compass, XR, or idle-detection flow (verified by grep in the
    # earlier sweeps and re-verified fresh this run: zero
    # IdleDetector/requestIdleCallback matches and zero
    # case-insensitive idle matches across frontend/app/src,
    # and the remaining flows verified absent).
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
async def test_put_notification_banner_with_missing_role_returns_404_with_cache_and_security_headers(client: AsyncClient):
    """
        The notification banner PUT (third and last path in this area):
    """
    # The notification area's GET and POST were locked, but the PUT
    # /banner/{id} had no test, so deleting the PUT route — or
    # dropping the central ApiBaseException no-store lines or the
    # security-headers middleware registration — would previously
    # have gone uncaught on the update path. The success path is
    # not asserted here: the PUT is permission-gated (FULL_ACCESS
    # via a parameter dependency, evaluated before the handler body
    # and before its tenant-scope guard), so it needs a DB role
    # lookup, and the shared conftest client seeds no role. The
    # error path below is deterministic instead: the mocked host
    # user's role_id points at no row in the fresh test database
    # (Role is in the conftest model set), so the permission
    # dependency raises RoleNotFoundException before the handler
    # runs — which matters here because the handler's banner
    # service would otherwise overwrite a record. The service
    # factory ahead of it only resolves a singleton and
    # get_tenant_id resolves request state without a lookup, and
    # the path id is never read on this path, so there is no side
    # effect and no unseeded-model lookup beyond the role. The
    # body is valid on purpose: is_enabled is required and a
    # disabled banner needs no message (the DTO normalizes a
    # missing message to None for disabled banners), so body
    # validation passes and cannot mask the 404. That 404 must
    # still carry the error-response headers: banner content is
    # admin-edited tenant settings data, so a cached error
    # response could otherwise be served to a different admin
    # after an account switch on a shared machine.
    response = await client.put("/notifications/banner/68c302ef6bf7a039b7e9b385", json={"is_enabled": False})
    assert response.status_code == 404
    body = response.json()
    assert body["code"] == 404
    assert "Role" in body["error"]
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the banner GET and POST tests:
    # the pure-ASGI middleware stamps every HTTP response with no
    # path exclusions, so the banner PUT 404 must carry the same
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
    # the banner GET and POST locks, using substring checks so
    # later additions to the list do not break this test. The full
    # value lives in _SECURITY_HEADERS. Each directive is safe to
    # lock here for the same reasons as on the other routes: the
    # SPA has no camera, microphone, geolocation, payment,
    # clipboard-read, display-capture, fullscreen, motion-sensor,
    # compass, XR, or idle-detection flow (verified by grep in the
    # earlier sweeps and re-verified fresh this run: zero
    # IdleDetector/requestIdleCallback matches and zero
    # case-insensitive idle matches across frontend/app/src,
    # and the remaining flows verified absent).
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
async def test_post_notification_banner_outside_tenant_scope_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        The notification banner POST create-scope-guard error path:
    """
    # The notification banner POST create-scope-guard branch, not
    # yet locked: function-name grep count 0 for
    # post_notification_banner_outside_tenant_scope (verified
    # fresh this run), and no test in this file asserts an error
    # on POST /notifications/banner with an "outside your
    # tenant's scope" message - the locks cover only the banner
    # GET 200 and the POST/PUT missing-role 404s. Deleting
    # _assert_create_scope (notification_endpoint.py:17-33) would
    # previously have gone uncaught, and a tenant caller
    # creating on the host DB (no X-Tenant-ID/subdomain) could
    # then plant a tenant-stamped banner record in the host DB
    # that host banner GETs serve as the application-wide banner
    # (the GET serves the first record in the current DB with no
    # tenant filter). The guard runs first in the handler body,
    # after the FULL_ACCESS permission dependency, so the gate
    # must be satisfied first and the handler must be reachable:
    # the shared conftest mock points at role id
    # 68c302ef6bf7a039b7e9b386 with no row in the fresh test
    # database, so that exact id is seeded here carrying
    # FULL_ACCESS, mirroring the users/billing/branding
    # scope-lock seed precedent. get_role_by_id is called with
    # no tenant filter (role_service.py:79-80) and
    # _caller_may_access returns True when the caller tenant is
    # None (role_service.py:18-19), so the seeded row is visible
    # regardless of the caller's tenant scope, and FULL_ACCESS
    # in the role's permissions passes the dependency outright.
    # The caller is then made tenant-scoped by swapping in a
    # per-test MeResponseDto override (tenant_id set), mirroring
    # the users/billing/branding scope locks' override pattern,
    # and restored in finally so no other test's mock is
    # affected. With no X-Tenant-ID header the tenant middleware
    # resolves host scope, so request_tenant_id is None and the
    # guard raises before create_banner_setting runs. The
    # notification router carries no feature gate (unlike the
    # invoice/checkout routers), so no tenant lookup stands
    # between the request and the guard, and the no-header route
    # reaches it directly - the existing POST 404 lock already
    # proves a headerless POST reaches the permission dependency.
    # The body is {"is_enabled": False} on purpose: is_enabled
    # is required and a disabled banner needs no message, so body
    # validation passes and cannot mask the error. Note the status
    # is 403, not 406: the guard raises ForbiddenException, which
    # the central ApiBaseException handler maps to 403
    # (api/__init__.py:98-103), with {"error": ..., "code": 403}
    # and the no-store/Pragma error headers; the message carries
    # no "Branding Error: " style prefix, so the assertion is a
    # substring match on "outside your tenant's scope". A future
    # change that drops the guard would break this lock while
    # leaving the notification POST 404 lock green, so the paths
    # are locked separately.
    from beanie import PydanticObjectId, init_beanie
    from pymongo import AsyncMongoClient

    from api import app
    from api.common.enums.gender import Gender
    from api.domain.dtos.auth_dto import MeResponseDto
    from api.domain.dtos.role_dto import RoleDto
    from api.domain.entities.notification_settings import NotificationBannerSetting
    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission
    from api.infrastructure.security.current_user import get_current_user

    mongo_client = AsyncMongoClient("mongodb://localhost:27012/test_db")
    await init_beanie(
        mongo_client["api_test_db"], document_models=[NotificationBannerSetting]
    )

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Tenant notification caller",
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
                name="Tenant notification caller",
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
        response = await client.post("/notifications/banner", json={"is_enabled": False})
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
    # handler sets no-store only on the success path, so on this
    # path they come from the central ApiBaseException handler,
    # and a cached 403 could otherwise be served to a different
    # user after an account switch on a shared machine.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the notification banner GET
    # test: the pure-ASGI middleware stamps every HTTP response
    # with no path exclusions, so the banner 403 must carry the
    # same headers as the authenticated calls, including the
    # exception-handler responses.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened:
    # lock the twelve most sensitive directives as disabled,
    # mirroring the banner GET lock, using substring checks so
    # later additions to the list do not break this test. Each
    # directive is safe to lock here for the same reasons as on
    # the other notification routes: the SPA has no camera,
    # microphone, geolocation, payment, clipboard-read,
    # display-capture, fullscreen, motion-sensor, compass, XR,
    # or idle-detection flow (verified by grep in the earlier
    # sweeps).
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
    # Postconditions: the guard fires before
    # create_banner_setting runs, so the request is side-effect
    # free - the seeded role is still there with its permission,
    # and no banner record exists in the test DB for the guard
    # to have squatted.
    stored = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored is not None
    assert stored.permissions == [Permission.FULL_ACCESS]
    assert await NotificationBannerSetting.find_one() is None
    await mongo_client.close()


@pytest.mark.asyncio
async def test_put_notification_banner_outside_tenant_scope_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        The notification banner PUT update-scope-guard error path:
    """
    # The notification banner PUT update-scope-guard branch, not
    # yet locked: function-name grep count 0 for
    # put_notification_banner_outside_tenant_scope (verified
    # fresh this run), and no test in this file asserts an error
    # on PUT /notifications/banner/{id} with an "outside your
    # tenant's scope" message - the locks cover only the banner
    # GET 200, the POST/PUT missing-role 404s, and the POST
    # create-scope 403. Deleting _assert_update_scope
    # (notification_endpoint.py:62-81) would previously have
    # gone uncaught, and a tenant caller updating on the host
    # DB (no X-Tenant-ID/subdomain) could then overwrite a
    # tenant-stamped banner record sitting in the host DB (e.g.
    # planted before the create guard), which host banner GETs
    # serve as the application-wide banner (the GET serves the
    # first record in the current DB with no tenant filter).
    # The guard runs first in the handler body, after the
    # FULL_ACCESS permission dependency, so the gate must be
    # satisfied first and the handler must be reachable: the
    # shared conftest mock points at role id
    # 68c302ef6bf7a039b7e9b386 with no row in the fresh test
    # database, so that exact id is seeded here carrying
    # FULL_ACCESS, mirroring the users/billing/branding and
    # notification create-scope-lock seed precedent.
    # get_role_by_id is called with no tenant filter
    # (role_service.py:79-80) and _caller_may_access returns
    # True when the caller tenant is None
    # (role_service.py:18-19), so the seeded row is visible
    # regardless of the caller's tenant scope, and FULL_ACCESS
    # in the role's permissions passes the dependency outright.
    # The caller is then made tenant-scoped by swapping in a
    # per-test MeResponseDto override (tenant_id set), mirroring
    # the users/billing/branding scope locks' override pattern,
    # and restored in finally so no other test's mock is
    # affected. With no X-Tenant-ID header the tenant middleware
    # resolves host scope, so request_tenant_id is None and the
    # guard raises before update_banner_setting runs. The
    # notification router carries no feature gate (unlike the
    # invoice/checkout routers), so no tenant lookup stands
    # between the request and the guard, and the no-header route
    # reaches it directly - the existing PUT 404 lock already
    # proves a headerless PUT reaches the permission dependency.
    # The path id is never read on this path, so the id value is
    # arbitrary; the same seeded id as the PUT 404 lock is used.
    # The body is {"is_enabled": False} on purpose: is_enabled
    # is required and a disabled banner needs no message, so body
    # validation passes and cannot mask the error. Note the status
    # is 403, not 406: the guard raises ForbiddenException, which
    # the central ApiBaseException handler maps to 403
    # (api/__init__.py:98-103), with {"error": ..., "code": 403}
    # and the no-store/Pragma error headers; the message carries
    # no "Branding Error: " style prefix, so the assertion is a
    # substring match on "outside your tenant's scope". A future
    # change that drops the guard would break this lock while
    # leaving the notification PUT 404 lock green, so the paths
    # are locked separately.
    from beanie import PydanticObjectId, init_beanie
    from pymongo import AsyncMongoClient

    from api import app
    from api.common.enums.gender import Gender
    from api.domain.dtos.auth_dto import MeResponseDto
    from api.domain.dtos.role_dto import RoleDto
    from api.domain.entities.notification_settings import NotificationBannerSetting
    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission
    from api.infrastructure.security.current_user import get_current_user

    mongo_client = AsyncMongoClient("mongodb://localhost:27012/test_db")
    await init_beanie(
        mongo_client["api_test_db"], document_models=[NotificationBannerSetting]
    )

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Tenant notification caller",
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
                name="Tenant notification caller",
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
        response = await client.put("/notifications/banner/68c302ef6bf7a039b7e9b385", json={"is_enabled": False})
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
    # handler sets no-store only on the success path, so on this
    # path they come from the central ApiBaseException handler,
    # and a cached 403 could otherwise be served to a different
    # user after an account switch on a shared machine.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the notification banner GET
    # test: the pure-ASGI middleware stamps every HTTP response
    # with no path exclusions, so the banner 403 must carry the
    # same headers as the authenticated calls, including the
    # exception-handler responses.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened:
    # lock the twelve most sensitive directives as disabled,
    # mirroring the banner GET lock, using substring checks so
    # later additions to the list do not break this test. Each
    # directive is safe to lock here for the same reasons as on
    # the other notification routes: the SPA has no camera,
    # microphone, geolocation, payment, clipboard-read,
    # display-capture, fullscreen, motion-sensor, compass, XR,
    # or idle-detection flow (verified by grep in the earlier
    # sweeps).
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
    # Postconditions: the guard fires before
    # update_banner_setting runs, so the request is side-effect
    # free - the seeded role is still there with its permission,
    # and no banner record exists in the test DB for the guard
    # to have edited.
    stored = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored is not None
    assert stored.permissions == [Permission.FULL_ACCESS]
    assert await NotificationBannerSetting.find_one() is None
    await mongo_client.close()


@pytest.mark.asyncio
async def test_update_banner_setting_audit_log_records_prior_values(client: AsyncClient):
    """
        The notification-banner audit-log "old" value, not yet locked:
        function-name grep count 0 for
        update_banner_setting_audit_log_records_prior_values
        (verified fresh this run). NotificationBannerRepository
        .update_banner_setting fetched the row, then mutated it in
        place (is_enabled/message) and only afterwards dumped it as
        the audit entry's "old", so "old" recorded the post-update
        values and the prior banner was lost from the trail - the
        same class as the user-preference audit fix, while the role
        repository logs a genuinely pre-update snapshot. The
        repository is called directly here, bypassing the endpoint
        on purpose: only a direct call seeds a row with known prior
        values deterministically. The client fixture is only used to
        initialise the per-test database (conftest.py, db.drop()
        after); no HTTP call is made. The seeded row carries no
        tenant_id, so capture_audit_log writes to the host file
        audit_logs_forhost_<YYYYMMDD>.jsonl in the temp dir; the
        entry is isolated by its distinctive prior message, since
        other tests may share the same day's file. The old code
        would have logged "old" as the new {is_enabled: True,
        message: "New message"}; the fix snapshots the row before
        mutating it, so "old" is {is_enabled: False, message:
        "Old message"} and "new" is the updated banner.
    """
    import json
    import tempfile
    from pathlib import Path

    from beanie import init_beanie
    from pymongo import AsyncMongoClient

    from api.common.utils import get_utc_now
    from api.domain.entities.notification_settings import NotificationBannerSetting
    from api.infrastructure.persistence.repositories.notification_banner_repository_impl import (
        NotificationBannerRepository,
    )

    mongo_client = AsyncMongoClient("mongodb://localhost:27012/test_db")
    await init_beanie(
        mongo_client["api_test_db"], document_models=[NotificationBannerSetting]
    )

    repository = NotificationBannerRepository()
    seeded = await repository.create_banner_setting(
        is_enabled=False, message="Old message", tenant_id=None
    )

    updated = await repository.update_banner_setting(
        str(seeded.id), True, "New message"
    )
    assert updated is not None
    assert updated.is_enabled is True
    assert updated.message == "New message"

    stored = await NotificationBannerSetting.find_one()
    assert stored is not None
    assert stored.is_enabled is True
    assert stored.message == "New message"

    audit_file = Path(tempfile.gettempdir()) / (
        f"audit_logs_forhost_{get_utc_now().strftime('%Y%m%d')}.jsonl"
    )
    assert audit_file.exists()
    entries = [
        json.loads(line)
        for line in audit_file.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    ours = [
        entry
        for entry in entries
        if entry.get("entity") == "NotificationBannerSetting"
        and entry.get("action") == "update"
        and entry.get("changes", {}).get("old", {}).get("message") == "Old message"
    ]
    assert len(ours) == 1
    assert ours[0]["changes"]["old"]["is_enabled"] is False
    assert ours[0]["changes"]["old"]["message"] == "Old message"
    assert ours[0]["changes"]["new"]["is_enabled"] is True
    assert ours[0]["changes"]["new"]["message"] == "New message"
    await mongo_client.close()


@pytest.mark.asyncio
async def test_create_notification_banner_non_bool_is_enabled_returns_422_with_security_headers(client: AsyncClient):
    """
    The notification banner create POST with a non-bool
    `is_enabled` (a JSON list):
    `is_enabled` is a required `bool` field of
    CreateNotificationBannerSettingDto, and Pydantic v2
    does not coerce lists to bool, so request validation
    rejects the body with 422 before the handler body
    runs.
    """
    # Function-name grep count 0 for
    # create_notification_banner_non_bool_is_enabled
    # before appending, verified fresh this run, not
    # assumed. This is the FIRST lock of the
    # notification banner create per-field validation
    # sweep: CreateNotificationBannerSettingDto has two
    # fields (is_enabled, message) and this run locks
    # is_enabled; one remains (message) for a future
    # run. The other field is sent valid alongside the
    # bad value: message "Scheduled maintenance" (a
    # non-blank str within the 500-character cap) --
    # nothing else can mask the 422. A list is used as
    # the non-bool payload because Pydantic v2 lax mode
    # coerces strings ("true"/"false"/"yes"/"no") and
    # ints (0/1) to bool, so neither pins the non-bool
    # class, exactly as in the billing plan-update
    # active lock and the SSO create enabled lock. The
    # normalize_message model_validator runs only after
    # field validation, so it cannot mask the 422. The
    # notifications POST carries a FULL_ACCESS
    # permission dependency (a parameter dependency,
    # solved before the endpoint's own body is
    # validated), so the caller role must carry
    # FULL_ACCESS -- otherwise the permission 403/404
    # would mask the 422, exactly as in the SSO create
    # locks. The Role row (id
    # 68c302ef6bf7a039b7e9b386) is seeded for that
    # dependency, mirroring the notification 403 scope
    # locks, and the override's RoleDto carries the
    # same permission. The _assert_create_scope guard
    # runs inside the handler body, after validation,
    # so it cannot mask the 422 either; the caller
    # tenant_id still matches the X-Tenant-ID header
    # (68c302ef6bf7a039b7e9b388) so the request is
    # otherwise legitimate, and no tenant row needs
    # seeding -- the notifications router has no
    # feature gate and the TenantMiddleware only sets
    # request.state.tenant_id from the header, as in
    # the SSO scope locks. Deliberately no exact
    # error-type assertion, mirroring the checkout
    # non-string email 422 lock. Deliberately no
    # Cache-Control/Pragma assertion: a 422 is FastAPI
    # request validation, not an ApiBaseException, so
    # the central handler's no-store headers do not
    # apply to it, mirroring the billing 422 locks.
    # The security headers ARE locked: the pure-ASGI
    # middleware stamps every HTTP response, including
    # validation errors, with no path exclusions.
    from beanie import PydanticObjectId, init_beanie
    from pymongo import AsyncMongoClient

    from api import app
    from api.common.enums.gender import Gender
    from api.domain.dtos.auth_dto import MeResponseDto
    from api.domain.dtos.role_dto import RoleDto
    from api.domain.entities.notification_settings import NotificationBannerSetting
    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission
    from api.infrastructure.security.current_user import get_current_user

    mongo_client = AsyncMongoClient("mongodb://localhost:27012/test_db")
    await init_beanie(
        mongo_client["api_test_db"], document_models=[NotificationBannerSetting]
    )

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Tenant notification administrator",
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
                name="Tenant notification administrator",
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
            "/notifications/banner",
            headers={"X-Tenant-ID": "68c302ef6bf7a039b7e9b388"},
            json={
                "is_enabled": [True],
                "message": "Scheduled maintenance",
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
    # mirroring the notification banner GET lock, using
    # substring checks so later additions to the list do not
    # break this test.
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
    # runs, so no banner service call is made and no record
    # is created -- the seeded role is still there with
    # FULL_ACCESS and no banner record exists in the test
    # DB, mirroring the notification 403 scope lock (the
    # init_beanie call above registers
    # NotificationBannerSetting, which is not in the
    # conftest model set, so the row can be queried here).
    stored_role = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored_role is not None
    assert stored_role.permissions == [Permission.FULL_ACCESS]
    assert await NotificationBannerSetting.find_one() is None
    await mongo_client.close()


@pytest.mark.asyncio
async def test_create_notification_banner_non_string_message_returns_422_with_security_headers(client: AsyncClient):
    """
    The notification banner create POST with a non-string
    `message` (a JSON list):
    `message` is an `str | None` field of
    CreateNotificationBannerSettingDto, and Pydantic v2
    does not coerce lists to str, so request validation
    rejects the body with 422 before the handler body
    runs.
    """
    # Function-name grep count 0 for
    # create_notification_banner_non_string_message
    # before appending, verified fresh this run, not
    # assumed. This is the SECOND and FINAL lock of the
    # notification banner create per-field validation
    # sweep: CreateNotificationBannerSettingDto has two
    # fields (is_enabled, message); is_enabled was
    # locked in the previous run and this run locks
    # message, so the sweep is now COMPLETE. The other
    # field is sent valid alongside the bad value:
    # is_enabled True (a bool) -- nothing else can
    # mask the 422. A list is used as the non-string
    # payload because a blank string would also 422
    # but would pin the blank-value class (the
    # normalize_message validator rejects a blank
    # message on an enabled banner), not the
    # non-string class, and Pydantic v2 lax mode has
    # no list-to-str coercion path, exactly as in the
    # SSO create client_secret lock. The
    # normalize_message model_validator runs only
    # after field validation and only touches message
    # when already str, so it cannot mask the 422.
    # The notifications POST carries a FULL_ACCESS
    # permission dependency (a parameter dependency,
    # solved before the endpoint's own body is
    # validated), so the caller role must carry
    # FULL_ACCESS -- otherwise the permission 403/404
    # would mask the 422, exactly as in the SSO create
    # locks and the is_enabled lock. The Role row (id
    # 68c302ef6bf7a039b7e9b386) is seeded for that
    # dependency, mirroring the notification 403 scope
    # locks, and the override's RoleDto carries the
    # same permission. The _assert_create_scope guard
    # runs inside the handler body, after validation,
    # so it cannot mask the 422 either; the caller
    # tenant_id still matches the X-Tenant-ID header
    # (68c302ef6bf7a039b7e9b388) so the request is
    # otherwise legitimate, and no tenant row needs
    # seeding -- the notifications router has no
    # feature gate and the TenantMiddleware only sets
    # request.state.tenant_id from the header, as in
    # the SSO scope locks. Deliberately no exact
    # error-type assertion, mirroring the checkout
    # non-string email 422 lock. Deliberately no
    # Cache-Control/Pragma assertion: a 422 is FastAPI
    # request validation, not an ApiBaseException, so
    # the central handler's no-store headers do not
    # apply to it, mirroring the billing 422 locks.
    # The security headers ARE locked: the pure-ASGI
    # middleware stamps every HTTP response, including
    # validation errors, with no path exclusions.
    from beanie import PydanticObjectId, init_beanie
    from pymongo import AsyncMongoClient

    from api import app
    from api.common.enums.gender import Gender
    from api.domain.dtos.auth_dto import MeResponseDto
    from api.domain.dtos.role_dto import RoleDto
    from api.domain.entities.notification_settings import NotificationBannerSetting
    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission
    from api.infrastructure.security.current_user import get_current_user

    mongo_client = AsyncMongoClient("mongodb://localhost:27012/test_db")
    await init_beanie(
        mongo_client["api_test_db"], document_models=[NotificationBannerSetting]
    )

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Tenant notification administrator",
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
                name="Tenant notification administrator",
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
            "/notifications/banner",
            headers={"X-Tenant-ID": "68c302ef6bf7a039b7e9b388"},
            json={
                "is_enabled": True,
                "message": ["Scheduled maintenance"],
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
        "message" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the notification banner GET lock, using
    # substring checks so later additions to the list do not
    # break this test.
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
    # runs, so no banner service call is made and no record
    # is created -- the seeded role is still there with
    # FULL_ACCESS and no banner record exists in the test
    # DB, mirroring the notification 403 scope lock (the
    # init_beanie call above registers
    # NotificationBannerSetting, which is not in the
    # conftest model set, so the row can be queried here).
    stored_role = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored_role is not None
    assert stored_role.permissions == [Permission.FULL_ACCESS]
    assert await NotificationBannerSetting.find_one() is None
    await mongo_client.close()


@pytest.mark.asyncio
async def test_update_notification_banner_non_bool_is_enabled_returns_422_with_security_headers(client: AsyncClient):
    """
    The notification banner update PUT with a non-bool
    `is_enabled` (a JSON list):
    `is_enabled` is a required `bool` field of
    CreateNotificationBannerSettingDto, which the PUT
    /banner/{id} endpoint reuses as its body, and
    Pydantic v2 does not coerce lists to bool, so
    request validation rejects the body with 422
    before the handler body runs.
    """
    # Function-name grep count 0 for
    # update_notification_banner_non_bool_is_enabled
    # before appending, verified fresh this run, not
    # assumed. This is the FIRST lock of the
    # notification banner update per-field validation
    # sweep: CreateNotificationBannerSettingDto has two
    # fields (is_enabled, message) and this run locks
    # is_enabled on the PUT path; one remains (message)
    # for a future run. The create sweep for the same
    # DTO is already complete (is_enabled 2868,
    # message 2869), but the PUT endpoint validates
    # the same DTO through its own route, so its
    # per-field behaviour needs its own locks. The
    # other field is sent valid alongside the bad
    # value: message "Scheduled maintenance" (a
    # non-blank str within the 500-character cap) --
    # nothing else can mask the 422. A list is used as
    # the non-bool payload because Pydantic v2 lax mode
    # coerces strings ("true"/"false"/"yes"/"no") and
    # ints (0/1) to bool, so neither pins the non-bool
    # class, exactly as in the billing plan-update
    # active lock, the SSO create enabled lock, and
    # the notification create is_enabled lock. The
    # normalize_message model_validator runs only after
    # field validation, so it cannot mask the 422. The
    # notifications PUT carries a FULL_ACCESS
    # permission dependency (a parameter dependency,
    # solved before the endpoint's own body is
    # validated), so the caller role must carry
    # FULL_ACCESS -- otherwise the permission 403/404
    # would mask the 422, exactly as in the SSO update
    # locks and the notification create locks. The Role
    # row (id 68c302ef6bf7a039b7e9b386) is seeded for
    # that dependency, mirroring the notification 403
    # scope locks, and the override's RoleDto carries
    # the same permission. The _assert_update_scope
    # guard runs inside the handler body, after
    # validation, so it cannot mask the 422 either;
    # the caller tenant_id still matches the
    # X-Tenant-ID header (68c302ef6bf7a039b7e9b388) so
    # the request is otherwise legitimate, and no
    # tenant row needs seeding -- the notifications
    # router has no feature gate and the
    # TenantMiddleware only sets request.state.tenant_id
    # from the header, as in the SSO scope locks. The
    # path id is never read before validation (it is a
    # plain str), so the same seeded id as the PUT 404
    # lock is used. Deliberately no exact error-type
    # assertion, mirroring the checkout non-string
    # email 422 lock. Deliberately no Cache-Control/
    # Pragma assertion: a 422 is FastAPI request
    # validation, not an ApiBaseException, so the
    # central handler's no-store headers do not apply
    # to it, mirroring the billing 422 locks. The
    # security headers ARE locked: the pure-ASGI
    # middleware stamps every HTTP response, including
    # validation errors, with no path exclusions.
    from beanie import PydanticObjectId, init_beanie
    from pymongo import AsyncMongoClient

    from api import app
    from api.common.enums.gender import Gender
    from api.domain.dtos.auth_dto import MeResponseDto
    from api.domain.dtos.role_dto import RoleDto
    from api.domain.entities.notification_settings import NotificationBannerSetting
    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission
    from api.infrastructure.security.current_user import get_current_user

    mongo_client = AsyncMongoClient("mongodb://localhost:27012/test_db")
    await init_beanie(
        mongo_client["api_test_db"], document_models=[NotificationBannerSetting]
    )

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Tenant notification administrator",
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
                name="Tenant notification administrator",
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
        response = await client.put(
            "/notifications/banner/68c302ef6bf7a039b7e9b385",
            headers={"X-Tenant-ID": "68c302ef6bf7a039b7e9b388"},
            json={
                "is_enabled": [True],
                "message": "Scheduled maintenance",
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
    # mirroring the notification banner GET lock, using
    # substring checks so later additions to the list do not
    # break this test.
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
    # runs, so no banner service call is made and no record
    # is created or updated -- the seeded role is still
    # there with FULL_ACCESS and no banner record exists
    # in the test DB, mirroring the notification 403 scope
    # lock (the init_beanie call above registers
    # NotificationBannerSetting, which is not in the
    # conftest model set, so the row can be queried here).
    stored_role = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored_role is not None
    assert stored_role.permissions == [Permission.FULL_ACCESS]
    assert await NotificationBannerSetting.find_one() is None
    await mongo_client.close()
