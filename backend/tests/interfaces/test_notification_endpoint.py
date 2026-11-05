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
