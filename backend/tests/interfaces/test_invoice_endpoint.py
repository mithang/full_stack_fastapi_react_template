import pytest
from httpx import AsyncClient

from api import app
from api.common.enums.gender import Gender
from api.domain.dtos.auth_dto import MeResponseDto
from api.domain.dtos.role_dto import RoleDto
from api.infrastructure.security.current_user import get_current_user


@pytest.mark.asyncio
async def test_get_invoices_with_feature_disabled_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        The invoice area had no interface test file at all, so
    deleting the invoice router from api/__init__.py — or dropping
    the central ApiBaseException no-store lines or the
    security-headers middleware registration — would previously
    have gone uncaught here even though every other interface
    area locks its headers in. The invoice router is feature-gated
    at the router level (Feature.STRIPE), in front of every
    handler, so the success path is not asserted here: it
    needs a Stripe account and a billing-record service, which the
    shared conftest client does not provide, and the invoice list
    is a financial read. The error path below is
    deterministic instead, and it reuses the per-test
    MeResponseDto override pattern from the checkout test: the
    invoice router's feature gate runs before any handler (the
    list handler itself carries a MANAGE_BILLING permission
    dependency and a read-scope guard, but neither is ever
    reached), but the gate reads currentUser.role, so with a role
    carrying no permissions and no tenant the host-scope branch of
    check_feature_access raises
    FeatureNotEnabledException("stripe") before the handler
    runs — so no billing service is ever reached and no live
    external call is made. The shared conftest mock cannot be
    used directly: it is a plain UserDto with no role
    attribute, so the gate would fail with an AttributeError
    500 instead of the deterministic 403. In production that
    cannot happen: get_current_user builds a MeResponseDto
    (role is a required field) and raises
    RoleNotFoundException before any feature check when the
    role row is missing. The original override is restored in
    finally, so no other test's mock is affected.
    That 403 must still carry the error-response headers: a
    cached 403 could otherwise be served to a different user
    after an account switch on a shared machine, and the invoice
    list is scope-dependent financial configuration (host vs
    tenant), which the handler itself marks no-store on the
    success path.
    """
    async def override_get_current_user_with_role():
        return MeResponseDto(
            first_name="Admin",
            last_name="User",
            id="68c302ef6bf7a039b7e9b385",
            email="admin@example.com",
            gender=Gender.OTHER,
            is_active=True,
            role_id="68c302ef6bf7a039b7e9b386",
            created_at="2024-10-01T00:00:00Z",
            updated_at="2024-10-01T00:00:00Z",
            role=RoleDto(
                id="68c302ef6bf7a039b7e9b386",
                name="No permissions",
                created_at="2024-10-01T00:00:00Z",
                updated_at="2024-10-01T00:00:00Z",
                permissions=[],
            ),
            subscription=None,
        )

    original_override = app.dependency_overrides.get(get_current_user)
    app.dependency_overrides[get_current_user] = override_get_current_user_with_role
    try:
        response = await client.get("/invoices/")
    finally:
        if original_override is None:
            app.dependency_overrides.pop(get_current_user, None)
        else:
            app.dependency_overrides[get_current_user] = original_override
    assert response.status_code == 403
    body = response.json()
    assert body["code"] == 403
    assert "stripe" in body["error"]
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the checkout test: the
    # pure-ASGI middleware stamps every HTTP response with no
    # path exclusions, so the invoice 403 must carry the same headers
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
    # the checkout lock, using substring checks so later additions
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
async def test_list_invoices_outside_tenant_scope_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        The invoice list scope-guard error path:
    """
    # The GET /invoices/ read scope-guard branch, not yet locked:
    # function-name grep count 0 for
    # list_invoices_outside_tenant_scope (verified fresh this
    # run), and no test in this file asserts a 403 with an
    # "outside your tenant's scope" message - the only lock
    # here covers the feature-disabled 403. Deleting
    # _assert_read_scope (invoice_endpoint.py:17-33) would
    # previously have gone uncaught, and a tenant caller
    # listing on the host DB would then list invoices from
    # the HOST Stripe account (the guard's own comment: the
    # tenant Stripe resolver reads the singleton settings
    # record in the current DB with no tenant filter) -
    # financial records leaking to a tenant admin, not just
    # a wrong catalog. The guard runs first in the handler
    # body, before any billing-service call, so no read
    # happens. It cannot be reached the way the roles list
    # lock reaches its guard (tenant-scoped caller, no
    # X-Tenant-ID header): the invoice router is
    # feature-gated, and check_feature_access looks the
    # tenant up by request.state.tenant_id before the
    # handler runs, so with no header the lookup gets None,
    # BaseRepository.get returns None, and get_tenant_by_id
    # raises TenantNotFoundException - a 404 from the gate,
    # never the scope 403. The lock therefore uses the
    # mismatched scope the guard is written for, mirroring
    # the checkout list scope lock: the caller is
    # tenant-scoped to 68c302ef6bf7a039b7e9b387 while the
    # request carries X-Tenant-ID
    # 68c302ef6bf7a039b7e9b388, a seeded tenant with the
    # STRIPE feature enabled, so the feature gate passes
    # (Tenant stays bound to the host DB - init_db excludes
    # it from the tenant-DB models, mongodb.py:53-56 - so
    # the lookup finds the seeded row) and the guard raises
    # ForbiddenException before any read. Like the checkout
    # list route, the invoice route carries a MANAGE_BILLING
    # permission dependency, which runs before the handler
    # body, so the seeded role (id
    # 68c302ef6bf7a039b7e9b386) must carry MANAGE_BILLING:
    # get_role_detail calls get_role_by_id with no tenant
    # filter (role_service.py:79-80), and _caller_may_access
    # returns True for a None caller tenant
    # (role_service.py:18-19), so the seeded row is visible
    # regardless of the caller's tenant scope - the same
    # mechanism the roles list lock relies on. The override's
    # RoleDto carries the same permission, and the caller
    # override mirrors the checkout lock's pattern
    # (per-test MeResponseDto, restored in finally). The
    # list handler takes no query parameters, so no 422 can
    # mask the 403. The central ApiBaseException handler
    # maps ForbiddenException to 403
    # (api/__init__.py:98-103) with {"error": ..., "code":
    # 403} and the no-store/Pragma error headers. A future
    # change that drops the guard would break this lock
    # while leaving the feature-disabled GET 403 lock green,
    # so the two paths are locked separately.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.entities.tenant import Feature, Tenant
    from api.domain.enum.feature import Feature as FeatureEnum
    from api.domain.enum.permission import Permission

    await Tenant(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b388"),
        name="invoice-scope-tenant",
        subdomain="invoice-scope.fsrapp.com",
        features=[Feature(name=FeatureEnum.STRIPE, enabled=True)],
    ).insert()
    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Tenant billing viewer",
        description="Role carrying MANAGE_BILLING for the mocked caller",
        permissions=[Permission.MANAGE_BILLING],
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
                name="Tenant billing viewer",
                description="Role carrying MANAGE_BILLING for the mocked caller",
                created_at="2024-10-01T00:00:00Z",
                updated_at="2024-10-01T00:00:00Z",
                permissions=[Permission.MANAGE_BILLING],
            ),
            subscription=None,
        )

    original_override = app.dependency_overrides.get(get_current_user)
    app.dependency_overrides[get_current_user] = override_get_current_user_tenant_scoped
    try:
        response = await client.get(
            "/invoices/",
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
    # handler sets no-store only after the guard, so on this path
    # they come from the central ApiBaseException handler, and a
    # cached 403 could otherwise be served to a different user
    # after an account switch on a shared machine.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the invoice feature-disabled
    # test: the pure-ASGI middleware stamps every HTTP response
    # with no path exclusions, so the invoice 403 must carry the
    # same headers as the authenticated GETs, including the
    # exception-handler responses.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened:
    # lock the twelve most sensitive directives as disabled,
    # mirroring the invoice GET lock, using substring checks
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
    # Postconditions: the guard fires before any billing-service
    # call, so the read is side-effect free - the seeded role is
    # still there with MANAGE_BILLING and the seeded tenant is
    # still there with the STRIPE feature enabled.
    stored_role = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored_role is not None
    assert stored_role.permissions == [Permission.MANAGE_BILLING]
    stored_tenant = await Tenant.find_one(
        Tenant.id == PydanticObjectId("68c302ef6bf7a039b7e9b388")
    )
    assert stored_tenant is not None
    assert stored_tenant.features == [Feature(name=FeatureEnum.STRIPE, enabled=True)]
