import pytest
from httpx import AsyncClient

from api import app
from api.common.enums.gender import Gender
from api.domain.dtos.auth_dto import MeResponseDto
from api.domain.dtos.role_dto import RoleDto
from api.infrastructure.security.current_user import get_current_user


@pytest.mark.asyncio
async def test_get_prices_with_feature_disabled_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        The prices area had no interface test file at all, so
    deleting the prices router from api/__init__.py — or dropping
    the central ApiBaseException no-store lines or the
    security-headers middleware registration — would previously
    have gone uncaught here even though every other interface
    area locks its headers in. The prices router is feature-gated
    at the router level (Feature.STRIPE), in front of every
    handler, so the success path is not asserted here: it
    needs a Stripe account with prices plus the
    MANAGE_PRODUCTS_AND_PRICING permission, neither of which
    the shared conftest client provides. The error path below
    is deterministic instead, and it reuses the per-test
    MeResponseDto override pattern from the AI test: the
    prices router also carries a permission dependency
    (MANAGE_PRODUCTS_AND_PRICING) after the feature gate, but
    the gate runs first, and with a role carrying no
    permissions and no tenant the host-scope branch of
    check_feature_access raises
    FeatureNotEnabledException("stripe") before the permission
    check or the handler runs — so no Stripe service is ever
    reached and no live external call is made. The shared
    conftest mock cannot be used directly: it is a plain
    UserDto with no role attribute, so the gate would fail
    with an AttributeError 500 instead of the deterministic
    403. In production that cannot happen: get_current_user
    builds a MeResponseDto (role is a required field) and
    raises RoleNotFoundException before any feature check
    when the role row is missing. The original override is
    restored in finally, so no other test's mock is affected.
    That 403 must still carry the error-response headers: a
    cached 403 could otherwise be served to a different user
    after an account switch on a shared machine, and the price
    list is account-visible catalog configuration.
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
        response = await client.get("/prices/")
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

    # Same security-headers lock as the AI test: the
    # pure-ASGI middleware stamps every HTTP response with no
    # path exclusions, so the prices 403 must carry the same headers
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
    # the AI lock, using substring checks so later additions
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
async def test_patch_prices_with_feature_disabled_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        The prices PATCH (second-path lock, following the GET lock
        above):
    """
    # The GET test locks the prices area's error path, but a
    # second route could lose its router dependency (or gain a
    # handler change that runs before it) while the GET lock still
    # passes, so each route needs its own lock. PATCH is the
    # deterministic second route: it shares the router-level
    # Feature.STRIPE gate with the GET, in front of the
    # MANAGE_PRODUCTS_AND_PRICING permission dependency, and
    # the gate raises FeatureNotEnabledException("stripe")
    # before the permission check or the handler runs — so no
    # Stripe service is ever reached and no live external call
    # is made, and the arbitrary price_id path param (a plain
    # :path string) cannot mask the error either. The body is
    # {"active": true} on purpose, not {}: unlike the branding
    # DTO, UpdatePricingDto.active is a required bool (metadata
    # and tax_behavior are optional), so an empty body would fail
    # validation with 422 and could mask the 403 depending on
    # validation-vs-dependency ordering; a valid body makes the
    # gate error deterministic either way. The same per-test
    # MeResponseDto override as the GET test is reused (role
    # with no permissions, no tenant): the shared conftest mock
    # is a plain UserDto with no role attribute and would hit
    # an AttributeError 500 instead. The original override is
    # restored in finally, so no other test's mock is affected.
    # That 403 must still carry the error-response headers: a
    # cached 403 could otherwise be served to a different user
    # after an account switch on a shared machine, and price
    # updates are account-visible catalog configuration.
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
        response = await client.patch("/prices/price_123", json={"active": True})
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

    # Same security-headers lock as the GET test: the
    # pure-ASGI middleware stamps every HTTP response with no
    # path exclusions, so the prices PATCH 403 must carry the
    # same headers as the GET 403, including the
    # exception-handler responses.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
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
async def test_post_prices_with_feature_disabled_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        The prices POST (third-path lock, following the GET and
        PATCH locks above):
    """
    # The GET and PATCH tests lock two routes, but a third route
    # could lose its router dependency (or gain a handler change
    # that runs before it) while those locks still pass, so each
    # route needs its own lock. POST is the deterministic third
    # route: it shares the router-level Feature.STRIPE gate with
    # the GET and PATCH, in front of the
    # MANAGE_PRODUCTS_AND_PRICING permission dependency, and the
    # gate raises FeatureNotEnabledException("stripe") before the
    # permission check or the handler runs — so no Stripe service
    # is ever reached and no live external call is made, and no
    # price is created (no side effect). The body is valid on
    # purpose, not {}: CreatePricingDto requires unit_amount
    # (ge=0), product (min_length=1, non-blank after strip) and
    # recurring (RecurringDto, all fields defaulted, so {} is
    # valid for it), while currency defaults to "eur" — an
    # invalid body would fail validation with 422 and could mask
    # the 403 depending on validation-vs-dependency ordering; a
    # valid body makes the gate error deterministic either way.
    # The same per-test MeResponseDto override as the GET and
    # PATCH tests is reused (role with no permissions, no
    # tenant): the shared conftest mock is a plain UserDto with
    # no role attribute and would hit an AttributeError 500
    # instead. The original override is restored in finally, so
    # no other test's mock is affected. That 403 must still
    # carry the error-response headers: a cached 403 could
    # otherwise be served to a different user after an account
    # switch on a shared machine, and price creation is
    # account-visible catalog configuration.
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
        response = await client.post(
            "/prices/",
            json={"unit_amount": 1000, "product": "prod_test123", "recurring": {}},
        )
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

    # Same security-headers lock as the GET and PATCH tests: the
    # pure-ASGI middleware stamps every HTTP response with no
    # path exclusions, so the prices POST 403 must carry the
    # same headers as the GET and PATCH 403s, including the
    # exception-handler responses.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
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
async def test_get_prices_outside_tenant_scope_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        The prices list scope-guard error path:
    """
    # The GET /prices/ read scope-guard branch, not yet locked:
    # function-name grep count 0 for
    # get_prices_outside_tenant_scope (verified fresh this
    # run), and no test in this file asserts a 403 with an
    # "outside your tenant's scope" message - the only locks
    # here cover the feature-disabled 403s. Deleting
    # _assert_read_scope (prices_endpoint.py:29-48) would
    # previously have gone uncaught, and a tenant caller
    # listing on the host DB would then list prices from
    # the HOST Stripe account (the guard's own comment: the
    # tenant Stripe resolver reads the singleton settings
    # record in the current DB with no tenant filter) -
    # catalog leaking to a tenant admin, not just a wrong
    # catalog. The guard runs first in the handler body,
    # before any pricing-service call, so no read happens.
    # It cannot be reached the way the notification banner
    # locks reach their guard (tenant-scoped caller, no
    # X-Tenant-ID header): the prices router is
    # feature-gated, and check_feature_access looks the
    # tenant up by request.state.tenant_id before the
    # handler runs, so with no header the lookup gets None,
    # BaseRepository.get returns None, and get_tenant_by_id
    # raises TenantNotFoundException - a 404 from the gate,
    # never the scope 403. The lock therefore uses the
    # mismatched scope the guard is written for, mirroring
    # the invoice list scope lock: the caller is
    # tenant-scoped to 68c302ef6bf7a039b7e9b387 while the
    # request carries X-Tenant-ID
    # 68c302ef6bf7a039b7e9b388, a seeded tenant with the
    # STRIPE feature enabled, so the feature gate passes
    # (Tenant stays bound to the host DB - init_db excludes
    # it from the tenant-DB models, mongodb.py:53-56 - so
    # the lookup finds the seeded row) and the guard raises
    # ForbiddenException before any read. Like the invoice
    # route, the prices route carries a
    # MANAGE_PRODUCTS_AND_PRICING permission dependency,
    # which runs before the handler body, so the seeded role
    # (id 68c302ef6bf7a039b7e9b386) must carry
    # MANAGE_PRODUCTS_AND_PRICING: get_role_detail calls
    # get_role_by_id with no tenant argument
    # (user_access_management.py), so _caller_may_access
    # sees a None caller tenant and returns True
    # (role_service.py:18-19), and the seeded row is
    # visible regardless of the caller's tenant scope -
    # the same mechanism the invoice list lock relies on.
    # The override's RoleDto carries the same permission,
    # and the caller override mirrors the invoice lock's
    # pattern (per-test MeResponseDto, restored in
    # finally). The list handler takes no query parameters,
    # so no 422 can mask the 403. The central
    # ApiBaseException handler maps ForbiddenException to
    # 403 (api/__init__.py:98-103) with {"error": ...,
    # "code": 403} and the no-store/Pragma error headers.
    # A future change that drops the guard would break this
    # lock while leaving the feature-disabled GET 403 lock
    # green, so the two paths are locked separately.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.entities.tenant import Feature, Tenant
    from api.domain.enum.feature import Feature as FeatureEnum
    from api.domain.enum.permission import Permission

    await Tenant(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b388"),
        name="prices-scope-tenant",
        subdomain="prices-scope.fsrapp.com",
        features=[Feature(name=FeatureEnum.STRIPE, enabled=True)],
    ).insert()
    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Tenant pricing viewer",
        description="Role carrying MANAGE_PRODUCTS_AND_PRICING for the mocked caller",
        permissions=[Permission.MANAGE_PRODUCTS_AND_PRICING],
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
                name="Tenant pricing viewer",
                description="Role carrying MANAGE_PRODUCTS_AND_PRICING for the mocked caller",
                created_at="2024-10-01T00:00:00Z",
                updated_at="2024-10-01T00:00:00Z",
                permissions=[Permission.MANAGE_PRODUCTS_AND_PRICING],
            ),
            subscription=None,
        )

    original_override = app.dependency_overrides.get(get_current_user)
    app.dependency_overrides[get_current_user] = override_get_current_user_tenant_scoped
    try:
        response = await client.get(
            "/prices/",
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

    # Same security-headers lock as the prices feature-disabled
    # tests: the pure-ASGI middleware stamps every HTTP response
    # with no path exclusions, so the prices 403 must carry the
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
    # mirroring the prices GET lock, using substring checks
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
    # Postconditions: the guard fires before any pricing-service
    # call, so the read is side-effect free - the seeded role is
    # still there with MANAGE_PRODUCTS_AND_PRICING and the seeded
    # tenant is still there with the STRIPE feature enabled.
    stored_role = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored_role is not None
    assert stored_role.permissions == [Permission.MANAGE_PRODUCTS_AND_PRICING]
    stored_tenant = await Tenant.find_one(
        Tenant.id == PydanticObjectId("68c302ef6bf7a039b7e9b388")
    )
    assert stored_tenant is not None
    assert stored_tenant.features == [Feature(name=FeatureEnum.STRIPE, enabled=True)]


@pytest.mark.asyncio
async def test_post_prices_outside_tenant_scope_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        The prices POST create scope-guard error path:
    """
    # The POST /prices/ create scope-guard branch, not yet locked:
    # function-name grep count 0 for
    # post_prices_outside_tenant_scope (verified fresh this
    # run), and no test in this file asserts a 403 with an
    # "outside your tenant's scope" message on POST - the only
    # scope lock here covers the GET list. Deleting
    # _assert_create_scope (prices_endpoint.py:16-35) would
    # previously have gone uncaught, and a tenant caller
    # creating on the host DB would then create a price in
    # the HOST Stripe account (the guard's own comment: the
    # tenant Stripe resolver reads the singleton settings
    # record in the current DB with no tenant filter) -
    # polluting the host catalog and hiding the object from
    # the caller's own tenant Stripe account. The guard runs
    # first in the handler body, before any pricing-service
    # call, so no price is created. It cannot be reached the
    # way the notification banner locks reach their guard
    # (tenant-scoped caller, no X-Tenant-ID header): the
    # prices router is feature-gated, and
    # check_feature_access looks the tenant up by
    # request.state.tenant_id before the handler runs, so
    # with no header the lookup gets None,
    # BaseRepository.get returns None, and get_tenant_by_id
    # raises TenantNotFoundException - a 404 from the gate,
    # never the scope 403. The lock therefore uses the
    # mismatched scope the guard is written for, mirroring
    # the GET prices scope lock: the caller is tenant-scoped
    # to 68c302ef6bf7a039b7e9b387 while the request carries
    # X-Tenant-ID 68c302ef6bf7a039b7e9b388, a seeded tenant
    # with the STRIPE feature enabled, so the feature gate
    # passes (Tenant stays bound to the host DB - init_db
    # excludes it from the tenant-DB models, mongodb.py:53-56
    # - so the lookup finds the seeded row) and the guard
    # raises ForbiddenException before any create. Like the
    # GET route, the POST route carries a
    # MANAGE_PRODUCTS_AND_PRICING permission dependency,
    # which runs before the handler body, so the seeded role
    # (id 68c302ef6bf7a039b7e9b386) must carry
    # MANAGE_PRODUCTS_AND_PRICING: get_role_detail calls
    # get_role_by_id with no tenant argument
    # (user_access_management.py), so _caller_may_access
    # sees a None caller tenant and returns True
    # (role_service.py:18-19), and the seeded row is
    # visible regardless of the caller's tenant scope -
    # the same mechanism the GET prices scope lock relies
    # on. The override's RoleDto carries the same
    # permission, and the caller override mirrors the GET
    # lock's pattern (per-test MeResponseDto, restored in
    # finally). The body is valid on purpose, not {}:
    # CreatePricingDto requires unit_amount (ge=0), product
    # (min_length=1) and recurring (RecurringDto, all fields
    # defaulted, so {} is valid for it), while currency
    # defaults to "eur" - an invalid body would fail
    # validation with 422 and could mask the 403 depending
    # on validation-vs-dependency ordering; a valid body
    # makes the guard error deterministic either way. The
    # central ApiBaseException handler maps
    # ForbiddenException to 403 (api/__init__.py:98-103)
    # with {"error": ..., "code": 403} and the no-store/Pragma
    # error headers. A future change that drops the guard
    # would break this lock while leaving the GET scope lock
    # and the feature-disabled POST 403 lock green, so the
    # three paths are locked separately.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.entities.tenant import Feature, Tenant
    from api.domain.enum.feature import Feature as FeatureEnum
    from api.domain.enum.permission import Permission

    await Tenant(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b388"),
        name="prices-scope-tenant",
        subdomain="prices-scope.fsrapp.com",
        features=[Feature(name=FeatureEnum.STRIPE, enabled=True)],
    ).insert()
    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Tenant pricing viewer",
        description="Role carrying MANAGE_PRODUCTS_AND_PRICING for the mocked caller",
        permissions=[Permission.MANAGE_PRODUCTS_AND_PRICING],
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
                name="Tenant pricing viewer",
                description="Role carrying MANAGE_PRODUCTS_AND_PRICING for the mocked caller",
                created_at="2024-10-01T00:00:00Z",
                updated_at="2024-10-01T00:00:00Z",
                permissions=[Permission.MANAGE_PRODUCTS_AND_PRICING],
            ),
            subscription=None,
        )

    original_override = app.dependency_overrides.get(get_current_user)
    app.dependency_overrides[get_current_user] = override_get_current_user_tenant_scoped
    try:
        response = await client.post(
            "/prices/",
            headers={"X-Tenant-ID": "68c302ef6bf7a039b7e9b388"},
            json={"unit_amount": 1000, "product": "prod_test123", "recurring": {}},
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

    # Same security-headers lock as the prices feature-disabled
    # tests: the pure-ASGI middleware stamps every HTTP response
    # with no path exclusions, so the prices 403 must carry the
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
    # mirroring the prices GET lock, using substring checks
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
    # Postconditions: the guard fires before any pricing-service
    # call, so the create is side-effect free - the seeded role
    # is still there with MANAGE_PRODUCTS_AND_PRICING and the
    # seeded tenant is still there with the STRIPE feature
    # enabled.
    stored_role = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored_role is not None
    assert stored_role.permissions == [Permission.MANAGE_PRODUCTS_AND_PRICING]
    stored_tenant = await Tenant.find_one(
        Tenant.id == PydanticObjectId("68c302ef6bf7a039b7e9b388")
    )
    assert stored_tenant is not None
    assert stored_tenant.features == [Feature(name=FeatureEnum.STRIPE, enabled=True)]


@pytest.mark.asyncio
async def test_patch_prices_outside_tenant_scope_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        The prices PATCH update scope-guard error path:
    """
    # The PATCH /prices/{price_id} update scope-guard branch, not
    # yet locked: function-name grep count 0 for
    # patch_prices_outside_tenant_scope (verified fresh this
    # run), and no test in this file asserts a 403 with an
    # "outside your tenant's scope" message on PATCH - the only
    # scope locks here cover the GET list and the POST create.
    # Deleting _assert_create_scope (prices_endpoint.py:16-35)
    # would previously have gone uncaught on this route: the
    # POST lock would stay green while a tenant caller updating
    # on the host DB would then update a price in the HOST
    # Stripe account (the guard's own comment: the tenant
    # Stripe resolver reads the singleton settings record in
    # the current DB with no tenant filter) - polluting the
    # host catalog and hiding the object from the caller's own
    # tenant Stripe account. The guard runs first in the
    # handler body, before any pricing-service call, so no
    # price is updated. It cannot be reached the way the
    # notification banner locks reach their guard
    # (tenant-scoped caller, no X-Tenant-ID header): the
    # prices router is feature-gated, and
    # check_feature_access looks the tenant up by
    # request.state.tenant_id before the handler runs, so
    # with no header the lookup gets None,
    # BaseRepository.get returns None, and get_tenant_by_id
    # raises TenantNotFoundException - a 404 from the gate,
    # never the scope 403. The lock therefore uses the
    # mismatched scope the guard is written for, mirroring
    # the POST prices scope lock: the caller is tenant-scoped
    # to 68c302ef6bf7a039b7e9b387 while the request carries
    # X-Tenant-ID 68c302ef6bf7a039b7e9b388, a seeded tenant
    # with the STRIPE feature enabled, so the feature gate
    # passes (Tenant stays bound to the host DB - init_db
    # excludes it from the tenant-DB models, mongodb.py:53-56
    # - so the lookup finds the seeded row) and the guard
    # raises ForbiddenException before any update. Like the
    # POST route, the PATCH route carries a
    # MANAGE_PRODUCTS_AND_PRICING permission dependency,
    # which runs before the handler body, so the seeded role
    # (id 68c302ef6bf7a039b7e9b386) must carry
    # MANAGE_PRODUCTS_AND_PRICING: get_role_detail calls
    # get_role_by_id with no tenant argument
    # (user_access_management.py), so _caller_may_access
    # sees a None caller tenant and returns True
    # (role_service.py:18-19), and the seeded row is
    # visible regardless of the caller's tenant scope -
    # the same mechanism the POST prices scope lock relies
    # on. The override's RoleDto carries the same
    # permission, and the caller override mirrors the POST
    # lock's pattern (per-test MeResponseDto, restored in
    # finally). The body is {"active": true} on purpose, not
    # {}: UpdatePricingDto.active is a required bool
    # (metadata and tax_behavior are optional), so an empty
    # body would fail validation with 422 and could mask the
    # 403 depending on validation-vs-dependency ordering; a
    # valid body makes the guard error deterministic either
    # way. The price_id is the arbitrary plain string
    # "price_test123" (the :path converter captures it as a
    # string), which cannot mask the error. The central
    # ApiBaseException handler maps ForbiddenException to 403
    # (api/__init__.py:98-103) with {"error": ..., "code":
    # 403} and the no-store/Pragma error headers. A future
    # change that drops the guard would break this lock while
    # leaving the GET and POST scope locks and the
    # feature-disabled PATCH 403 lock green, so the four
    # paths are locked separately.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.entities.tenant import Feature, Tenant
    from api.domain.enum.feature import Feature as FeatureEnum
    from api.domain.enum.permission import Permission

    await Tenant(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b388"),
        name="prices-scope-tenant",
        subdomain="prices-scope.fsrapp.com",
        features=[Feature(name=FeatureEnum.STRIPE, enabled=True)],
    ).insert()
    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Tenant pricing viewer",
        description="Role carrying MANAGE_PRODUCTS_AND_PRICING for the mocked caller",
        permissions=[Permission.MANAGE_PRODUCTS_AND_PRICING],
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
                name="Tenant pricing viewer",
                description="Role carrying MANAGE_PRODUCTS_AND_PRICING for the mocked caller",
                created_at="2024-10-01T00:00:00Z",
                updated_at="2024-10-01T00:00:00Z",
                permissions=[Permission.MANAGE_PRODUCTS_AND_PRICING],
            ),
            subscription=None,
        )

    original_override = app.dependency_overrides.get(get_current_user)
    app.dependency_overrides[get_current_user] = override_get_current_user_tenant_scoped
    try:
        response = await client.patch(
            "/prices/price_test123",
            headers={"X-Tenant-ID": "68c302ef6bf7a039b7e9b388"},
            json={"active": True},
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

    # Same security-headers lock as the prices feature-disabled
    # tests: the pure-ASGI middleware stamps every HTTP response
    # with no path exclusions, so the prices 403 must carry the
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
    # mirroring the prices GET lock, using substring checks
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
    # Postconditions: the guard fires before any pricing-service
    # call, so the update is side-effect free - the seeded role
    # is still there with MANAGE_PRODUCTS_AND_PRICING and the
    # seeded tenant is still there with the STRIPE feature
    # enabled.
    stored_role = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored_role is not None
    assert stored_role.permissions == [Permission.MANAGE_PRODUCTS_AND_PRICING]
    stored_tenant = await Tenant.find_one(
        Tenant.id == PydanticObjectId("68c302ef6bf7a039b7e9b388")
    )
    assert stored_tenant is not None
    assert stored_tenant.features == [Feature(name=FeatureEnum.STRIPE, enabled=True)]


@pytest.mark.asyncio
async def test_create_pricing_non_string_currency_returns_422_with_security_headers(client: AsyncClient):
    """
    The price-create POST with a non-string `currency` (a JSON
    list): `currency` is a required `str` field (min_length=3,
    max_length=3), and Pydantic v2 does not coerce lists to
    strings, so request validation rejects the body with 422
    before the handler body runs.
    """
    # Function-name grep count 0 for
    # create_pricing_non_string_currency before appending,
    # verified fresh this run, not assumed. No non-string
    # lock exists for any CreatePricingDto field yet, so this
    # starts the price-create per-field sweep: currency: str,
    # unit_amount: int, product: str, active: bool,
    # recurring: RecurringDto (pricing_dto.py). The other
    # fields sent are valid, so none can mask the 422:
    # unit_amount 1000 (int, ge=0), product "prod_test123"
    # (min_length=1, non-blank after strip), recurring {}
    # (all RecurringDto fields defaulted, so {} is valid);
    # active is not sent and defaults to True. The DTO's
    # mode="after" normalize_product validator only runs
    # after valid field parsing, so it cannot mask the 422.
    # The endpoint is feature-gated (STRIPE) and
    # permission-gated (MANAGE_PRODUCTS_AND_PRICING) at the
    # router level, and FastAPI solves sub-dependencies
    # before validating the endpoint's own body, so the
    # tenant must be seeded with the STRIPE feature enabled
    # and the mocked caller's role must be seeded with the
    # permission first -- otherwise the feature gate's 403 or
    # the permission gate's RoleNotFoundException 404 would
    # mask the 422, exactly as in the product-create locks.
    # The tenant id (68c302ef6bf7a039b7e9b388) is both the
    # X-Tenant-ID header value and the caller's tenant_id, so
    # the handler's _assert_create_scope check would also
    # pass; the 422 comes from validation, before the
    # handler runs at all. FastAPI request validation fails
    # before the handler body runs: PricingService
    # .create_price never runs, so no Stripe call is made.
    # Deliberately no exact error-type assertion, mirroring
    # the product non-string-field 422 locks. Deliberately no
    # Cache-Control/Pragma assertion: a 422 is FastAPI request
    # validation, not an ApiBaseException, so the central
    # handler's no-store headers do not apply to it, mirroring
    # the product 422 locks. The security headers ARE locked:
    # the pure-ASGI middleware stamps every HTTP response,
    # including validation errors, with no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.entities.tenant import Feature, Tenant
    from api.domain.enum.feature import Feature as FeatureEnum
    from api.domain.enum.permission import Permission

    await Tenant(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b388"),
        name="prices-validation-tenant",
        subdomain="prices-validation.fsrapp.com",
        features=[Feature(name=FeatureEnum.STRIPE, enabled=True)],
    ).insert()
    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Tenant price manager",
        description="Role carrying MANAGE_PRODUCTS_AND_PRICING for the mocked caller",
        permissions=[Permission.MANAGE_PRODUCTS_AND_PRICING],
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
                name="Tenant price manager",
                description="Role carrying MANAGE_PRODUCTS_AND_PRICING for the mocked caller",
                created_at="2024-10-01T00:00:00Z",
                updated_at="2024-10-01T00:00:00Z",
                permissions=[Permission.MANAGE_PRODUCTS_AND_PRICING],
            ),
            subscription=None,
        )

    original_override = app.dependency_overrides.get(get_current_user)
    app.dependency_overrides[get_current_user] = override_get_current_user_tenant_scoped
    try:
        response = await client.post(
            "/prices/",
            headers={"X-Tenant-ID": "68c302ef6bf7a039b7e9b388"},
            json={
                "currency": ["not-a-string"],
                "unit_amount": 1000,
                "product": "prod_test123",
                "recurring": {},
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
        "currency" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the product locks, using substring checks so
    # later additions to the list do not break this test.
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
    # runs, so no Stripe call is made and nothing is created
    # -- the seeded role is still there with
    # MANAGE_PRODUCTS_AND_PRICING and the seeded tenant is
    # still there with the STRIPE feature enabled. Prices
    # are Stripe objects, not DB rows, so the tenant row is
    # the observable postcondition.
    stored_role = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored_role is not None
    assert stored_role.permissions == [Permission.MANAGE_PRODUCTS_AND_PRICING]
    stored_tenant = await Tenant.find_one(
        Tenant.id == PydanticObjectId("68c302ef6bf7a039b7e9b388")
    )
    assert stored_tenant is not None
    assert stored_tenant.features == [Feature(name=FeatureEnum.STRIPE, enabled=True)]


async def test_create_pricing_non_int_unit_amount_returns_422_with_security_headers(client: AsyncClient):
    """
    The price-create POST with a non-int `unit_amount` (a JSON
    list): `unit_amount` is a required `int` field (ge=0), and
    Pydantic v2 does not coerce lists to ints, so request
    validation rejects the body with 422 before the handler
    body runs.
    """
    # Function-name grep count 0 for
    # create_pricing_non_int_unit_amount before appending,
    # verified fresh this run, not assumed. The price-create
    # per-field sweep so far: currency locked (2837);
    # unit_amount is next, product/active/recurring remain.
    # The other fields sent are valid, so none can mask the
    # 422: currency "eur" (exactly 3 chars, non-blank after
    # strip), product "prod_test123" (min_length=1, non-blank
    # after strip), recurring {} (all RecurringDto fields
    # defaulted, so {} is valid); active is not sent and
    # defaults to True. The DTO's mode="after"
    # normalize_product validator only runs after valid field
    # parsing and only touches product/currency strings, so
    # it cannot mask the 422. The endpoint is feature-gated
    # (STRIPE) and permission-gated
    # (MANAGE_PRODUCTS_AND_PRICING) at the router level, and
    # FastAPI solves sub-dependencies before validating the
    # endpoint's own body, so the tenant must be seeded with
    # the STRIPE feature enabled and the mocked caller's role
    # must be seeded with the permission first -- otherwise
    # the feature gate's 403 or the permission gate's
    # RoleNotFoundException 404 would mask the 422, exactly
    # as in the product-create locks. The tenant id
    # (68c302ef6bf7a039b7e9b388) is both the X-Tenant-ID
    # header value and the caller's tenant_id, so the
    # handler's _assert_create_scope check would also pass;
    # the 422 comes from validation, before the handler runs
    # at all. FastAPI request validation fails before the
    # handler body runs: PricingService.create_price never
    # runs, so no Stripe call is made. Deliberately no exact
    # error-type assertion, mirroring the product non-string
    # -field 422 locks. Deliberately no Cache-Control/Pragma
    # assertion: a 422 is FastAPI request validation, not an
    # ApiBaseException, so the central handler's no-store
    # headers do not apply to it, mirroring the product 422
    # locks. The security headers ARE locked: the pure-ASGI
    # middleware stamps every HTTP response, including
    # validation errors, with no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.entities.tenant import Feature, Tenant
    from api.domain.enum.feature import Feature as FeatureEnum
    from api.domain.enum.permission import Permission

    await Tenant(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b388"),
        name="prices-validation-tenant",
        subdomain="prices-validation.fsrapp.com",
        features=[Feature(name=FeatureEnum.STRIPE, enabled=True)],
    ).insert()
    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Tenant price manager",
        description="Role carrying MANAGE_PRODUCTS_AND_PRICING for the mocked caller",
        permissions=[Permission.MANAGE_PRODUCTS_AND_PRICING],
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
                name="Tenant price manager",
                description="Role carrying MANAGE_PRODUCTS_AND_PRICING for the mocked caller",
                created_at="2024-10-01T00:00:00Z",
                updated_at="2024-10-01T00:00:00Z",
                permissions=[Permission.MANAGE_PRODUCTS_AND_PRICING],
            ),
            subscription=None,
        )

    original_override = app.dependency_overrides.get(get_current_user)
    app.dependency_overrides[get_current_user] = override_get_current_user_tenant_scoped
    try:
        response = await client.post(
            "/prices/",
            headers={"X-Tenant-ID": "68c302ef6bf7a039b7e9b388"},
            json={
                "currency": "eur",
                "unit_amount": ["not-an-int"],
                "product": "prod_test123",
                "recurring": {},
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
        "unit_amount" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the product locks, using substring checks so
    # later additions to the list do not break this test.
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
    # runs, so no Stripe call is made and nothing is created
    # -- the seeded role is still there with
    # MANAGE_PRODUCTS_AND_PRICING and the seeded tenant is
    # still there with the STRIPE feature enabled. Prices
    # are Stripe objects, not DB rows, so the tenant row is
    # the observable postcondition.
    stored_role = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored_role is not None
    assert stored_role.permissions == [Permission.MANAGE_PRODUCTS_AND_PRICING]
    stored_tenant = await Tenant.find_one(
        Tenant.id == PydanticObjectId("68c302ef6bf7a039b7e9b388")
    )
    assert stored_tenant is not None
    assert stored_tenant.features == [Feature(name=FeatureEnum.STRIPE, enabled=True)]


async def test_create_pricing_non_string_product_returns_422_with_security_headers(client: AsyncClient):
    """
    The price-create POST with a non-string `product` (a JSON
    list): `product` is a required `str` field (min_length=1),
    and Pydantic v2 does not coerce lists to strings, so
    request validation rejects the body with 422 before the
    handler body runs.
    """
    # Function-name grep count 0 for
    # create_pricing_non_string_product before appending,
    # verified fresh this run, not assumed. The price-create
    # per-field sweep so far: currency locked (2837),
    # unit_amount locked (2838); product is next,
    # active/recurring remain. The other fields sent are
    # valid, so none can mask the 422: currency "eur"
    # (exactly 3 chars, non-blank after strip), unit_amount
    # 1000 (ge=0), recurring {} (all RecurringDto fields
    # defaulted, so {} is valid); active is not sent and
    # defaults to True. The DTO's mode="after"
    # normalize_product validator only runs after valid field
    # parsing and only strips string product/currency values,
    # so it cannot mask the 422. The endpoint is
    # feature-gated (STRIPE) and permission-gated
    # (MANAGE_PRODUCTS_AND_PRICING) at the router level, and
    # FastAPI solves sub-dependencies before validating the
    # endpoint's own body, so the tenant must be seeded with
    # the STRIPE feature enabled and the mocked caller's role
    # must be seeded with the permission first -- otherwise
    # the feature gate's 403 or the permission gate's
    # RoleNotFoundException 404 would mask the 422, exactly
    # as in the product-create locks. The tenant id
    # (68c302ef6bf7a039b7e9b388) is both the X-Tenant-ID
    # header value and the caller's tenant_id, so the
    # handler's _assert_create_scope check would also pass;
    # the 422 comes from validation, before the handler runs
    # at all. FastAPI request validation fails before the
    # handler body runs: PricingService.create_price never
    # runs, so no Stripe call is made. Deliberately no exact
    # error-type assertion, mirroring the product non-string
    # -field 422 locks. Deliberately no Cache-Control/Pragma
    # assertion: a 422 is FastAPI request validation, not an
    # ApiBaseException, so the central handler's no-store
    # headers do not apply to it, mirroring the product 422
    # locks. The security headers ARE locked: the pure-ASGI
    # middleware stamps every HTTP response, including
    # validation errors, with no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.entities.tenant import Feature, Tenant
    from api.domain.enum.feature import Feature as FeatureEnum
    from api.domain.enum.permission import Permission

    await Tenant(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b388"),
        name="prices-validation-tenant",
        subdomain="prices-validation.fsrapp.com",
        features=[Feature(name=FeatureEnum.STRIPE, enabled=True)],
    ).insert()
    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Tenant price manager",
        description="Role carrying MANAGE_PRODUCTS_AND_PRICING for the mocked caller",
        permissions=[Permission.MANAGE_PRODUCTS_AND_PRICING],
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
                name="Tenant price manager",
                description="Role carrying MANAGE_PRODUCTS_AND_PRICING for the mocked caller",
                created_at="2024-10-01T00:00:00Z",
                updated_at="2024-10-01T00:00:00Z",
                permissions=[Permission.MANAGE_PRODUCTS_AND_PRICING],
            ),
            subscription=None,
        )

    original_override = app.dependency_overrides.get(get_current_user)
    app.dependency_overrides[get_current_user] = override_get_current_user_tenant_scoped
    try:
        response = await client.post(
            "/prices/",
            headers={"X-Tenant-ID": "68c302ef6bf7a039b7e9b388"},
            json={
                "currency": "eur",
                "unit_amount": 1000,
                "product": ["not-a-string"],
                "recurring": {},
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
        "product" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the product locks, using substring checks so
    # later additions to the list do not break this test.
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
    # runs, so no Stripe call is made and nothing is created
    # -- the seeded role is still there with
    # MANAGE_PRODUCTS_AND_PRICING and the seeded tenant is
    # still there with the STRIPE feature enabled. Prices
    # are Stripe objects, not DB rows, so the tenant row is
    # the observable postcondition.
    stored_role = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored_role is not None
    assert stored_role.permissions == [Permission.MANAGE_PRODUCTS_AND_PRICING]
    stored_tenant = await Tenant.find_one(
        Tenant.id == PydanticObjectId("68c302ef6bf7a039b7e9b388")
    )
    assert stored_tenant is not None
    assert stored_tenant.features == [Feature(name=FeatureEnum.STRIPE, enabled=True)]


async def test_create_pricing_non_bool_active_returns_422_with_security_headers(client: AsyncClient):
    """
    The price-create POST with a non-bool `active` (a JSON
    list): `active` is a `bool` field (default True), and
    Pydantic v2 does not coerce lists to bools, so request
    validation rejects the body with 422 before the handler
    body runs.
    """
    # Function-name grep count 0 for
    # create_pricing_non_bool_active before appending,
    # verified fresh this run, not assumed. The price-create
    # per-field sweep so far: currency locked (2837),
    # unit_amount locked (2838), product locked (2839);
    # active is next, recurring remains. The other fields
    # sent are valid, so none can mask the 422: currency
    # "eur" (exactly 3 chars, non-blank after strip),
    # unit_amount 1000 (ge=0), product "prod_test123"
    # (min_length=1, non-blank after strip), recurring {}
    # (all RecurringDto fields defaulted, so {} is valid).
    # The DTO's mode="after" normalize_product validator
    # only runs after valid field parsing and only strips
    # string product/currency values, so it cannot mask the
    # 422. The endpoint is feature-gated (STRIPE) and
    # permission-gated (MANAGE_PRODUCTS_AND_PRICING) at the
    # router level, and FastAPI solves sub-dependencies
    # before validating the endpoint's own body, so the
    # tenant must be seeded with the STRIPE feature enabled
    # and the mocked caller's role must be seeded with the
    # permission first -- otherwise the feature gate's 403
    # or the permission gate's RoleNotFoundException 404
    # would mask the 422, exactly as in the product-create
    # locks. The tenant id (68c302ef6bf7a039b7e9b388) is both
    # the X-Tenant-ID header value and the caller's
    # tenant_id, so the handler's _assert_create_scope
    # check would also pass; the 422 comes from validation,
    # before the handler runs at all. FastAPI request
    # validation fails before the handler body runs:
    # PricingService.create_price never runs, so no Stripe
    # call is made. Deliberately no exact error-type
    # assertion, mirroring the product non-string-field 422
    # locks. Deliberately no Cache-Control/Pragma assertion:
    # a 422 is FastAPI request validation, not an
    # ApiBaseException, so the central handler's no-store
    # headers do not apply to it, mirroring the product 422
    # locks. The security headers ARE locked: the pure-ASGI
    # middleware stamps every HTTP response, including
    # validation errors, with no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.entities.tenant import Feature, Tenant
    from api.domain.enum.feature import Feature as FeatureEnum
    from api.domain.enum.permission import Permission

    await Tenant(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b388"),
        name="prices-validation-tenant",
        subdomain="prices-validation.fsrapp.com",
        features=[Feature(name=FeatureEnum.STRIPE, enabled=True)],
    ).insert()
    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Tenant price manager",
        description="Role carrying MANAGE_PRODUCTS_AND_PRICING for the mocked caller",
        permissions=[Permission.MANAGE_PRODUCTS_AND_PRICING],
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
                name="Tenant price manager",
                description="Role carrying MANAGE_PRODUCTS_AND_PRICING for the mocked caller",
                created_at="2024-10-01T00:00:00Z",
                updated_at="2024-10-01T00:00:00Z",
                permissions=[Permission.MANAGE_PRODUCTS_AND_PRICING],
            ),
            subscription=None,
        )

    original_override = app.dependency_overrides.get(get_current_user)
    app.dependency_overrides[get_current_user] = override_get_current_user_tenant_scoped
    try:
        response = await client.post(
            "/prices/",
            headers={"X-Tenant-ID": "68c302ef6bf7a039b7e9b388"},
            json={
                "currency": "eur",
                "unit_amount": 1000,
                "product": "prod_test123",
                "active": ["not-a-bool"],
                "recurring": {},
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
        "active" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the product locks, using substring checks so
    # later additions to the list do not break this test.
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
    # runs, so no Stripe call is made and nothing is created
    # -- the seeded role is still there with
    # MANAGE_PRODUCTS_AND_PRICING and the seeded tenant is
    # still there with the STRIPE feature enabled. Prices
    # are Stripe objects, not DB rows, so the tenant row is
    # the observable postcondition.
    stored_role = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored_role is not None
    assert stored_role.permissions == [Permission.MANAGE_PRODUCTS_AND_PRICING]
    stored_tenant = await Tenant.find_one(
        Tenant.id == PydanticObjectId("68c302ef6bf7a039b7e9b388")
    )
    assert stored_tenant is not None
    assert stored_tenant.features == [Feature(name=FeatureEnum.STRIPE, enabled=True)]
