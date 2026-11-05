import pytest
from httpx import AsyncClient

from api import app
from api.common.enums.gender import Gender
from api.domain.dtos.auth_dto import MeResponseDto
from api.domain.dtos.role_dto import RoleDto
from api.infrastructure.security.current_user import get_current_user


@pytest.mark.asyncio
async def test_get_billing_plans_with_feature_disabled_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        The billing area had no interface test file at all, so
    deleting the billing router from api/__init__.py — or dropping
    the central ApiBaseException no-store lines or the
    security-headers middleware registration — would previously
    have gone uncaught here even though every other interface
    area locks its headers in. The billing router is feature-gated
    at the router level (Feature.STRIPE), in front of every
    handler, so the success path is not asserted here: it
    needs a Stripe account with plans, which the shared
    conftest client does not provide, and the plan list is a
    live external-service read. The error path below is
    deterministic instead, and it reuses the per-test
    MeResponseDto override pattern from the products test: the
    billing router's feature gate runs before any handler (the
    plan-list handler itself takes only CurrentUserOptional and
    has no permission dependency), but the gate reads
    currentUser.role, so with a role carrying no permissions
    and no tenant the host-scope branch of
    check_feature_access raises
    FeatureNotEnabledException("stripe") before the handler
    runs — so no Stripe service is ever reached and no live
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
    after an account switch on a shared machine, and the plan
    list is scope-dependent catalog configuration (host vs
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
        response = await client.get("/billing/plans")
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

    # Same security-headers lock as the products test: the
    # pure-ASGI middleware stamps every HTTP response with no
    # path exclusions, so the billing 403 must carry the same headers
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
    # the products lock, using substring checks so later additions
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
async def test_delete_billing_plan_with_feature_disabled_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        Second-path lock for the billing area: the GET test locks
        GET /billing/plans only, so deleting just the delete route
        (delete_plan) would previously have gone uncaught — the
        GET 403 would still pass while DELETE /billing/plans/<id>
        silently became a 404. The delete route sits under the
        same router-level Feature.STRIPE gate as the plan list,
        in front of the MANAGE_BILLING permission dependency, the
        create-scope guard, and the handler, so the same
        deterministic error path applies: with a role carrying no
        permissions and no tenant, the host-scope branch of
        check_feature_access raises
        FeatureNotEnabledException("stripe") before the permission
        check, the scope guard, or the handler runs — so no Stripe
        service is ever reached, no live external call is made,
        and no plan is deleted (no side effect). DELETE takes no
        body, so unlike POST/PATCH there is no validation that
        could mask the 403; the :path plan_id param is a plain
        string and cannot mask the error either. The shared
        conftest mock cannot be used directly: it is a plain
        UserDto with no role attribute, so the gate would fail
        with an AttributeError 500 instead of the deterministic
        403. In production that cannot happen: get_current_user
        builds a MeResponseDto (role is a required field) and
        raises RoleNotFoundException before any feature check when
        the role row is missing. The original override is restored
        in finally, so no other test's mock is affected. That 403
        must still carry the error-response headers: a cached 403
        could otherwise be served to a different user after an
        account switch on a shared machine, and plan deletions
        are account-visible catalog configuration.
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
        response = await client.delete("/billing/plans/plan_test123")
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

    # Same security-headers lock as the billing GET test: the
    # pure-ASGI middleware stamps every HTTP response with no
    # path exclusions, so the billing DELETE 403 must carry the
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
    # the billing GET lock, using substring checks so later
    # additions to the list do not break this test. The full value
    # lives in _SECURITY_HEADERS. Each directive is safe to lock
    # here for the same reasons as on the other routes: the SPA
    # has no camera, microphone, geolocation, payment,
    # clipboard-read, display-capture, fullscreen, motion-sensor,
    # compass, XR, or idle-detection flow (verified by grep in
    # the earlier sweeps and re-verified fresh this run: zero
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
async def test_post_billing_plan_with_feature_disabled_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        Second-path lock for the billing area: the GET and DELETE
        tests lock those routes only, so dropping the router-level
        gate on the create route (create_plan) would previously
        have gone uncaught — the GET/DELETE 403s would still pass
        while POST /billing/plans silently reached the handler
        (and Stripe) instead of the deterministic 403. The create
        route sits under the same router-level Feature.STRIPE gate
        as the plan list and delete, in front of the MANAGE_BILLING
        permission dependency, the create-scope guard, and the
        handler, so the same deterministic error path applies:
        with a role carrying no permissions and no tenant, the
        host-scope branch of check_feature_access raises
        FeatureNotEnabledException("stripe") before the permission
        check, the scope guard, or the handler runs — so no Stripe
        service is ever reached, no live external call is made,
        and no plan is created (no side effect). The body is
        valid under CreatePlanDto — interval "month" is a
        permitted literal, product_id is non-blank with
        min_length=1, amount 1000 satisfies ge=1, and currency
        defaults to "eur" — so no 422 can mask the 403 whatever
        the validation-vs-dependency ordering. The shared
        conftest mock cannot be used directly: it is a plain
        UserDto with no role attribute, so the gate would fail
        with an AttributeError 500 instead of the deterministic
        403. In production that cannot happen: get_current_user
        builds a MeResponseDto (role is a required field) and
        raises RoleNotFoundException before any feature check when
        the role row is missing. The original override is restored
        in finally, so no other test's mock is affected. That 403
        must still carry the error-response headers: a cached 403
        could otherwise be served to a different user after an
        account switch on a shared machine, and plan creation is
        account-visible catalog configuration.
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
        response = await client.post(
            "/billing/plans",
            json={"interval": "month", "product_id": "prod_test123", "amount": 1000},
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

    # Same security-headers lock as the billing GET and DELETE
    # tests: the pure-ASGI middleware stamps every HTTP response
    # with no path exclusions, so the billing POST 403 must carry
    # the same headers as the authenticated GETs, including the
    # exception-handler responses.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the twelve most sensitive directives as disabled, mirroring
    # the billing GET and DELETE locks, using substring checks so
    # later additions to the list do not break this test. The full
    # value lives in _SECURITY_HEADERS. Each directive is safe to
    # lock here for the same reasons as on the other routes: the
    # SPA has no camera, microphone, geolocation, payment,
    # clipboard-read, display-capture, fullscreen, motion-sensor,
    # compass, XR, or idle-detection flow (verified by grep in the
    # earlier sweeps and re-verified fresh this run: zero
    # case-insensitive idle matches across frontend/app/src, and
    # the remaining flows verified absent).
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
async def test_patch_billing_plan_with_feature_disabled_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        Second-path lock for the billing area: the GET, DELETE and
        POST tests lock those routes only, so dropping the
        router-level gate on the update route (update_plan) would
        previously have gone uncaught — the other 403s would still
        pass while PATCH /billing/plans/{plan_id} silently reached
        the handler (and Stripe) instead of the deterministic 403.
        The update route sits under the same router-level
        Feature.STRIPE gate as the plan list, delete and create,
        in front of the MANAGE_BILLING permission dependency, the
        create-scope guard, and the handler, so the same
        deterministic error path applies: with a role carrying no
        permissions and no tenant, the host-scope branch of
        check_feature_access raises
        FeatureNotEnabledException("stripe") before the permission
        check, the scope guard, or the handler runs — so no Stripe
        service is ever reached, no live external call is made,
        and no plan is updated (no side effect). The body is
        valid under UpdatePlanDto — trial_period_days 14 is
        within ge=0/le=365, active defaults to None (leave
        unchanged) and metadata defaults to None — so no 422 can
        mask the 403 whatever the validation-vs-dependency
        ordering, and the :path plan_id param is a plain string
        and cannot mask the error. The shared conftest mock
        cannot be used directly: it is a plain UserDto with no
        role attribute, so the gate would fail with an
        AttributeError 500 instead of the deterministic 403. In
        production that cannot happen: get_current_user builds a
        MeResponseDto (role is a required field) and raises
        RoleNotFoundException before any feature check when the
        role row is missing. The original override is restored
        in finally, so no other test's mock is affected. That 403
        must still carry the error-response headers: a cached 403
        could otherwise be served to a different user after an
        account switch on a shared machine, and plan updates are
        account-visible catalog configuration.
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
        response = await client.patch(
            "/billing/plans/plan_test123",
            json={"trial_period_days": 14},
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

    # Same security-headers lock as the billing GET, DELETE and
    # POST tests: the pure-ASGI middleware stamps every HTTP
    # response with no path exclusions, so the billing PATCH 403
    # must carry the same headers as the authenticated GETs,
    # including the exception-handler responses.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the twelve most sensitive directives as disabled, mirroring
    # the billing GET, DELETE and POST locks, using substring
    # checks so later additions to the list do not break this
    # test. The full value lives in _SECURITY_HEADERS. Each
    # directive is safe to lock here for the same reasons as on
    # the other routes: the SPA has no camera, microphone,
    # geolocation, payment, clipboard-read, display-capture,
    # fullscreen, motion-sensor, compass, XR, or idle-detection
    # flow (verified by grep in the earlier sweeps and re-verified
    # fresh this run: zero case-insensitive idle matches across
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
async def test_get_billing_plan_detail_with_feature_disabled_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        Second-path lock for the billing area: the GET, DELETE,
        POST and PATCH tests lock those routes only, so dropping
        just the detail route (get_plan) would previously have
        gone uncaught — the other 403s would still pass while
        GET /billing/plans/<id> silently became a 404. The
        detail route sits under the same router-level
        Feature.STRIPE gate as the plan list, in front of the
        handler, so the same deterministic error path applies:
        with a role carrying no permissions and no tenant, the
        host-scope branch of check_feature_access raises
        FeatureNotEnabledException("stripe") before the handler
        runs — so no Stripe service is ever reached, no live
        external call is made, and the detail read is a pure
        GET (no side effect). GET takes no body, so there is no
        validation that could mask the 403; the :path plan_id
        param is a plain string and cannot mask the error
        either, and the detail handler has no permission
        dependency in front of the gate. The shared conftest
        mock cannot be used directly: it is a plain UserDto
        with no role attribute, so the gate would fail with an
        AttributeError 500 instead of the deterministic 403. In
        production that cannot happen: get_current_user builds
        a MeResponseDto (role is a required field) and raises
        RoleNotFoundException before any feature check when the
        role row is missing. The original override is restored
        in finally, so no other test's mock is affected. That
        403 must still carry the error-response headers: a
        cached 403 could otherwise be served to a different user
        after an account switch on a shared machine, and plan
        details are scope-dependent catalog configuration (host
        vs tenant), which the handler itself marks no-store on
        the success path.
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
        response = await client.get("/billing/plans/plan_test123")
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

    # Same security-headers lock as the billing GET, DELETE,
    # POST and PATCH tests: the pure-ASGI middleware stamps
    # every HTTP response with no path exclusions, so the
    # billing detail 403 must carry the same headers as the
    # authenticated GETs, including the exception-handler
    # responses.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the twelve most sensitive directives as disabled, mirroring
    # the billing GET, DELETE, POST and PATCH locks, using
    # substring checks so later additions to the list do not
    # break this test. The full value lives in _SECURITY_HEADERS.
    # Each directive is safe to lock here for the same reasons as
    # on the other routes: the SPA has no camera, microphone,
    # geolocation, payment, clipboard-read, display-capture,
    # fullscreen, motion-sensor, compass, XR, or idle-detection
    # flow (verified by grep in the earlier sweeps and re-verified
    # fresh this run: zero IdleDetector/requestIdleCallback and
    # zero case-insensitive idle matches across frontend/app/src,
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
async def test_post_billing_plan_outside_tenant_scope_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        The billing create scope-guard error path:
    """
    # The /billing/plans create scope-guard branch, not yet
    # locked: function-name grep count 0 for
    # post_billing_plan_outside_tenant_scope (verified fresh
    # this run), and no test in this file asserts a 403 with
    # an "outside your tenant's scope" message - the locks
    # cover only the feature-disabled 403s. Deleting
    # _assert_create_scope (billing_endpoint.py:18-36) would
    # previously have gone uncaught, and a tenant caller
    # creating a plan on the wrong DB would then have the
    # plan written into the HOST Stripe account (the tenant
    # Stripe resolver reads the singleton settings record in
    # the current DB with no tenant filter), polluting the
    # host catalog and hiding the plan from the caller's own
    # tenant Stripe account. The guard runs first in the
    # handler body, before any Stripe call. It cannot be
    # reached the way the roles/users/audit-logs locks reach
    # their guards (tenant-scoped caller, no X-Tenant-ID
    # header): the billing router is feature-gated, and
    # check_feature_access looks the tenant up by
    # request.state.tenant_id before the handler runs, so
    # with no header the lookup gets None, BaseRepository.get
    # returns None, and get_tenant_by_id raises
    # TenantNotFoundException - a 404 from the gate, never
    # the scope 403. The lock therefore uses the mismatched
    # scope the guard is written for: the caller is
    # tenant-scoped to 68c302ef6bf7a039b7e9b387 while the
    # request carries X-Tenant-ID
    # 68c302ef6bf7a039b7e9b388, a seeded tenant with the
    # STRIPE feature enabled, so the feature gate passes
    # (Tenant stays bound to the host DB - init_db excludes
    # it from the tenant-DB models, mongodb.py:53-56 - so
    # the lookup finds the seeded row) and the guard raises
    # ForbiddenException before any Stripe call. The caller
    # override mirrors the audit-logs lock's pattern
    # (per-test MeResponseDto, restored in finally), but the
    # role must carry MANAGE_BILLING here: unlike /ai/ask,
    # the billing create route has a MANAGE_BILLING
    # permission dependency that runs before the handler
    # body, so a role without it would 403 with
    # "Insufficient permissions." instead of the scope
    # message. The body is the same valid body the
    # feature-disabled POST lock puts (interval "month",
    # product_id non-blank, amount 1000, currency defaults
    # to "eur"), so no 422 can mask the 403. The central
    # ApiBaseException handler maps ForbiddenException to
    # 403 (api/__init__.py:98-103) with {"error": ...,
    # "code": 403} and the no-store/Pragma error headers. A
    # future change that drops the guard would break this
    # lock while leaving the feature-disabled POST /billing
    # /plans 403 lock green, so the two paths are locked
    # separately.
    from beanie import PydanticObjectId

    from api.domain.entities.tenant import Feature, Tenant
    from api.domain.enum.feature import Feature as FeatureEnum
    from api.domain.enum.permission import Permission

    await Tenant(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b388"),
        name="billing-scope-tenant",
        subdomain="billing-scope.fsrapp.com",
        features=[Feature(name=FeatureEnum.STRIPE, enabled=True)],
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
                name="Tenant billing caller",
                description="Role for the tenant-scoped billing create caller",
                created_at="2024-10-01T00:00:00Z",
                updated_at="2024-10-01T00:00:00Z",
                permissions=[Permission.MANAGE_BILLING],
            ),
            subscription=None,
        )

    original_override = app.dependency_overrides.get(get_current_user)
    app.dependency_overrides[get_current_user] = override_get_current_user_tenant_scoped
    try:
        response = await client.post(
            "/billing/plans",
            json={"interval": "month", "product_id": "prod_test123", "amount": 1000},
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
    # handler sets no-store only on the success path, so on this
    # path they come from the central ApiBaseException handler,
    # and a cached 403 could otherwise be served to a different
    # user after an account switch on a shared machine.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the billing POST
    # feature-disabled test: the pure-ASGI middleware stamps
    # every HTTP response with no path exclusions, so the
    # billing 403 must carry the same headers as the
    # authenticated calls, including the exception-handler
    # responses.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened:
    # lock the twelve most sensitive directives as disabled,
    # mirroring the billing POST feature-disabled lock, using
    # substring checks so later additions to the list do not
    # break this test. Each directive is safe to lock here for
    # the same reasons as on the other billing routes: the SPA
    # has no camera, microphone, geolocation, payment,
    # clipboard-read, display-capture, fullscreen,
    # motion-sensor, compass, XR, or idle-detection flow
    # (verified by grep in the earlier sweeps).
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
    # Postconditions: the guard fires before any Stripe call,
    # so no plan was created in either Stripe account, and the
    # seeded tenant is still there with the STRIPE feature
    # enabled (there is no DB record a plan write would leave
    # behind - plans are Stripe objects, not DB rows - so the
    # tenant row is the observable postcondition).
    stored = await Tenant.find_one(
        Tenant.id == PydanticObjectId("68c302ef6bf7a039b7e9b388")
    )
    assert stored is not None
    assert stored.features == [Feature(name=FeatureEnum.STRIPE, enabled=True)]


@pytest.mark.asyncio
async def test_patch_billing_plan_outside_tenant_scope_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        The billing update scope-guard error path:
    """
    # The /billing/plans/{plan_id} update scope-guard branch,
    # not yet locked: function-name grep count 0 for
    # patch_billing_plan_outside_tenant_scope (verified fresh
    # this run), and no test in this file asserts a 403 with
    # an "outside your tenant's scope" message on PATCH - the
    # locks cover only the feature-disabled 403s and the POST
    # create scope 403 (previous run). PATCH shares the same
    # _assert_create_scope guard (billing_endpoint.py:18-36)
    # as POST, called first in the update handler body
    # (:122-136), but a future change could drop the guard
    # call from update_plan while leaving create_plan's call
    # intact, and the POST lock would stay green while PATCH
    # silently wrote into the HOST Stripe account. Deleting
    # the guard would previously have gone uncaught on this
    # route: a tenant caller updating a plan on the wrong DB
    # would then have the update applied to the HOST Stripe
    # account (the tenant Stripe resolver reads the singleton
    # settings record in the current DB with no tenant
    # filter), mutating the host catalog and hiding the change
    # from the caller's own tenant Stripe account. The guard
    # runs first in the handler body, before any Stripe call.
    # It cannot be reached the way the roles/users/audit-logs
    # locks reach their guards (tenant-scoped caller, no
    # X-Tenant-ID header): the billing router is
    # feature-gated, and check_feature_access looks the tenant
    # up by request.state.tenant_id before the handler runs, so
    # with no header the lookup gets None, BaseRepository.get
    # returns None, and get_tenant_by_id raises
    # TenantNotFoundException - a 404 from the gate, never the
    # scope 403. The lock therefore uses the mismatched scope
    # the guard is written for: the caller is tenant-scoped to
    # 68c302ef6bf7a039b7e9b387 while the request carries
    # X-Tenant-ID 68c302ef6bf7a039b7e9b388, a seeded tenant
    # with the STRIPE feature enabled, so the feature gate
    # passes (Tenant stays bound to the host DB - init_db
    # excludes it from the tenant-DB models, mongodb.py:53-56
    # - so the lookup finds the seeded row) and the guard
    # raises ForbiddenException before any Stripe call. The
    # caller override mirrors the POST scope lock's pattern
    # (per-test MeResponseDto, restored in finally), and the
    # role must carry MANAGE_BILLING here: like create, the
    # update route has a MANAGE_BILLING permission dependency
    # that runs before the handler body, so a role without it
    # would 403 with "Insufficient permissions." instead of
    # the scope message. The body is the same valid body the
    # feature-disabled PATCH lock puts (trial_period_days 14,
    # within ge=0/le=365; active and metadata default to None),
    # so no 422 can mask the 403, and the :path plan_id param
    # is a plain string and cannot mask the error. The central
    # ApiBaseException handler maps ForbiddenException to 403
    # (api/__init__.py:98-103) with {"error": ..., "code": 403}
    # and the no-store/Pragma error headers. A future change
    # that drops the guard from update_plan would break this
    # lock while leaving the feature-disabled PATCH 403 lock
    # and the POST scope 403 lock green, so the paths are
    # locked separately.
    from beanie import PydanticObjectId

    from api.domain.entities.tenant import Feature, Tenant
    from api.domain.enum.feature import Feature as FeatureEnum
    from api.domain.enum.permission import Permission

    await Tenant(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b388"),
        name="billing-scope-tenant",
        subdomain="billing-scope.fsrapp.com",
        features=[Feature(name=FeatureEnum.STRIPE, enabled=True)],
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
                name="Tenant billing caller",
                description="Role for the tenant-scoped billing update caller",
                created_at="2024-10-01T00:00:00Z",
                updated_at="2024-10-01T00:00:00Z",
                permissions=[Permission.MANAGE_BILLING],
            ),
            subscription=None,
        )

    original_override = app.dependency_overrides.get(get_current_user)
    app.dependency_overrides[get_current_user] = override_get_current_user_tenant_scoped
    try:
        response = await client.patch(
            "/billing/plans/plan_test123",
            json={"trial_period_days": 14},
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
    # handler sets no-store only on the success path, so on this
    # path they come from the central ApiBaseException handler,
    # and a cached 403 could otherwise be served to a different
    # user after an account switch on a shared machine.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the billing PATCH
    # feature-disabled test: the pure-ASGI middleware stamps
    # every HTTP response with no path exclusions, so the
    # billing 403 must carry the same headers as the
    # authenticated calls, including the exception-handler
    # responses.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened:
    # lock the twelve most sensitive directives as disabled,
    # mirroring the billing PATCH feature-disabled lock, using
    # substring checks so later additions to the list do not
    # break this test. Each directive is safe to lock here for
    # the same reasons as on the other billing routes: the SPA
    # has no camera, microphone, geolocation, payment,
    # clipboard-read, display-capture, fullscreen,
    # motion-sensor, compass, XR, or idle-detection flow
    # (verified by grep in the earlier sweeps).
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
    # Postconditions: the guard fires before any Stripe call,
    # so no plan was updated in either Stripe account, and the
    # seeded tenant is still there with the STRIPE feature
    # enabled (there is no DB record a plan write would leave
    # behind - plans are Stripe objects, not DB rows - so the
    # tenant row is the observable postcondition).
    stored = await Tenant.find_one(
        Tenant.id == PydanticObjectId("68c302ef6bf7a039b7e9b388")
    )
    assert stored is not None
    assert stored.features == [Feature(name=FeatureEnum.STRIPE, enabled=True)]


async def test_delete_billing_plan_outside_tenant_scope_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        The billing delete scope-guard error path:
    """
    # The /billing/plans/{plan_id} delete scope-guard branch,
    # not yet locked: function-name grep count 0 for
    # delete_billing_plan_outside_tenant_scope (verified fresh
    # this run), and no test in this file asserts a 403 with
    # an "outside your tenant's scope" message on DELETE - the
    # locks cover only the feature-disabled 403s and the POST
    # create and PATCH update scope 403s (previous runs).
    # DELETE shares the same _assert_create_scope guard
    # (billing_endpoint.py:18-36) as POST and PATCH, called
    # first in the delete handler body (:82-104), but a future
    # change could drop the guard call from delete_plan while
    # leaving create_plan's and update_plan's calls intact,
    # and the POST/PATCH locks would stay green while DELETE
    # silently removed a plan from the HOST Stripe account.
    # Deleting the guard would previously have gone uncaught
    # on this route: a tenant caller deleting a plan on the
    # wrong DB would then have the deletion applied to the
    # HOST Stripe account (the tenant Stripe resolver reads
    # the singleton settings record in the current DB with no
    # tenant filter), removing a host catalog entry and hiding
    # the change from the caller's own tenant Stripe account.
    # The guard runs first in the handler body, before any
    # Stripe call. It cannot be reached the way the
    # roles/users/audit-logs locks reach their guards
    # (tenant-scoped caller, no X-Tenant-ID header): the
    # billing router is feature-gated, and
    # check_feature_access looks the tenant up by
    # request.state.tenant_id before the handler runs, so with
    # no header the lookup gets None, BaseRepository.get
    # returns None, and get_tenant_by_id raises
    # TenantNotFoundException - a 404 from the gate, never the
    # scope 403. The lock therefore uses the mismatched scope
    # the guard is written for: the caller is tenant-scoped to
    # 68c302ef6bf7a039b7e9b387 while the request carries
    # X-Tenant-ID 68c302ef6bf7a039b7e9b388, a seeded tenant
    # with the STRIPE feature enabled, so the feature gate
    # passes (Tenant stays bound to the host DB - init_db
    # excludes it from the tenant-DB models, mongodb.py:53-56
    # - so the lookup finds the seeded row) and the guard
    # raises ForbiddenException before any Stripe call. The
    # caller override mirrors the PATCH scope lock's pattern
    # (per-test MeResponseDto, restored in finally), and the
    # role must carry MANAGE_BILLING here: like create and
    # update, the delete route has a MANAGE_BILLING permission
    # dependency that runs before the handler body, so a role
    # without it would 403 with "Insufficient permissions."
    # instead of the scope message. DELETE carries no body,
    # so no 422 can mask the 403, and the :path plan_id param
    # is a plain string and cannot mask the error. The central
    # ApiBaseException handler maps ForbiddenException to 403
    # (api/__init__.py:98-103) with {"error": ..., "code": 403}
    # and the no-store/Pragma error headers. A future change
    # that drops the guard from delete_plan would break this
    # lock while leaving the feature-disabled DELETE 403 lock
    # and the POST/PATCH scope 403 locks green, so the paths
    # are locked separately.
    from beanie import PydanticObjectId

    from api.domain.entities.tenant import Feature, Tenant
    from api.domain.enum.feature import Feature as FeatureEnum
    from api.domain.enum.permission import Permission

    await Tenant(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b388"),
        name="billing-scope-tenant",
        subdomain="billing-scope.fsrapp.com",
        features=[Feature(name=FeatureEnum.STRIPE, enabled=True)],
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
                name="Tenant billing caller",
                description="Role for the tenant-scoped billing delete caller",
                created_at="2024-10-01T00:00:00Z",
                updated_at="2024-10-01T00:00:00Z",
                permissions=[Permission.MANAGE_BILLING],
            ),
            subscription=None,
        )

    original_override = app.dependency_overrides.get(get_current_user)
    app.dependency_overrides[get_current_user] = override_get_current_user_tenant_scoped
    try:
        response = await client.delete(
            "/billing/plans/plan_test123",
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
    # handler sets no-store only on the success path, so on this
    # path they come from the central ApiBaseException handler,
    # and a cached 403 could otherwise be served to a different
    # user after an account switch on a shared machine.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the billing DELETE
    # feature-disabled test: the pure-ASGI middleware stamps
    # every HTTP response with no path exclusions, so the
    # billing 403 must carry the same headers as the
    # authenticated calls, including the exception-handler
    # responses.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened:
    # lock the twelve most sensitive directives as disabled,
    # mirroring the billing DELETE feature-disabled lock, using
    # substring checks so later additions to the list do not
    # break this test. Each directive is safe to lock here for
    # the same reasons as on the other billing routes: the SPA
    # has no camera, microphone, geolocation, payment,
    # clipboard-read, display-capture, fullscreen,
    # motion-sensor, compass, XR, or idle-detection flow
    # (verified by grep in the earlier sweeps).
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
    # Postconditions: the guard fires before any Stripe call,
    # so no plan was deleted in either Stripe account, and the
    # seeded tenant is still there with the STRIPE feature
    # enabled (there is no DB record a plan write would leave
    # behind - plans are Stripe objects, not DB rows - so the
    # tenant row is the observable postcondition).
    stored = await Tenant.find_one(
        Tenant.id == PydanticObjectId("68c302ef6bf7a039b7e9b388")
    )
    assert stored is not None
    assert stored.features == [Feature(name=FeatureEnum.STRIPE, enabled=True)]
