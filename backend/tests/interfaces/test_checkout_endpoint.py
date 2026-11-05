import pytest
from httpx import AsyncClient

from api import app
from api.common.enums.gender import Gender
from api.domain.dtos.auth_dto import MeResponseDto
from api.domain.dtos.role_dto import RoleDto
from api.infrastructure.security.current_user import get_current_user


@pytest.mark.asyncio
async def test_get_checkout_records_with_feature_disabled_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        The checkout area had no interface test file at all, so
    deleting the checkout router from api/__init__.py — or dropping
    the central ApiBaseException no-store lines or the
    security-headers middleware registration — would previously
    have gone uncaught here even though every other interface
    area locks its headers in. The checkout router is feature-gated
    at the router level (Feature.STRIPE), in front of every
    handler, so the success path is not asserted here: it
    needs a Stripe account and a billing-record service, which the
    shared conftest client does not provide, and the record list
    is a financial read. The error path below is
    deterministic instead, and it reuses the per-test
    MeResponseDto override pattern from the billing test: the
    checkout router's feature gate runs before any handler (the
    record-list handler itself carries a MANAGE_BILLING permission
    dependency, but that is never reached), but the gate reads
    currentUser.role, so with a role carrying no permissions
    and no tenant the host-scope branch of
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
    after an account switch on a shared machine, and the record
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
        response = await client.get("/checkouts/all")
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

    # Same security-headers lock as the billing test: the
    # pure-ASGI middleware stamps every HTTP response with no
    # path exclusions, so the checkout 403 must carry the same headers
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
    # the billing lock, using substring checks so later additions
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
async def test_create_host_checkout_session_with_feature_disabled_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        Second-path lock for the checkout area: the GET test locks
        GET /checkouts/all only, so deleting just the host checkout
        POST route (create_host_checkout_session) would previously
        have gone uncaught — the GET 403 would still pass while
        POST /checkouts/host/<tenant_id>/tenant silently became
        a 404. The POST route sits under the same router-level
        Feature.STRIPE gate as the record list, in front of the
        handler, the tenant/email scope guards, and the billing
        service, so the same deterministic error path applies:
        with a role carrying no permissions and no tenant, the
        host-scope branch of check_feature_access raises
        FeatureNotEnabledException("stripe") before the handler
        runs — so no Stripe service is ever reached, no live
        external call is made, and no checkout session or billing
        record is created (no side effect). The request body is
        deliberately valid under CheckoutRequestDto (a non-empty
        price_id, a valid email, mode "subscription"), so no 422
        can mask the 403 even if body validation runs before the
        router-level gate; the :path tenant_id param is a plain
        string and cannot mask the error either. The shared
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
        after an account switch on a shared machine, and a host
        checkout session is scope-dependent financial
        configuration, which the handler itself marks no-store
        on the success path.
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
            "/checkouts/host/68c302ef6bf7a039b7e9b387/tenant",
            json={
                "price_id": "price_test",
                "email": "admin@example.com",
                "mode": "subscription",
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
    assert "stripe" in body["error"]
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the checkout GET test: the
    # pure-ASGI middleware stamps every HTTP response with no
    # path exclusions, so the checkout POST 403 must carry the
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
    # the checkout GET lock, using substring checks so later
    # additions to the list do not break this test. The full value
    # lives in _SECURITY_HEADERS. Each directive is safe to lock
    # here for the same reasons as on the other routes: the SPA
    # has no camera, microphone, geolocation, payment,
    # clipboard-read, display-capture, fullscreen, motion-sensor,
    # compass, XR, or idle-detection flow (verified by grep in
    # the earlier sweeps and re-verified fresh this run: zero
    # case-insensitive idle matches across frontend/app/src).
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
async def test_create_tenant_checkout_session_with_feature_disabled_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        Second-path lock for the checkout area: the GET and host
        POST tests lock their routes only, so deleting just the
        tenant checkout POST route
        (create_tenant_checkout_session) would previously have
        gone uncaught — the other 403s would still pass while
        POST /checkouts/tenant/subscription silently became a
        404. The tenant POST route sits under the same
        router-level Feature.STRIPE gate as the other checkout
        routes, in front of the handler and its service
        dependencies (get_tenant_service,
        get_billing_record_service, get_tenant_id), so the same
        deterministic error path applies: with a role carrying
        no permissions and no tenant, the host-scope branch of
        check_feature_access raises
        FeatureNotEnabledException("stripe") before the handler
        runs — so no tenant lookup happens, no Stripe service is
        ever reached, no live external call is made, and no
        checkout session or billing record is created (no side
        effect). The request body is deliberately valid under
        CheckoutRequestDto (a non-empty price_id, a valid
        email, mode "subscription", tenant_id omitted/None), so
        no 422 can mask the 403 even if body validation runs
        before the router-level gate. The shared conftest mock
        cannot be used directly: it is a plain UserDto with no
        role attribute, so the gate would fail with an
        AttributeError 500 instead of the deterministic 403.
        In production that cannot happen: get_current_user
        builds a MeResponseDto (role is a required field) and
        raises RoleNotFoundException before any feature check
        when the role row is missing. The original override is
        restored in finally, so no other test's mock is
        affected. That 403 must still carry the error-response
        headers: a cached 403 could otherwise be served to a
        different user after an account switch on a shared
        machine, and a tenant checkout session is
        scope-dependent financial configuration, which the
        handler itself marks no-store on the success path.
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
            "/checkouts/tenant/subscription",
            json={
                "price_id": "price_test",
                "email": "admin@example.com",
                "mode": "subscription",
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
    assert "stripe" in body["error"]
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the checkout GET and host
    # POST tests: the pure-ASGI middleware stamps every HTTP
    # response with no path exclusions, so the tenant checkout
    # POST 403 must carry the same headers as the
    # authenticated GETs, including the exception-handler
    # responses.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened:
    # lock the twelve most sensitive directives as disabled,
    # mirroring the checkout GET lock, using substring checks
    # so later additions to the list do not break this test.
    # The full value lives in _SECURITY_HEADERS. Each directive
    # is safe to lock here for the same reasons as on the other
    # routes: the SPA has no camera, microphone, geolocation,
    # payment, clipboard-read, display-capture, fullscreen,
    # motion-sensor, compass, XR, or idle-detection flow
    # (verified by grep in the earlier sweeps and re-verified
    # fresh this run: zero IdleDetector/requestIdleCallback
    # matches and zero case-insensitive idle matches across
    # frontend/app/src, and the remaining flows verified
    # absent).
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
async def test_host_checkout_success_with_feature_disabled_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        Second-path lock for the checkout area: the GET, host
        POST, and tenant POST tests lock their routes only, so
        deleting just the host payment-success callback route
        (host_checkout_success) would previously have gone
        uncaught — the other 403s would still pass while
        POST /checkouts/host/payment/success silently became a
        404. The callback sits under the same router-level
        Feature.STRIPE gate as the other checkout routes, in
        front of the handler and its billing-service
        dependency, so the same deterministic error path
        applies: with a role carrying no permissions and no
        tenant, the host-scope branch of check_feature_access
        raises FeatureNotEnabledException("stripe") before the
        handler runs — so no tenant lookup happens, no Stripe
        service is ever reached, no live external call is made,
        and no billing record is finalised (no side effect).
        Both query params are supplied (a non-empty
        session_id and a tenant_id), so no 422 can mask the
        403 even if query validation runs before the
        router-level gate. The shared conftest mock cannot be
        used directly: it is a plain UserDto with no role
        attribute, so the gate would fail with an
        AttributeError 500 instead of the deterministic 403.
        In production that cannot happen: get_current_user
        builds a MeResponseDto (role is a required field) and
        raises RoleNotFoundException before any feature check
        when the role row is missing. The original override is
        restored in finally, so no other test's mock is
        affected. That 403 must still carry the error-response
        headers: a cached 403 could otherwise be served to a
        different user after an account switch on a shared
        machine, and a payment-success callback finalises
        scope-dependent financial records, which the handler
        itself marks no-store on the success path.
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
            "/checkouts/host/payment/success",
            params={
                "session_id": "cs_test_session",
                "tenant_id": "68c302ef6bf7a039b7e9b387",
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
    assert "stripe" in body["error"]
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the checkout GET, host
    # POST, and tenant POST tests: the pure-ASGI middleware
    # stamps every HTTP response with no path exclusions, so
    # the host payment-success 403 must carry the same headers
    # as the authenticated GETs, including the
    # exception-handler responses.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened:
    # lock the twelve most sensitive directives as disabled,
    # mirroring the checkout GET lock, using substring checks
    # so later additions to the list do not break this test.
    # The full value lives in _SECURITY_HEADERS. Each directive
    # is safe to lock here for the same reasons as on the other
    # routes: the SPA has no camera, microphone, geolocation,
    # payment, clipboard-read, display-capture, fullscreen,
    # motion-sensor, compass, XR, or idle-detection flow
    # (verified by grep in the earlier sweeps and re-verified
    # fresh this run: zero IdleDetector/requestIdleCallback
    # matches and zero case-insensitive idle matches across
    # frontend/app/src, and the remaining flows verified
    # absent).
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
async def test_host_checkout_cancel_with_feature_disabled_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        Second-path lock for the checkout area: the GET, host
        POST, tenant POST, and host payment-success tests lock
        their routes only, so deleting just the host
        payment-cancel callback route (host_checkout_canceled)
        would previously have gone uncaught — the other 403s
        would still pass while POST
        /checkouts/host/payment/cancel silently became a 404.
        The callback sits under the same router-level
        Feature.STRIPE gate as the other checkout routes, in
        front of the handler and its billing-service
        dependency, so the same deterministic error path
        applies: with a role carrying no permissions and no
        tenant, the host-scope branch of check_feature_access
        raises FeatureNotEnabledException("stripe") before the
        handler runs — so no tenant lookup happens, no Stripe
        service is ever reached, no live external call is made,
        and no billing record is canceled (no side effect).
        Unlike the success callback, the cancel callback takes
        only one query param (tenant_id, no session_id), and
        it is supplied here, so no 422 can mask the 403 even
        if query validation runs before the router-level gate.
        The shared conftest mock cannot be used directly: it
        is a plain UserDto with no role attribute, so the gate
        would fail with an AttributeError 500 instead of the
        deterministic 403. In production that cannot happen:
        get_current_user builds a MeResponseDto (role is a
        required field) and raises RoleNotFoundException
        before any feature check when the role row is missing.
        The original override is restored in finally, so no
        other test's mock is affected. That 403 must still
        carry the error-response headers: a cached 403 could
        otherwise be served to a different user after an
        account switch on a shared machine, and a
        payment-cancel callback touches scope-dependent
        financial records, which the handler itself marks
        no-store on the success path of the sibling route.
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
            "/checkouts/host/payment/cancel",
            params={
                "tenant_id": "68c302ef6bf7a039b7e9b387",
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
    assert "stripe" in body["error"]
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the checkout GET, host
    # POST, tenant POST, and host payment-success tests: the
    # pure-ASGI middleware stamps every HTTP response with no
    # path exclusions, so the host payment-cancel 403 must
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
    # mirroring the checkout GET lock, using substring checks
    # so later additions to the list do not break this test.
    # The full value lives in _SECURITY_HEADERS. Each directive
    # is safe to lock here for the same reasons as on the other
    # routes: the SPA has no camera, microphone, geolocation,
    # payment, clipboard-read, display-capture, fullscreen,
    # motion-sensor, compass, XR, or idle-detection flow
    # (verified by grep in the earlier sweeps and re-verified
    # fresh this run: zero IdleDetector/requestIdleCallback
    # matches and zero case-insensitive idle matches across
    # frontend/app/src, and the remaining flows verified
    # absent).
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
async def test_tenant_checkout_success_with_feature_disabled_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        Second-path lock for the checkout area: the GET, host
        POST, tenant POST, host payment-success, and host
        payment-cancel tests lock their routes only, so
        deleting just the tenant payment-success callback
        route (tenant_checkout_success) would previously
        have gone uncaught — the other 403s would still pass
        while POST /checkouts/tenant/payment/success
        silently became a 404. The callback sits under the
        same router-level Feature.STRIPE gate as the other
        checkout routes, in front of the handler and its
        billing-service and get_tenant_id dependencies, so
        the same deterministic error path applies: with a
        role carrying no permissions and no tenant, the
        host-scope branch of check_feature_access raises
        FeatureNotEnabledException("stripe") before the
        handler runs — so no scope guard runs, no Stripe
        service is ever reached, no live external call is
        made, and no billing record is finalised (no side
        effect). Unlike the host success callback, the
        tenant callback takes only one query param
        (session_id, no tenant_id), and it is supplied
        here, so no 422 can mask the 403 even if query
        validation runs before the router-level gate. The
        shared conftest mock cannot be used directly: it
        is a plain UserDto with no role attribute, so the
        gate would fail with an AttributeError 500 instead
        of the deterministic 403. In production that
        cannot happen: get_current_user builds a
        MeResponseDto (role is a required field) and
        raises RoleNotFoundException before any feature
        check when the role row is missing. The original
        override is restored in finally, so no other
        test's mock is affected. That 403 must still carry
        the error-response headers: a cached 403 could
        otherwise be served to a different user after an
        account switch on a shared machine, and a
        payment-success callback finalises
        scope-dependent financial records, which the
        handler itself marks no-store on the success path
        of the sibling record-list route.
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
            "/checkouts/tenant/payment/success",
            params={
                "session_id": "cs_test_session",
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
    assert "stripe" in body["error"]
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the checkout GET, host
    # POST, tenant POST, and host payment-callback tests:
    # the pure-ASGI middleware stamps every HTTP response
    # with no path exclusions, so the tenant
    # payment-success 403 must carry the same headers as
    # the authenticated GETs, including the
    # exception-handler responses.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened:
    # lock the twelve most sensitive directives as disabled,
    # mirroring the checkout GET lock, using substring checks
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

@pytest.mark.asyncio
async def test_tenant_checkout_cancel_with_feature_disabled_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        Second-path lock for the checkout area: the GET, host
        POST, tenant POST, host payment-success, host
        payment-cancel, and tenant payment-success tests lock
        their routes only, so deleting just the tenant
        payment-cancel callback route (tenant_checkout_canceled)
        would previously have gone uncaught — the other 403s
        would still pass while POST
        /checkouts/tenant/payment/cancel silently became a
        404. The callback sits under the same router-level
        Feature.STRIPE gate as the other checkout routes, in
        front of the handler and its billing-service and
        get_tenant_id dependencies, so the same deterministic
        error path applies: with a role carrying no
        permissions and no tenant, the host-scope branch of
        check_feature_access raises
        FeatureNotEnabledException("stripe") before the
        handler runs — so no scope guard runs, no
        tenant-required error is reached, no Stripe service
        is ever reached, no live external call is made, and
        no billing record is canceled (no side effect).
        Unlike the tenant payment-success callback, the
        cancel callback takes no query params and no body
        at all, so no 422 can mask the 403. The shared
        conftest mock cannot be used directly: it is a
        plain UserDto with no role attribute, so the gate
        would fail with an AttributeError 500 instead of
        the deterministic 403. In production that cannot
        happen: get_current_user builds a MeResponseDto
        (role is a required field) and raises
        RoleNotFoundException before any feature check when
        the role row is missing. The original override is
        restored in finally, so no other test's mock is
        affected. That 403 must still carry the
        error-response headers: a cached 403 could
        otherwise be served to a different user after an
        account switch on a shared machine, and a
        payment-cancel callback marks scope-dependent
        financial records canceled, which the handler
        itself treats as a tenant-scope write.
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
            "/checkouts/tenant/payment/cancel",
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

    # Same security-headers lock as the checkout GET, host
    # POST, tenant POST, and host and tenant payment-callback
    # tests: the pure-ASGI middleware stamps every HTTP
    # response with no path exclusions, so the tenant
    # payment-cancel 403 must carry the same headers as the
    # authenticated GETs, including the exception-handler
    # responses.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened:
    # lock the twelve most sensitive directives as disabled,
    # mirroring the checkout GET lock, using substring checks
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

@pytest.mark.asyncio
async def test_create_tenant_checkout_session_outside_tenant_scope_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        The checkout tenant-create scope-guard error path:
    """
    # The POST /checkouts/tenant/subscription create scope-guard
    # branch, not yet locked: function-name grep count 0 for
    # create_tenant_checkout_session_outside_tenant_scope
    # (verified fresh this run), and no test in this file asserts
    # a 403 with an "outside your tenant's scope" message - the
    # locks cover only the feature-disabled 403s (GET /all, host
    # POST, tenant POST, host/tenant payment-success, host/tenant
    # payment-cancel). Deleting _assert_create_scope
    # (checkout_endpoint.py:40-54) would previously have gone
    # uncaught, and a tenant caller creating a session on the
    # wrong DB would then have the customer and session created
    # in the WRONG Stripe account (the tenant Stripe resolver
    # reads the singleton settings record in the current DB with
    # no tenant filter) and the billing record saved in the host
    # DB, hiding the session from the caller's own tenant
    # account. The guard runs first in the handler body
    # (:137-141), before the tenant/email mismatch checks and
    # before any service call, so no Stripe call is made and no
    # billing record is created. It cannot be reached the way
    # the roles/users/audit-logs locks reach their guards
    # (tenant-scoped caller, no X-Tenant-ID header): the
    # checkout router is feature-gated, and check_feature_access
    # looks the tenant up by request.state.tenant_id before the
    # handler runs, so with no header the lookup gets None,
    # BaseRepository.get returns None, and get_tenant_by_id
    # raises TenantNotFoundException - a 404 from the gate,
    # never the scope 403. The lock therefore uses the
    # mismatched scope the guard is written for, mirroring the
    # billing create scope lock: the caller is tenant-scoped
    # to 68c302ef6bf7a039b7e9b387 while the request carries
    # X-Tenant-ID 68c302ef6bf7a039b7e9b388, a seeded tenant
    # with the STRIPE feature enabled, so the feature gate
    # passes (Tenant stays bound to the host DB - init_db
    # excludes it from the tenant-DB models, mongodb.py:53-56
    # - so the lookup finds the seeded row) and the guard
    # raises ForbiddenException before any Stripe call. The
    # caller override mirrors the audit-logs/billing locks'
    # pattern (per-test MeResponseDto, restored in finally).
    # Unlike the billing create route, the tenant checkout
    # create route carries no permission dependency, so the
    # role needs no permission here - an empty permission list
    # is deliberate, not an omission. The body is the same
    # valid body the feature-disabled tenant POST lock uses
    # (a non-empty price_id, a valid email, mode
    # "subscription", tenant_id omitted/None), so no 422 can
    # mask the 403. The central ApiBaseException handler maps
    # ForbiddenException to 403 (api/__init__.py:98-103) with
    # {"error": ..., "code": 403} and the no-store/Pragma error
    # headers. A future change that drops the guard would break
    # this lock while leaving the feature-disabled tenant POST
    # 403 lock green, so the two paths are locked separately.
    from beanie import PydanticObjectId

    from api.domain.entities.tenant import Feature, Tenant
    from api.domain.enum.feature import Feature as FeatureEnum

    await Tenant(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b388"),
        name="checkout-scope-tenant",
        subdomain="checkout-scope.fsrapp.com",
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
                name="Tenant checkout caller",
                description="Role for the tenant-scoped checkout create caller",
                created_at="2024-10-01T00:00:00Z",
                updated_at="2024-10-01T00:00:00Z",
                permissions=[],
            ),
            subscription=None,
        )

    original_override = app.dependency_overrides.get(get_current_user)
    app.dependency_overrides[get_current_user] = override_get_current_user_tenant_scoped
    try:
        response = await client.post(
            "/checkouts/tenant/subscription",
            json={
                "price_id": "price_test",
                "email": "admin@example.com",
                "mode": "subscription",
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
    # handler sets no-store only on the success path, so on this
    # path they come from the central ApiBaseException handler,
    # and a cached 403 could otherwise be served to a different
    # user after an account switch on a shared machine.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the checkout feature-disabled
    # tests: the pure-ASGI middleware stamps every HTTP response
    # with no path exclusions, so the checkout 403 must carry the
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
    # mirroring the checkout GET lock, using substring checks
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
    # Postconditions: the guard fires before any Stripe call,
    # so no checkout session or billing record was created,
    # and the seeded tenant is still there with the STRIPE
    # feature enabled (there is no DB record a session write
    # would leave behind in the test DB - sessions are Stripe
    # objects and the billing record is only written after the
    # Stripe call - so the tenant row is the observable
    # postcondition).
    stored = await Tenant.find_one(
        Tenant.id == PydanticObjectId("68c302ef6bf7a039b7e9b388")
    )
    assert stored is not None
    assert stored.features == [Feature(name=FeatureEnum.STRIPE, enabled=True)]

@pytest.mark.asyncio
async def test_list_checkout_records_outside_tenant_scope_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        The checkout record-list scope-guard error path:
    """
    # The GET /checkouts/all list scope-guard branch, not yet locked:
    # function-name grep count 0 for
    # list_checkout_records_outside_tenant_scope (verified fresh
    # this run), and no test in this file asserts a 403 with an
    # "outside your tenant's scope" message - the locks cover
    # only the feature-disabled 403s (GET /all, host POST, tenant
    # POST, host/tenant payment-success, host/tenant
    # payment-cancel) and the create-scope 403. Deleting
    # _assert_list_scope (checkout_endpoint.py:57-73) would
    # previously have gone uncaught, and a tenant caller listing
    # on the host DB would then read tenant-stamped checkout
    # records sitting in the host DB (e.g. planted before the
    # create guard) - financial records, not just names - even
    # though the service scopes the list to the caller's tenant
    # stamp, because it never checks which database served the
    # request. The guard runs first in the handler body, before
    # any billing-service call, so no read happens. It cannot be
    # reached the way the roles list lock reaches its guard
    # (tenant-scoped caller, no X-Tenant-ID header): the
    # checkout router is feature-gated, and check_feature_access
    # looks the tenant up by request.state.tenant_id before the
    # handler runs, so with no header the lookup gets None,
    # BaseRepository.get returns None, and get_tenant_by_id
    # raises TenantNotFoundException - a 404 from the gate,
    # never the scope 403. The lock therefore uses the
    # mismatched scope the guard is written for, mirroring the
    # checkout create scope lock: the caller is tenant-scoped
    # to 68c302ef6bf7a039b7e9b387 while the request carries
    # X-Tenant-ID 68c302ef6bf7a039b7e9b388, a seeded tenant
    # with the STRIPE feature enabled, so the feature gate
    # passes (Tenant stays bound to the host DB - init_db
    # excludes it from the tenant-DB models, mongodb.py:53-56
    # - so the lookup finds the seeded row) and the guard
    # raises ForbiddenException before any read. Unlike the
    # create route, the list route carries a MANAGE_BILLING
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
    # override mirrors the audit-logs/billing locks' pattern
    # (per-test MeResponseDto, restored in finally). The
    # default skip/limit query values pass validation, so no
    # 422 can mask the 403. The central ApiBaseException
    # handler maps ForbiddenException to 403
    # (api/__init__.py:98-103) with {"error": ..., "code":
    # 403} and the no-store/Pragma error headers. A future
    # change that drops the guard would break this lock while
    # leaving the feature-disabled GET 403 lock and the
    # create-scope 403 lock green, so the three paths are
    # locked separately.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.entities.tenant import Feature, Tenant
    from api.domain.enum.feature import Feature as FeatureEnum
    from api.domain.enum.permission import Permission

    await Tenant(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b388"),
        name="checkout-scope-tenant",
        subdomain="checkout-scope.fsrapp.com",
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
            "/checkouts/all",
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

    # Same security-headers lock as the checkout feature-disabled
    # tests: the pure-ASGI middleware stamps every HTTP response
    # with no path exclusions, so the checkout 403 must carry the
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
    # mirroring the checkout GET lock, using substring checks
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


@pytest.mark.asyncio
async def test_tenant_checkout_success_outside_tenant_scope_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        The checkout tenant payment-success scope-guard error path:
    """
    # The POST /checkouts/tenant/payment/success create scope-guard
    # branch, not yet locked: function-name grep count 0 for
    # tenant_checkout_success_outside_tenant_scope (verified fresh
    # this run), and no test in this file asserts a 403 with an
    # "outside your tenant's scope" message for this route - the
    # locks cover only the feature-disabled 403s (GET /all, host
    # POST, tenant POST, host/tenant payment-success, host/tenant
    # payment-cancel) and the create/list scope 403s. Deleting
    # _assert_create_scope (checkout_endpoint.py:40-54) from the
    # success handler would previously have gone uncaught, and a
    # tenant caller confirming a session on the wrong DB would then
    # have the session retrieved through the WRONG tenant's Stripe
    # account (the tenant Stripe resolver reads the singleton
    # settings record in the current DB with no tenant filter) and
    # the billing record finalised in the host DB. The guard runs
    # first in the handler body (:239), before the tenant-required
    # check and before any billing-service call, so no Stripe call
    # is made and no record is finalised. It cannot be reached the
    # way the roles/users/audit-logs locks reach their guards
    # (tenant-scoped caller, no X-Tenant-ID header): the checkout
    # router is feature-gated, and check_feature_access looks the
    # tenant up by request.state.tenant_id before the handler runs,
    # so with no header the lookup gets None, BaseRepository.get
    # returns None, and get_tenant_by_id raises
    # TenantNotFoundException - a 404 from the gate, never the
    # scope 403. The lock therefore uses the mismatched scope the
    # guard is written for, mirroring the checkout create scope
    # lock: the caller is tenant-scoped to
    # 68c302ef6bf7a039b7e9b387 while the request carries X-Tenant-ID
    # 68c302ef6bf7a039b7e9b388, a seeded tenant with the STRIPE
    # feature enabled, so the feature gate passes (Tenant stays
    # bound to the host DB - init_db excludes it from the
    # tenant-DB models, mongodb.py:53-56 - so the lookup finds
    # the seeded row) and the guard raises ForbiddenException
    # before any Stripe call. The caller override mirrors the
    # create scope lock's pattern (per-test MeResponseDto,
    # restored in finally). Unlike the checkout list route, this
    # route carries no permission dependency, so the role needs
    # no permission here - an empty permission list is deliberate,
    # not an omission. The required session_id query param is
    # supplied (the same value the feature-disabled tenant
    # success lock uses), so no 422 can mask the 403. The handler
    # takes no Response param, so the no-store/Pragma headers on
    # the 403 come from the central ApiBaseException handler, which
    # maps ForbiddenException to 403 (api/__init__.py:98-103) with
    # {"error": ..., "code": 403}. A future change that drops the
    # guard would break this lock while leaving the
    # feature-disabled tenant success 403 lock and the create/list
    # scope 403 locks green, so the paths are locked separately.
    from beanie import PydanticObjectId

    from api.domain.entities.tenant import Feature, Tenant
    from api.domain.enum.feature import Feature as FeatureEnum

    await Tenant(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b388"),
        name="checkout-scope-tenant",
        subdomain="checkout-scope.fsrapp.com",
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
                name="Tenant checkout caller",
                description="Role for the tenant-scoped checkout success caller",
                created_at="2024-10-01T00:00:00Z",
                updated_at="2024-10-01T00:00:00Z",
                permissions=[],
            ),
            subscription=None,
        )

    original_override = app.dependency_overrides.get(get_current_user)
    app.dependency_overrides[get_current_user] = override_get_current_user_tenant_scoped
    try:
        response = await client.post(
            "/checkouts/tenant/payment/success",
            params={
                "session_id": "cs_test_session",
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
    # handler sets no-store only on the success path of the sibling
    # record-list route, so on this path they come from the central
    # ApiBaseException handler, and a cached 403 could otherwise be
    # served to a different user after an account switch on a shared
    # machine.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the checkout feature-disabled
    # tests: the pure-ASGI middleware stamps every HTTP response
    # with no path exclusions, so the checkout 403 must carry the
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
    # mirroring the checkout GET lock, using substring checks
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
    # Postconditions: the guard fires before any Stripe call, so
    # no session is retrieved and no billing record is finalised,
    # and the seeded tenant is still there with the STRIPE feature
    # enabled (there is no DB record a success write would leave
    # behind in the test DB - sessions are Stripe objects and the
    # billing record is only finalised after the Stripe call - so
    # the tenant row is the observable postcondition).
    stored = await Tenant.find_one(
        Tenant.id == PydanticObjectId("68c302ef6bf7a039b7e9b388")
    )
    assert stored is not None
    assert stored.features == [Feature(name=FeatureEnum.STRIPE, enabled=True)]


@pytest.mark.asyncio
async def test_tenant_checkout_cancel_outside_tenant_scope_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        The checkout tenant payment-cancel scope-guard error path:
    """
    # The POST /checkouts/tenant/payment/cancel create scope-guard
    # branch, not yet locked: function-name grep count 0 for
    # tenant_checkout_cancel_outside_tenant_scope (verified fresh
    # this run), and no test in this file asserts a 403 with an
    # "outside your tenant's scope" message for this route - the
    # locks cover only the feature-disabled 403s (GET /all, host
    # POST, tenant POST, host/tenant payment-success, host/tenant
    # payment-cancel) and the create/list/success scope 403s.
    # Deleting _assert_create_scope (checkout_endpoint.py:34-54)
    # from the cancel handler would previously have gone
    # uncaught, and a tenant caller confirming a cancel on the
    # wrong DB would then have the caller's pending tenant-scope
    # billing records marked canceled in the host DB instead of
    # the caller's own tenant DB. The guard runs first in the
    # handler body (:268), before the tenant-required check and
    # before any billing-service call, so no record is touched.
    # It cannot be reached the way the roles/users/audit-logs
    # locks reach their guards (tenant-scoped caller, no
    # X-Tenant-ID header): the checkout router is feature-gated,
    # and check_feature_access looks the tenant up by
    # request.state.tenant_id before the handler runs, so with
    # no header the lookup gets None, BaseRepository.get returns
    # None, and get_tenant_by_id raises TenantNotFoundException
    # - a 404 from the gate, never the scope 403. The lock
    # therefore uses the mismatched scope the guard is written
    # for, mirroring the checkout create/success scope locks:
    # the caller is tenant-scoped to
    # 68c302ef6bf7a039b7e9b387 while the request carries
    # X-Tenant-ID 68c302ef6bf7a039b7e9b388, a seeded tenant with
    # the STRIPE feature enabled, so the feature gate passes
    # (Tenant stays bound to the host DB - init_db excludes it
    # from the tenant-DB models, mongodb.py:53-56 - so the
    # lookup finds the seeded row) and the guard raises
    # ForbiddenException before any service call. The caller
    # override mirrors the success scope lock's pattern
    # (per-test MeResponseDto, restored in finally). Unlike
    # the checkout list route, this route carries no permission
    # dependency, so the role needs no permission here - an
    # empty permission list is deliberate, not an omission.
    # Unlike the payment-success callback, the cancel callback
    # takes no query params and no body at all, so no 422 can
    # mask the 403. The handler takes no Response param, so the
    # no-store/Pragma headers on the 403 come from the central
    # ApiBaseException handler, which maps ForbiddenException to
    # 403 (api/__init__.py:98-103) with {"error": ..., "code":
    # 403}. A future change that drops the guard would break
    # this lock while leaving the feature-disabled tenant
    # cancel 403 lock and the create/list/success scope 403
    # locks green, so the paths are locked separately.
    from beanie import PydanticObjectId

    from api.domain.entities.tenant import Feature, Tenant
    from api.domain.enum.feature import Feature as FeatureEnum

    await Tenant(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b388"),
        name="checkout-scope-tenant",
        subdomain="checkout-scope.fsrapp.com",
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
                name="Tenant checkout caller",
                description="Role for the tenant-scoped checkout cancel caller",
                created_at="2024-10-01T00:00:00Z",
                updated_at="2024-10-01T00:00:00Z",
                permissions=[],
            ),
            subscription=None,
        )

    original_override = app.dependency_overrides.get(get_current_user)
    app.dependency_overrides[get_current_user] = override_get_current_user_tenant_scoped
    try:
        response = await client.post(
            "/checkouts/tenant/payment/cancel",
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
    # handler sets no-store only on the success path of the sibling
    # record-list route, so on this path they come from the central
    # ApiBaseException handler, and a cached 403 could otherwise be
    # served to a different user after an account switch on a shared
    # machine.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the checkout feature-disabled
    # tests: the pure-ASGI middleware stamps every HTTP response
    # with no path exclusions, so the checkout 403 must carry the
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
    # mirroring the checkout GET lock, using substring checks
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
    # Postconditions: the guard fires before any service call, so
    # no billing record is marked canceled, and the seeded tenant
    # is still there with the STRIPE feature enabled. A pending
    # billing record would be the decisive postcondition - without
    # the guard, handle_tenant_checkout_canceled
    # (billing_record_service.py:611-642) searches the caller's
    # pending tenant-scope records and flips the matching ones
    # to "canceled" - but BillingRecord is not among the conftest
    # test-DB models (conftest.py:24), so no such record can be
    # seeded in the test DB; the tenant row is the observable
    # postcondition, as in the success scope lock. The 403
    # assertion itself is the lock: dropping the guard changes
    # the outcome to a 202 or a service error, never a 403.
    stored = await Tenant.find_one(
        Tenant.id == PydanticObjectId("68c302ef6bf7a039b7e9b388")
    )
    assert stored is not None
    assert stored.features == [Feature(name=FeatureEnum.STRIPE, enabled=True)]
