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
