import pytest
from httpx import AsyncClient

from api import app
from api.common.enums.gender import Gender
from api.domain.dtos.auth_dto import MeResponseDto
from api.domain.dtos.role_dto import RoleDto
from api.infrastructure.security.current_user import get_current_user


@pytest.mark.asyncio
async def test_get_products_with_feature_disabled_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        The products area had no interface test file at all, so
    deleting the products router from api/__init__.py — or dropping
    the central ApiBaseException no-store lines or the
    security-headers middleware registration — would previously
    have gone uncaught here even though every other interface
    area locks its headers in. The products router is feature-gated
    at the router level (Feature.STRIPE), in front of every
    handler, so the success path is not asserted here: it
    needs a Stripe account with products plus the
    MANAGE_PRODUCTS_AND_PRICING permission, neither of which
    the shared conftest client provides. The error path below
    is deterministic instead, and it reuses the per-test
    MeResponseDto override pattern from the AI/prices tests: the
    products router also carries a permission dependency
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
    after an account switch on a shared machine, and the product
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
        response = await client.get("/products/")
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

    # Same security-headers lock as the prices test: the
    # pure-ASGI middleware stamps every HTTP response with no
    # path exclusions, so the products 403 must carry the same headers
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
    # the prices lock, using substring checks so later additions
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
async def test_get_product_by_id_with_feature_disabled_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        Second-path lock for the products area: the list test locks
    GET /products/ only, so deleting just the detail route
    (get_product_by_id) would previously have gone uncaught —
    the list 403 would still pass while GET /products/<id>
    silently became a 404. The detail route sits under the same
    router-level Feature.STRIPE gate as the list, in front of
    every handler, so the same deterministic error path applies:
    with a role carrying no permissions and no tenant, the
    host-scope branch of check_feature_access raises
    FeatureNotEnabledException("stripe") before the permission
    check or the handler runs — so no Stripe service is ever
    reached and no live external call is made. The path param is
    a plain string ({product_id:path}), so no path validation can
    mask the gate error, and no body is needed. The shared
    conftest mock cannot be used directly: it is a plain UserDto
    with no role attribute, so the gate would fail with an
    AttributeError 500 instead of the deterministic 403. In
    production that cannot happen: get_current_user builds a
    MeResponseDto (role is a required field) and raises
    RoleNotFoundException before any feature check when the role
    row is missing. The original override is restored in finally,
    so no other test's mock is affected. That 403 must still
    carry the error-response headers: a cached 403 could
    otherwise be served to a different user after an account
    switch on a shared machine, and a single product record is
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
        response = await client.get("/products/prod_test123")
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

    # Same security-headers lock as the products list test: the
    # pure-ASGI middleware stamps every HTTP response with no
    # path exclusions, so the detail 403 must carry the same headers
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
async def test_post_products_with_feature_disabled_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        Third-path lock for the products area: the list and detail
    tests lock GET /products/ and GET /products/<id> only, so
    deleting just the create route (create_product) would
    previously have gone uncaught — the GET 403s would still
    pass while POST /products/ silently became a 404. The create
    route sits under the same router-level Feature.STRIPE gate
    as the GETs, in front of the MANAGE_PRODUCTS_AND_PRICING
    permission dependency and the handler, so the same
    deterministic error path applies: with a role carrying no
    permissions and no tenant, the host-scope branch of
    check_feature_access raises
    FeatureNotEnabledException("stripe") before the permission
    check or the handler runs — so no Stripe service is ever
    reached, no live external call is made, and no product is
    created (no side effect). The body is valid on purpose, not
    {}: CreateProductDto requires name and description
    (min_length=1, non-blank after strip, via the model
    validator), while tax_code is optional and active defaults
    to True — an invalid body would fail validation with 422
    and could mask the 403 depending on validation-vs-
    dependency ordering; a valid body makes the gate error
    deterministic either way. The shared conftest mock cannot
    be used directly: it is a plain UserDto with no role
    attribute, so the gate would fail with an AttributeError
    500 instead of the deterministic 403. In production that
    cannot happen: get_current_user builds a MeResponseDto
    (role is a required field) and raises RoleNotFoundException
    before any feature check when the role row is missing. The
    original override is restored in finally, so no other
    test's mock is affected. That 403 must still carry the
    error-response headers: a cached 403 could otherwise be
    served to a different user after an account switch on a
    shared machine, and product creation is account-visible
    catalog configuration.
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
            "/products/",
            json={"name": "Test Product", "description": "A test product"},
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

    # Same security-headers lock as the products GET tests: the
    # pure-ASGI middleware stamps every HTTP response with no
    # path exclusions, so the products POST 403 must carry the
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
    # the GET locks, using substring checks so later additions
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
async def test_patch_product_with_feature_disabled_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        Fourth-path lock for the products area: the list, detail
    and create tests lock GET /products/, GET /products/<id>
    and POST /products/ only, so deleting just the update route
    (update_product) would previously have gone uncaught — the
    other 403s would still pass while PATCH /products/<id>
    silently became a 404. The update route sits under the same
    router-level Feature.STRIPE gate as the GETs and POST, in
    front of the MANAGE_PRODUCTS_AND_PRICING permission
    dependency and the handler, so the same deterministic error
    path applies: with a role carrying no permissions and no
    tenant, the host-scope branch of check_feature_access raises
    FeatureNotEnabledException("stripe") before the permission
    check, the create-scope guard, or the handler runs — so no
    Stripe service is ever reached, no live external call is
    made, and no product is updated (no side effect). The body
    is valid on purpose, not {}: PATCH reuses CreateProductDto,
    which requires name and description (min_length=1,
    non-blank after strip, via the model validator), while
    tax_code is optional and active defaults to True — an
    invalid body would fail validation with 422 and could mask
    the 403 depending on validation-vs-dependency ordering; a
    valid body makes the gate error deterministic either way.
    The :path product_id param is a plain string and cannot
    mask the error. The shared conftest mock cannot be used
    directly: it is a plain UserDto with no role attribute, so
    the gate would fail with an AttributeError 500 instead of
    the deterministic 403. In production that cannot happen:
    get_current_user builds a MeResponseDto (role is a required
    field) and raises RoleNotFoundException before any feature
    check when the role row is missing. The original override
    is restored in finally, so no other test's mock is
    affected. That 403 must still carry the error-response
    headers: a cached 403 could otherwise be served to a
    different user after an account switch on a shared machine,
    and product updates are account-visible catalog
    configuration.
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
            "/products/prod_test123",
            json={"name": "Test Product", "description": "A test product"},
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

    # Same security-headers lock as the products GET/POST tests:
    # the pure-ASGI middleware stamps every HTTP response with no
    # path exclusions, so the products PATCH 403 must carry the
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
    # the GET/POST locks, using substring checks so later additions
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
async def test_delete_product_with_feature_disabled_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        Fifth-path lock for the products area: the list, detail,
    create and update tests lock GET /products/,
    GET /products/<id>, POST /products/ and PATCH /products/<id>
    only, so deleting just the delete route (delete_product)
    would previously have gone uncaught — the other 403s would
    still pass while DELETE /products/<id> silently became a
    404. The delete route sits under the same router-level
    Feature.STRIPE gate as the GETs, POST and PATCH, in front
    of the MANAGE_PRODUCTS_AND_PRICING permission dependency
    and the handler, so the same deterministic error path
    applies: with a role carrying no permissions and no tenant,
    the host-scope branch of check_feature_access raises
    FeatureNotEnabledException("stripe") before the permission
    check, the create-scope guard, or the handler runs — so no
    Stripe service is ever reached, no live external call is
    made, and no product is deleted (no side effect). DELETE
    takes no body, so unlike PATCH there is no validation that
    could mask the 403; the :path product_id param is a plain
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
    account switch on a shared machine, and product deletions
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
        response = await client.delete("/products/prod_test123")
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

    # Same security-headers lock as the products GET/POST/PATCH
    # tests: the pure-ASGI middleware stamps every HTTP response
    # with no path exclusions, so the products DELETE 403 must
    # carry the same headers as the authenticated GETs,
    # including the exception-handler responses.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the twelve most sensitive directives as disabled, mirroring
    # the GET/POST/PATCH locks, using substring checks so later
    # additions to the list do not break this test. The full value
    # lives in _SECURITY_HEADERS. Each directive is safe to lock
    # here for the same reasons as on the other routes: the SPA
    # has no camera, microphone, geolocation, payment,
    # clipboard-read, display-capture, fullscreen, motion-sensor,
    # compass, XR, or idle-detection flow (verified by grep in
    # the earlier sweeps and re-verified fresh this run: zero
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
async def test_post_products_outside_tenant_scope_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        The products POST create scope-guard error path: the five
        feature-disabled 403 locks cover the gate, but no test
        asserted a 403 on POST /products/ via the create scope
        guard - function-name grep count 0 for
        post_products_outside_tenant_scope, verified fresh this
        run. Deleting _assert_create_scope
        (product_endpoint.py:16-35) would previously have gone
        uncaught, and a tenant caller creating on the host DB
        would then create a product in the HOST Stripe account
        (the guard's own comment: the tenant Stripe resolver
        reads the singleton settings record in the current DB
        with no tenant filter) - polluting the host catalog and
        hiding the object from the caller's own tenant Stripe
        account. The guard runs first in the handler body,
        before any product-service call, so no product is
        created. It cannot be reached the way the notification
        banner locks reach their guard (tenant-scoped caller,
        no X-Tenant-ID header): the products router is
        feature-gated, and check_feature_access looks the
        tenant up by request.state.tenant_id before the handler
        runs, so with no header the lookup gets None,
        BaseRepository.get returns None, and get_tenant_by_id
        raises TenantNotFoundException - a 404 from the gate,
        never the scope 403. The lock therefore uses the
        mismatched scope the guard is written for, mirroring
        the POST prices scope lock: the caller is tenant-scoped
        to 68c302ef6bf7a039b7e9b387 while the request carries
        X-Tenant-ID 68c302ef6bf7a039b7e9b388, a seeded tenant
        with the STRIPE feature enabled, so the feature gate
        passes (Tenant stays bound to the host DB - init_db
        excludes it from the tenant-DB models, mongodb.py:53-56
        - so the lookup finds the seeded row) and the guard
        raises ForbiddenException before any create. Like the
        prices POST route, the products POST route carries a
        MANAGE_PRODUCTS_AND_PRICING permission dependency,
        which runs before the handler body, so the seeded role
        (id 68c302ef6bf7a039b7e9b386) must carry
        MANAGE_PRODUCTS_AND_PRICING: get_role_detail calls
        get_role_by_id with no tenant argument
        (user_access_management.py), so _caller_may_access
        sees a None caller tenant and returns True
        (role_service.py:18-19), and the seeded row is
        visible regardless of the caller's tenant scope -
        the same mechanism the prices scope lock relies on.
        The override's RoleDto carries the same permission,
        and the caller override mirrors the prices lock's
        pattern (per-test MeResponseDto, restored in finally).
        The body is valid on purpose, not {}:
        CreateProductDto requires name and description
        (min_length=1, non-blank after strip, via the model
        validator), while tax_code is optional and active
        defaults to True - an invalid body would fail
        validation with 422 and could mask the 403 depending
        on validation-vs-dependency ordering; a valid body
        makes the guard error deterministic either way. The
        central ApiBaseException handler maps
        ForbiddenException to 403 (api/__init__.py:98-103)
        with {"error": ..., "code": 403} and the no-store/Pragma
        error headers. A future change that drops the guard
        would break this lock while leaving the GET scope lock
        (still to add) and the feature-disabled POST 403 lock
        green, so the paths are locked separately.
    """
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.entities.tenant import Feature, Tenant
    from api.domain.enum.feature import Feature as FeatureEnum
    from api.domain.enum.permission import Permission

    await Tenant(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b388"),
        name="products-scope-tenant",
        subdomain="products-scope.fsrapp.com",
        features=[Feature(name=FeatureEnum.STRIPE, enabled=True)],
    ).insert()
    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Tenant product manager",
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
                name="Tenant product manager",
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
            "/products/",
            headers={"X-Tenant-ID": "68c302ef6bf7a039b7e9b388"},
            json={"name": "Test Product", "description": "A test product"},
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

    # Same security-headers lock as the products feature-disabled
    # tests: the pure-ASGI middleware stamps every HTTP response
    # with no path exclusions, so the products POST 403 must carry
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
    # mirroring the products GET lock, using substring checks
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
    # Postconditions: the guard fires before any product-service
    # call, so the create is side-effect free - the seeded role
    # is still there with MANAGE_PRODUCTS_AND_PRICING and the
    # seeded tenant is still there with the STRIPE feature
    # enabled. Products are Stripe objects, not DB rows, so the
    # tenant row is the observable postcondition.
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


async def test_get_products_outside_tenant_scope_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        The products GET list read scope-guard error path: the five
        feature-disabled 403 locks and the POST create-scope 403 lock
        cover the gate and the write guard, but no test asserted a
        403 on GET /products/ via the read scope guard - function-name
        grep count 0 for get_products_outside_tenant_scope, verified
        fresh this run. Deleting _assert_read_scope
        (product_endpoint.py:37-66) would previously have gone
        uncaught, and a tenant caller listing on the host DB would
        then be served the HOST Stripe account's products (the
        guard's own comment: the tenant Stripe resolver reads the
        singleton settings record in the current DB with no tenant
        filter) - a catalog leak to a tenant admin, not just a wrong
        catalog. The guard runs first in the handler body, before
        any product-service call, so no catalog is served. It cannot
        be reached the way the notification banner locks reach their
        guard (tenant-scoped caller, no X-Tenant-ID header): the
        products router is feature-gated, and check_feature_access
        looks the tenant up by request.state.tenant_id before the
        handler runs, so with no header the lookup gets None,
        BaseRepository.get returns None, and get_tenant_by_id raises
        TenantNotFoundException - a 404 from the gate, never the
        scope 403. The lock therefore uses the mismatched scope the
        guard is written for, mirroring the POST products scope
        lock: the caller is tenant-scoped to
        68c302ef6bf7a039b7e9b387 while the request carries
        X-Tenant-ID 68c302ef6bf7a039b7e9b388, a seeded tenant with
        the STRIPE feature enabled, so the feature gate passes
        (Tenant stays bound to the host DB - init_db excludes it
        from the tenant-DB models, mongodb.py:53-56 - so the lookup
        finds the seeded row) and the guard raises
        ForbiddenException before any list. Like the POST route, the
        products GET list route carries a
        MANAGE_PRODUCTS_AND_PRICING permission dependency, which
        runs before the handler body, so the seeded role (id
        68c302ef6bf7a039b7e9b386) must carry
        MANAGE_PRODUCTS_AND_PRICING: get_role_detail calls
        get_role_by_id with no tenant argument
        (user_access_management.py), so _caller_may_access sees a
        None caller tenant and returns True (role_service.py:18-19),
        and the seeded row is visible regardless of the caller's
        tenant scope - the same mechanism the POST scope lock
        relies on. The override's RoleDto carries the same
        permission, and the caller override mirrors the POST lock's
        pattern (per-test MeResponseDto, restored in finally). The
        GET takes no body and its only query param, active, defaults
        to True, so no 422 can mask the 403. The central
        ApiBaseException handler maps ForbiddenException to 403
        (api/__init__.py:98-103) with {"error": ..., "code": 403}
        and the no-store/Pragma error headers. A future change that
        drops the guard would break this lock while leaving the
        feature-disabled GET /products/ 403 lock and the POST scope
        403 lock green, so the paths are locked separately.
    """
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.entities.tenant import Feature, Tenant
    from api.domain.enum.feature import Feature as FeatureEnum
    from api.domain.enum.permission import Permission

    await Tenant(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b388"),
        name="products-scope-tenant",
        subdomain="products-scope.fsrapp.com",
        features=[Feature(name=FeatureEnum.STRIPE, enabled=True)],
    ).insert()
    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Tenant product manager",
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
                name="Tenant product manager",
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
            "/products/",
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

    # Same security-headers lock as the products feature-disabled
    # tests: the pure-ASGI middleware stamps every HTTP response
    # with no path exclusions, so the products GET 403 must carry
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
    # mirroring the products POST scope lock, using substring
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
    # Postconditions: the guard fires before any product-service
    # call, so the list is side-effect free - the seeded role is
    # still there with MANAGE_PRODUCTS_AND_PRICING and the seeded
    # tenant is still there with the STRIPE feature enabled.
    # Products are Stripe objects, not DB rows, so the tenant row
    # is the observable postcondition.
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


async def test_get_product_by_id_outside_tenant_scope_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        The products GET detail read scope-guard error path: the
        feature-disabled 403 locks and the GET /products/ read-scope
        403 lock cover the gate and the list guard, but no test
        asserted a 403 on GET /products/{id} via the read scope
        guard - function-name grep count 0 for
        get_product_by_id_outside_tenant_scope, verified fresh this
        run. Deleting _assert_read_scope
        (product_endpoint.py:38-66) would previously have gone
        uncaught on the detail route, and a tenant caller fetching
        a product id on the host DB would then be served the HOST
        Stripe account's product (the guard's own comment: the
        tenant Stripe resolver reads the singleton settings record
        in the current DB with no tenant filter) - a catalog leak
        to a tenant admin, not just a wrong catalog. The guard
        runs first in the handler body, before any
        product-service call, so no catalog is served. It cannot
        be reached the way the notification banner locks reach
        their guard (tenant-scoped caller, no X-Tenant-ID header):
        the products router is feature-gated, and
        check_feature_access looks the tenant up by
        request.state.tenant_id before the handler runs, so with
        no header the lookup gets None, BaseRepository.get
        returns None, and get_tenant_by_id raises
        TenantNotFoundException - a 404 from the gate, never the
        scope 403. The lock therefore uses the mismatched scope
        the guard is written for, mirroring the GET /products/
        scope lock: the caller is tenant-scoped to
        68c302ef6bf7a039b7e9b387 while the request carries
        X-Tenant-ID 68c302ef6bf7a039b7e9b388, a seeded tenant with
        the STRIPE feature enabled, so the feature gate passes
        (Tenant stays bound to the host DB - init_db excludes it
        from the tenant-DB models, mongodb.py:53-56 - so the
        lookup finds the seeded row) and the guard raises
        ForbiddenException before any detail fetch. Like the list
        route, the products GET detail route carries a
        MANAGE_PRODUCTS_AND_PRICING permission dependency, which
        runs before the handler body, so the seeded role (id
        68c302ef6bf7a039b7e9b386) must carry
        MANAGE_PRODUCTS_AND_PRICING: get_role_detail calls
        get_role_by_id with no tenant argument
        (user_access_management.py), so _caller_may_access sees a
        None caller tenant and returns True (role_service.py:18-19),
        and the seeded row is visible regardless of the caller's
        tenant scope - the same mechanism the list scope lock
        relies on. The override's RoleDto carries the same
        permission, and the caller override mirrors the list
        lock's pattern (per-test MeResponseDto, restored in
        finally). The GET takes no body, its only path param is a
        plain string ({product_id:path}, "prod_test123" as in the
        feature-disabled detail lock), so no 422 can mask the
        403. The central ApiBaseException handler maps
        ForbiddenException to 403 (api/__init__.py:98-103) with
        {"error": ..., "code": 403} and the no-store/Pragma error
        headers. A future change that drops the guard would break
        this lock while leaving the feature-disabled GET
        /products/{id} 403 lock and the GET /products/ scope 403
        lock green, so the paths are locked separately.
    """
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.entities.tenant import Feature, Tenant
    from api.domain.enum.feature import Feature as FeatureEnum
    from api.domain.enum.permission import Permission

    await Tenant(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b388"),
        name="products-scope-tenant",
        subdomain="products-scope.fsrapp.com",
        features=[Feature(name=FeatureEnum.STRIPE, enabled=True)],
    ).insert()
    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Tenant product manager",
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
                name="Tenant product manager",
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
            "/products/prod_test123",
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

    # Same security-headers lock as the products feature-disabled
    # tests: the pure-ASGI middleware stamps every HTTP response
    # with no path exclusions, so the products GET detail 403 must
    # carry the same headers as the authenticated GETs, including
    # the exception-handler responses.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened:
    # lock the twelve most sensitive directives as disabled,
    # mirroring the products list scope lock, using substring
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
    # Postconditions: the guard fires before any product-service
    # call, so the detail fetch is side-effect free - the seeded
    # role is still there with MANAGE_PRODUCTS_AND_PRICING and the
    # seeded tenant is still there with the STRIPE feature
    # enabled. Products are Stripe objects, not DB rows, so the
    # tenant row is the observable postcondition.
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
async def test_patch_product_outside_tenant_scope_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        The products PATCH update scope-guard error path: the five
        feature-disabled 403 locks cover the gate, and the POST
        create-scope 403 lock covers the create route, but no test
        asserted a 403 on PATCH /products/{id} via the create scope
        guard - function-name grep count 0 for
        patch_product_outside_tenant_scope, verified fresh this
        run. Deleting _assert_create_scope
        (product_endpoint.py:16-35) would previously have gone
        uncaught on the update route, and a tenant caller updating
        on the host DB would then update a product in the HOST
        Stripe account (the guard's own comment: the tenant Stripe
        resolver reads the singleton settings record in the current
        DB with no tenant filter) - polluting the host catalog and
        hiding the object from the caller's own tenant Stripe
        account. The guard runs first in the handler body,
        before any product-service call, so no product is
        updated. It cannot be reached the way the notification
        banner locks reach their guard (tenant-scoped caller,
        no X-Tenant-ID header): the products router is
        feature-gated, and check_feature_access looks the
        tenant up by request.state.tenant_id before the handler
        runs, so with no header the lookup gets None,
        BaseRepository.get returns None, and get_tenant_by_id
        raises TenantNotFoundException - a 404 from the gate,
        never the scope 403. The lock therefore uses the
        mismatched scope the guard is written for, mirroring
        the POST products scope lock: the caller is tenant-scoped
        to 68c302ef6bf7a039b7e9b387 while the request carries
        X-Tenant-ID 68c302ef6bf7a039b7e9b388, a seeded tenant
        with the STRIPE feature enabled, so the feature gate
        passes (Tenant stays bound to the host DB - init_db
        excludes it from the tenant-DB models, mongodb.py:53-56
        - so the lookup finds the seeded row) and the guard
        raises ForbiddenException before any update. Like the
        POST route, the products PATCH route carries a
        MANAGE_PRODUCTS_AND_PRICING permission dependency,
        which runs before the handler body, so the seeded role
        (id 68c302ef6bf7a039b7e9b386) must carry
        MANAGE_PRODUCTS_AND_PRICING: get_role_detail calls
        get_role_by_id with no tenant argument
        (user_access_management.py), so _caller_may_access
        sees a None caller tenant and returns True
        (role_service.py:18-19), and the seeded row is
        visible regardless of the caller's tenant scope -
        the same mechanism the POST scope lock relies on.
        The override's RoleDto carries the same permission,
        and the caller override mirrors the POST lock's
        pattern (per-test MeResponseDto, restored in finally).
        The body is valid on purpose, not {}: update_product
        reuses CreateProductDto, which requires name and
        description (min_length=1, non-blank after strip, via
        the model validator), while tax_code is optional and
        active defaults to True - an invalid body would fail
        validation with 422 and could mask the 403 depending
        on validation-vs-dependency ordering; a valid body
        makes the guard error deterministic either way. The
        path param is a plain string ({product_id:path},
        "prod_test123" as in the feature-disabled PATCH lock),
        so no 422 can mask the 403 from the path. The central
        ApiBaseException handler maps ForbiddenException to 403
        (api/__init__.py:98-103) with {"error": ..., "code":
        403} and the no-store/Pragma error headers. A future
        change that drops the guard would break this lock
        while leaving the feature-disabled PATCH 403 lock and
        the POST/GET scope 403 locks green, so the paths are
        locked separately.
    """
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.entities.tenant import Feature, Tenant
    from api.domain.enum.feature import Feature as FeatureEnum
    from api.domain.enum.permission import Permission

    await Tenant(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b388"),
        name="products-scope-tenant",
        subdomain="products-scope.fsrapp.com",
        features=[Feature(name=FeatureEnum.STRIPE, enabled=True)],
    ).insert()
    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Tenant product manager",
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
                name="Tenant product manager",
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
            "/products/prod_test123",
            headers={"X-Tenant-ID": "68c302ef6bf7a039b7e9b388"},
            json={"name": "Test Product", "description": "A test product"},
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

    # Same security-headers lock as the products feature-disabled
    # tests: the pure-ASGI middleware stamps every HTTP response
    # with no path exclusions, so the products PATCH 403 must carry
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
    # mirroring the products POST scope lock, using substring
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
    # Postconditions: the guard fires before any product-service
    # call, so the update is side-effect free - the seeded role
    # is still there with MANAGE_PRODUCTS_AND_PRICING and the
    # seeded tenant is still there with the STRIPE feature
    # enabled. Products are Stripe objects, not DB rows, so the
    # tenant row is the observable postcondition.
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
async def test_delete_product_outside_tenant_scope_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        The products DELETE delete scope-guard error path: the five
        feature-disabled 403 locks cover the gate, and the POST,
        GET and PATCH scope 403 locks cover the create, read and
        update routes, but no test asserted a 403 on DELETE
        /products/{id} via the create scope guard - function-name
        grep count 0 for delete_product_outside_tenant_scope,
        verified fresh this run. Deleting _assert_create_scope
        (product_endpoint.py:16-35) would previously have gone
        uncaught on the delete route, and a tenant caller deleting
        on the host DB would then delete a product in the HOST
        Stripe account (the guard's own comment: the tenant Stripe
        resolver reads the singleton settings record in the current
        DB with no tenant filter) - polluting the host catalog and
        hiding the object from the caller's own tenant Stripe
        account. The guard runs first in the handler body,
        before any product-service call, so no product is
        deleted. It cannot be reached the way the notification
        banner locks reach their guard (tenant-scoped caller,
        no X-Tenant-ID header): the products router is
        feature-gated, and check_feature_access looks the
        tenant up by request.state.tenant_id before the handler
        runs, so with no header the lookup gets None,
        BaseRepository.get returns None, and get_tenant_by_id
        raises TenantNotFoundException - a 404 from the gate,
        never the scope 403. The lock therefore uses the
        mismatched scope the guard is written for, mirroring
        the PATCH products scope lock: the caller is tenant-scoped
        to 68c302ef6bf7a039b7e9b387 while the request carries
        X-Tenant-ID 68c302ef6bf7a039b7e9b388, a seeded tenant
        with the STRIPE feature enabled, so the feature gate
        passes (Tenant stays bound to the host DB - init_db
        excludes it from the tenant-DB models, mongodb.py:53-56
        - so the lookup finds the seeded row) and the guard
        raises ForbiddenException before any deletion. Like the
        PATCH route, the products DELETE route carries a
        MANAGE_PRODUCTS_AND_PRICING permission dependency,
        which runs before the handler body, so the seeded role
        (id 68c302ef6bf7a039b7e9b386) must carry
        MANAGE_PRODUCTS_AND_PRICING: get_role_detail calls
        get_role_by_id with no tenant argument
        (user_access_management.py), so _caller_may_access
        sees a None caller tenant and returns True
        (role_service.py:18-19), and the seeded row is
        visible regardless of the caller's tenant scope -
        the same mechanism the PATCH scope lock relies on.
        The override's RoleDto carries the same permission,
        and the caller override mirrors the PATCH lock's
        pattern (per-test MeResponseDto, restored in finally).
        DELETE takes no body, so unlike PATCH there is no
        validation that could mask the 403; the path param is
        a plain string ({product_id:path}, "prod_test123" as
        in the feature-disabled DELETE lock), so no 422 can
        mask the 403 from the path. The central
        ApiBaseException handler maps ForbiddenException to 403
        (api/__init__.py:98-103) with {"error": ..., "code":
        403} and the no-store/Pragma error headers. A future
        change that drops the guard would break this lock
        while leaving the feature-disabled DELETE 403 lock and
        the POST/GET/PATCH scope 403 locks green, so the paths
        are locked separately.
    """
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.entities.tenant import Feature, Tenant
    from api.domain.enum.feature import Feature as FeatureEnum
    from api.domain.enum.permission import Permission

    await Tenant(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b388"),
        name="products-scope-tenant",
        subdomain="products-scope.fsrapp.com",
        features=[Feature(name=FeatureEnum.STRIPE, enabled=True)],
    ).insert()
    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Tenant product manager",
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
                name="Tenant product manager",
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
        response = await client.delete(
            "/products/prod_test123",
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

    # Same security-headers lock as the products feature-disabled
    # tests: the pure-ASGI middleware stamps every HTTP response
    # with no path exclusions, so the products DELETE 403 must carry
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
    # mirroring the products PATCH scope lock, using substring
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
    # Postconditions: the guard fires before any product-service
    # call, so the deletion is side-effect free - the seeded role
    # is still there with MANAGE_PRODUCTS_AND_PRICING and the
    # seeded tenant is still there with the STRIPE feature
    # enabled. Products are Stripe objects, not DB rows, so the
    # tenant row is the observable postcondition.
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
async def test_create_product_non_string_name_returns_422_with_security_headers(client: AsyncClient):
    """
    The product-create POST with a non-string `name` (a JSON
    list): `name` is a required `str` field, and Pydantic v2
    does not coerce lists to strings, so request validation
    rejects the body with 422 before the handler body runs.
    """
    # Function-name grep count 0 for
    # create_product_non_string_name before appending,
    # verified fresh this run, not assumed. No non-string
    # lock exists for any CreateProductDto field yet, so this
    # starts the product-create per-field sweep: name: str,
    # description: str, tax_code: str | None, active: bool
    # (product_dto.py:16-20). The description sent is a valid
    # string, so it cannot mask the 422; tax_code is optional
    # and active defaults to True, so neither is sent and
    # neither can mask it. The DTO's mode="after"
    # normalize_name_and_description validator only runs
    # after valid field parsing, so it cannot mask the 422.
    # The endpoint is feature-gated (STRIPE) and
    # permission-gated (MANAGE_PRODUCTS_AND_PRICING) at the
    # router level, and FastAPI solves sub-dependencies
    # before validating the endpoint's own body, so the
    # tenant must be seeded with the STRIPE feature enabled
    # and the mocked caller's role must be seeded with the
    # permission first -- otherwise the feature gate's 403 or
    # the permission gate's RoleNotFoundException 404 would
    # mask the 422, exactly as in the role-create locks. The
    # tenant id (68c302ef6bf7a039b7e9b388) is both the
    # X-Tenant-ID header value and the caller's tenant_id, so
    # the handler's _assert_create_scope check would also
    # pass; the 422 comes from validation, before the
    # handler runs at all. FastAPI request validation fails
    # before the handler body runs: ProductService
    # .create_product never runs, so no Stripe call is made.
    # Deliberately no exact error-type assertion, mirroring
    # the role non-string-field 422 locks. Deliberately no
    # Cache-Control/Pragma assertion: a 422 is FastAPI request
    # validation, not an ApiBaseException, so the central
    # handler's no-store headers do not apply to it, mirroring
    # the role 422 locks. The security headers ARE locked:
    # the pure-ASGI middleware stamps every HTTP response,
    # including validation errors, with no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.entities.tenant import Feature, Tenant
    from api.domain.enum.feature import Feature as FeatureEnum
    from api.domain.enum.permission import Permission

    await Tenant(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b388"),
        name="products-validation-tenant",
        subdomain="products-validation.fsrapp.com",
        features=[Feature(name=FeatureEnum.STRIPE, enabled=True)],
    ).insert()
    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Tenant product manager",
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
                name="Tenant product manager",
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
            "/products/",
            headers={"X-Tenant-ID": "68c302ef6bf7a039b7e9b388"},
            json={"name": ["not-a-string"], "description": "A test product"},
        )
    finally:
        if original_override is None:
            app.dependency_overrides.pop(get_current_user, None)
        else:
            app.dependency_overrides[get_current_user] = original_override
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "name" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the other product locks in this file, using
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
    # runs, so no Stripe call is made and nothing is created
    # -- the seeded role is still there with
    # MANAGE_PRODUCTS_AND_PRICING and the seeded tenant is
    # still there with the STRIPE feature enabled. Products
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


@pytest.mark.asyncio
async def test_create_product_non_string_description_returns_422_with_security_headers(client: AsyncClient):
    """
    The product-create POST with a non-string `description` (a JSON
    list): `description` is a required `str` field, and Pydantic v2
    does not coerce lists to strings, so request validation
    rejects the body with 422 before the handler body runs.
    """
    # Function-name grep count 0 for
    # create_product_non_string_description before appending,
    # verified fresh this run, not assumed. The product-create
    # per-field sweep so far: name locked (2829); description
    # is this run; tax_code and active remain. CreateProductDto
    # fields (product_dto.py:16-20): name: str,
    # description: str, tax_code: str | None, active: bool.
    # The name sent is a valid string, so it cannot mask the
    # 422; tax_code is optional and active defaults to True,
    # so neither is sent and neither can mask it. The DTO's
    # mode="after" normalize_name_and_description validator
    # only runs after valid field parsing, so it cannot mask
    # the 422. The endpoint is feature-gated (STRIPE) and
    # permission-gated (MANAGE_PRODUCTS_AND_PRICING) at the
    # router level, and FastAPI solves sub-dependencies
    # before validating the endpoint's own body, so the
    # tenant must be seeded with the STRIPE feature enabled
    # and the mocked caller's role must be seeded with the
    # permission first -- otherwise the feature gate's 403 or
    # the permission gate's RoleNotFoundException 404 would
    # mask the 422, exactly as in the role-create locks. The
    # tenant id (68c302ef6bf7a039b7e9b388) is both the
    # X-Tenant-ID header value and the caller's tenant_id, so
    # the handler's _assert_create_scope check would also
    # pass; the 422 comes from validation, before the
    # handler runs at all. FastAPI request validation fails
    # before the handler body runs: ProductService
    # .create_product never runs, so no Stripe call is made.
    # Deliberately no exact error-type assertion, mirroring
    # the role non-string-field 422 locks. Deliberately no
    # Cache-Control/Pragma assertion: a 422 is FastAPI request
    # validation, not an ApiBaseException, so the central
    # handler's no-store headers do not apply to it, mirroring
    # the role 422 locks. The security headers ARE locked:
    # the pure-ASGI middleware stamps every HTTP response,
    # including validation errors, with no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.entities.tenant import Feature, Tenant
    from api.domain.enum.feature import Feature as FeatureEnum
    from api.domain.enum.permission import Permission

    await Tenant(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b388"),
        name="products-validation-tenant",
        subdomain="products-validation.fsrapp.com",
        features=[Feature(name=FeatureEnum.STRIPE, enabled=True)],
    ).insert()
    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Tenant product manager",
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
                name="Tenant product manager",
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
            "/products/",
            headers={"X-Tenant-ID": "68c302ef6bf7a039b7e9b388"},
            json={"name": "A test product", "description": ["not-a-string"]},
        )
    finally:
        if original_override is None:
            app.dependency_overrides.pop(get_current_user, None)
        else:
            app.dependency_overrides[get_current_user] = original_override
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "description" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the other product locks in this file, using
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
    # runs, so no Stripe call is made and nothing is created
    # -- the seeded role is still there with
    # MANAGE_PRODUCTS_AND_PRICING and the seeded tenant is
    # still there with the STRIPE feature enabled. Products
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


@pytest.mark.asyncio
async def test_create_product_non_string_tax_code_returns_422_with_security_headers(client: AsyncClient):
    """
    The product-create POST with a non-string `tax_code` (a JSON
    list): `tax_code` is an optional `str | None` field, and
    Pydantic v2 does not coerce lists to strings (a list is
    neither a string nor null), so request validation rejects
    the body with 422 before the handler body runs.
    """
    # Function-name grep count 0 for
    # create_product_non_string_tax_code before appending,
    # verified fresh this run, not assumed. The product-create
    # per-field sweep so far: name locked (2829), description
    # locked (2830); tax_code is this run; active remains.
    # CreateProductDto fields (product_dto.py:16-20): name: str,
    # description: str, tax_code: str | None, active: bool.
    # The name and description sent are valid strings, so they
    # cannot mask the 422; active defaults to True, so it is
    # not sent and cannot mask it. The DTO's mode="after"
    # normalize_name_and_description validator only runs after
    # valid field parsing and only touches name/description,
    # so it cannot mask the 422. The endpoint is feature-gated
    # (STRIPE) and permission-gated (MANAGE_PRODUCTS_AND_PRICING)
    # at the router level, and FastAPI solves sub-dependencies
    # before validating the endpoint's own body, so the tenant
    # must be seeded with the STRIPE feature enabled and the
    # mocked caller's role must be seeded with the permission
    # first -- otherwise the feature gate's 403 or the
    # permission gate's RoleNotFoundException 404 would mask
    # the 422, exactly as in the role-create locks. The tenant
    # id (68c302ef6bf7a039b7e9b388) is both the X-Tenant-ID
    # header value and the caller's tenant_id, so the handler's
    # _assert_create_scope check would also pass; the 422 comes
    # from validation, before the handler runs at all. FastAPI
    # request validation fails before the handler body runs:
    # ProductService.create_product never runs, so no Stripe
    # call is made. Deliberately no exact error-type assertion,
    # mirroring the role non-string-field 422 locks.
    # Deliberately no Cache-Control/Pragma assertion: a 422 is
    # FastAPI request validation, not an ApiBaseException, so
    # the central handler's no-store headers do not apply to
    # it, mirroring the role 422 locks. The security headers
    # ARE locked: the pure-ASGI middleware stamps every HTTP
    # response, including validation errors, with no path
    # exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.entities.tenant import Feature, Tenant
    from api.domain.enum.feature import Feature as FeatureEnum
    from api.domain.enum.permission import Permission

    await Tenant(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b388"),
        name="products-validation-tenant",
        subdomain="products-validation.fsrapp.com",
        features=[Feature(name=FeatureEnum.STRIPE, enabled=True)],
    ).insert()
    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Tenant product manager",
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
                name="Tenant product manager",
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
            "/products/",
            headers={"X-Tenant-ID": "68c302ef6bf7a039b7e9b388"},
            json={"name": "A test product", "description": "A test product", "tax_code": ["not-a-string"]},
        )
    finally:
        if original_override is None:
            app.dependency_overrides.pop(get_current_user, None)
        else:
            app.dependency_overrides[get_current_user] = original_override
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "tax_code" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the other product locks in this file, using
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
    # runs, so no Stripe call is made and nothing is created
    # -- the seeded role is still there with
    # MANAGE_PRODUCTS_AND_PRICING and the seeded tenant is
    # still there with the STRIPE feature enabled. Products
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


async def test_create_product_non_bool_active_returns_422_with_security_headers(client: AsyncClient):
    """
    The product-create POST with a non-bool `active` (a JSON
    list): `active` is a `bool` field defaulting to True, and
    Pydantic v2 does not coerce lists to bools, so request
    validation rejects the body with 422 before the handler
    body runs.
    """
    # Function-name grep count 0 for
    # create_product_non_bool_active before appending,
    # verified fresh this run, not assumed. The product-create
    # per-field sweep so far: name locked (2829), description
    # locked (2830), tax_code locked (2831); active is this
    # run and completes the sweep -- all four CreateProductDto
    # fields then have non-string/non-bool locks.
    # CreateProductDto fields (product_dto.py:16-20): name: str,
    # description: str, tax_code: str | None, active: bool.
    # The name and description sent are valid strings, so they
    # cannot mask the 422; tax_code is not sent (defaults to
    # None) and cannot mask it. The DTO's mode="after"
    # normalize_name_and_description validator only runs after
    # valid field parsing and only touches name/description,
    # so it cannot mask the 422. The endpoint is feature-gated
    # (STRIPE) and permission-gated (MANAGE_PRODUCTS_AND_PRICING)
    # at the router level, and FastAPI solves sub-dependencies
    # before validating the endpoint's own body, so the tenant
    # must be seeded with the STRIPE feature enabled and the
    # mocked caller's role must be seeded with the permission
    # first -- otherwise the feature gate's 403 or the
    # permission gate's RoleNotFoundException 404 would mask
    # the 422, exactly as in the role-create locks. The tenant
    # id (68c302ef6bf7a039b7e9b388) is both the X-Tenant-ID
    # header value and the caller's tenant_id, so the handler's
    # _assert_create_scope check would also pass; the 422 comes
    # from validation, before the handler runs at all. FastAPI
    # request validation fails before the handler body runs:
    # ProductService.create_product never runs, so no Stripe
    # call is made. Deliberately no exact error-type assertion,
    # mirroring the role non-string-field 422 locks.
    # Deliberately no Cache-Control/Pragma assertion: a 422 is
    # FastAPI request validation, not an ApiBaseException, so
    # the central handler's no-store headers do not apply to
    # it, mirroring the role 422 locks. The security headers
    # ARE locked: the pure-ASGI middleware stamps every HTTP
    # response, including validation errors, with no path
    # exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.entities.tenant import Feature, Tenant
    from api.domain.enum.feature import Feature as FeatureEnum
    from api.domain.enum.permission import Permission

    await Tenant(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b388"),
        name="products-validation-tenant",
        subdomain="products-validation.fsrapp.com",
        features=[Feature(name=FeatureEnum.STRIPE, enabled=True)],
    ).insert()
    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Tenant product manager",
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
                name="Tenant product manager",
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
            "/products/",
            headers={"X-Tenant-ID": "68c302ef6bf7a039b7e9b388"},
            json={"name": "A test product", "description": "A test product", "active": ["not-a-bool"]},
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
    # mirroring the other product locks in this file, using
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
    # runs, so no Stripe call is made and nothing is created
    # -- the seeded role is still there with
    # MANAGE_PRODUCTS_AND_PRICING and the seeded tenant is
    # still there with the STRIPE feature enabled. Products
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


@pytest.mark.asyncio
async def test_update_product_non_string_name_returns_422_with_security_headers(client: AsyncClient):
    """
    The product-update PATCH with a non-string `name` (a JSON
    list): PATCH /products/{id} reuses CreateProductDto, so
    `name` is a required `str` field with min_length=1, and
    Pydantic v2 does not coerce lists to strings, so request
    validation rejects the body with 422 before the handler
    body runs.
    """
    # Function-name grep count 0 for
    # update_product_non_string_name before appending,
    # verified fresh this run, not assumed. The product-create
    # per-field sweep is COMPLETE (name 2829, description
    # 2830, tax_code 2831, active 2832), but the PATCH update
    # route had no validation lock of its own: the create
    # locks prove the DTO rejects a bad body on POST, not
    # that the PATCH route reaches the same validation -- a
    # regression that dropped the body param (or the route)
    # would go uncaught by the POST locks. This run starts
    # the product-update per-field sweep with name;
    # description, tax_code, and active remain.
    # CreateProductDto fields (product_dto.py:16-20): name: str,
    # description: str, tax_code: str | None, active: bool.
    # The description sent is a valid string, so it cannot
    # mask the 422; tax_code is not sent (defaults to None)
    # and active is not sent (defaults to True), so neither
    # can mask it. The DTO's mode="after"
    # normalize_name_and_description validator only runs after
    # valid field parsing and only touches name/description,
    # so it cannot mask the 422. The endpoint is feature-gated
    # (STRIPE) and permission-gated (MANAGE_PRODUCTS_AND_PRICING)
    # at the router level, and FastAPI solves sub-dependencies
    # before validating the endpoint's own body, so the tenant
    # must be seeded with the STRIPE feature enabled and the
    # mocked caller's role must be seeded with the permission
    # first -- otherwise the feature gate's 403 or the
    # permission gate's RoleNotFoundException 404 would mask
    # the 422, exactly as in the product-create locks. The
    # tenant id (68c302ef6bf7a039b7e9b388) is both the
    # X-Tenant-ID header value and the caller's tenant_id, so
    # the handler's _assert_create_scope check would also pass;
    # the 422 comes from validation, before the handler runs
    # at all. The :path product_id param is a plain string
    # ("prod_test123", as in the feature-disabled PATCH lock)
    # and cannot mask the error. FastAPI request validation
    # fails before the handler body runs:
    # ProductService.update_product never runs, so no Stripe
    # call is made. Deliberately no exact error-type assertion,
    # mirroring the product-create non-string-field 422 locks.
    # Deliberately no Cache-Control/Pragma assertion: a 422 is
    # FastAPI request validation, not an ApiBaseException, so
    # the central handler's no-store headers do not apply to
    # it, mirroring the product-create 422 locks. The security
    # headers ARE locked: the pure-ASGI middleware stamps every
    # HTTP response, including validation errors, with no path
    # exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.entities.tenant import Feature, Tenant
    from api.domain.enum.feature import Feature as FeatureEnum
    from api.domain.enum.permission import Permission

    await Tenant(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b388"),
        name="products-validation-tenant",
        subdomain="products-validation.fsrapp.com",
        features=[Feature(name=FeatureEnum.STRIPE, enabled=True)],
    ).insert()
    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Tenant product manager",
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
                name="Tenant product manager",
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
            "/products/prod_test123",
            headers={"X-Tenant-ID": "68c302ef6bf7a039b7e9b388"},
            json={"name": ["not-a-string"], "description": "A test product"},
        )
    finally:
        if original_override is None:
            app.dependency_overrides.pop(get_current_user, None)
        else:
            app.dependency_overrides[get_current_user] = original_override
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "name" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the other product locks in this file, using
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
    # runs, so no Stripe call is made and nothing is updated
    # -- the seeded role is still there with
    # MANAGE_PRODUCTS_AND_PRICING and the seeded tenant is
    # still there with the STRIPE feature enabled. Products
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


async def test_update_product_non_string_description_returns_422_with_security_headers(client: AsyncClient):
    """
    The product-update PATCH with a non-string `description`
    (a JSON list): PATCH /products/{id} reuses
    CreateProductDto, so `description` is a required `str`
    field with min_length=1, and Pydantic v2 does not coerce
    lists to strings, so request validation rejects the body
    with 422 before the handler body runs.
    """
    # Function-name grep count 0 for
    # update_product_non_string_description before appending,
    # verified fresh this run, not assumed. The product-update
    # per-field sweep has name (2833) locked; this run locks
    # description; tax_code and active remain. CreateProductDto
    # fields (product_dto.py:16-20): name: str, description:
    # str, tax_code: str | None, active: bool. The name sent
    # is a valid string, so it cannot mask the 422; tax_code
    # is not sent (defaults to None) and active is not sent
    # (defaults to True), so neither can mask it. The DTO's
    # mode="after" normalize_name_and_description validator
    # only runs after valid field parsing and only touches
    # name/description, so it cannot mask the 422. The endpoint
    # is feature-gated (STRIPE) and permission-gated
    # (MANAGE_PRODUCTS_AND_PRICING) at the router level, and
    # FastAPI solves sub-dependencies before validating the
    # endpoint's own body, so the tenant must be seeded with
    # the STRIPE feature enabled and the mocked caller's role
    # must be seeded with the permission first -- otherwise the
    # feature gate's 403 or the permission gate's
    # RoleNotFoundException 404 would mask the 422, exactly as
    # in the product-create locks and the update name lock. The
    # tenant id (68c302ef6bf7a039b7e9b388) is both the
    # X-Tenant-ID header value and the caller's tenant_id, so
    # the handler's _assert_create_scope check would also pass;
    # the 422 comes from validation, before the handler runs
    # at all. The :path product_id param is a plain string
    # ("prod_test123", as in the feature-disabled PATCH lock)
    # and cannot mask the error. FastAPI request validation
    # fails before the handler body runs:
    # ProductService.update_product never runs, so no Stripe
    # call is made. Deliberately no exact error-type assertion,
    # mirroring the product-create non-string-field 422 locks.
    # Deliberately no Cache-Control/Pragma assertion: a 422 is
    # FastAPI request validation, not an ApiBaseException, so
    # the central handler's no-store headers do not apply to
    # it, mirroring the product-create 422 locks. The security
    # headers ARE locked: the pure-ASGI middleware stamps every
    # HTTP response, including validation errors, with no path
    # exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.entities.tenant import Feature, Tenant
    from api.domain.enum.feature import Feature as FeatureEnum
    from api.domain.enum.permission import Permission

    await Tenant(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b388"),
        name="products-validation-tenant",
        subdomain="products-validation.fsrapp.com",
        features=[Feature(name=FeatureEnum.STRIPE, enabled=True)],
    ).insert()
    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Tenant product manager",
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
                name="Tenant product manager",
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
            "/products/prod_test123",
            headers={"X-Tenant-ID": "68c302ef6bf7a039b7e9b388"},
            json={"name": "A test product", "description": ["not-a-string"]},
        )
    finally:
        if original_override is None:
            app.dependency_overrides.pop(get_current_user, None)
        else:
            app.dependency_overrides[get_current_user] = original_override
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "description" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the other product locks in this file, using
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
    # runs, so no Stripe call is made and nothing is updated
    # -- the seeded role is still there with
    # MANAGE_PRODUCTS_AND_PRICING and the seeded tenant is
    # still there with the STRIPE feature enabled. Products
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
