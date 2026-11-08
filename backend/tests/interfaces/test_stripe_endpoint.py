import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_stripe_webhook_without_signature_returns_bad_request_with_security_headers(client: AsyncClient):
    """
        The Stripe webhook POST without a signature header:
    """
    # The Stripe area had no interface test file at all, so deleting
    # the webhook router from api/__init__.py — or dropping the
    # security-headers middleware registration — would previously
    # have gone uncaught here even though every other interface area
    # locks its headers in. This POST needs no new fixture, no
    # authenticated user, and no live Stripe service: the webhook
    # router deliberately carries no auth dependencies (Stripe's
    # server-to-server POSTs carry no Bearer token; signature
    # verification inside the handler is its authentication), and
    # the request carries no X-Tenant-ID, so the tenant middleware
    # resolves host scope (the "test" host is neither the main
    # domain nor a subdomain of it, and no tenant record matches
    # it). On the host branch the secret comes from settings — a
    # required Settings field, so any environment that can import
    # the app has one — and verification then runs before any
    # service call or event dispatch. With no stripe-signature
    # header, stripe's verify_header raises
    # SignatureVerificationError before parsing the payload, and
    # the handler maps it to HTTPException 400 "Invalid signature".
    # That error path is therefore deterministic regardless of the
    # payload or the configured secret value.
    response = await client.post("/configurations/stripe/webhooks", content=b"{}")
    assert response.status_code == 400
    assert response.json()["detail"] == "Invalid signature"
    # Same security-headers lock as the other interface tests: the
    # pure-ASGI middleware stamps every HTTP response with no path
    # exclusions, so this unauthenticated webhook 400 must carry the
    # same headers as the authenticated GETs. Cache-Control:
    # no-store is now asserted too: the central HTTPException
    # handler in api/__init__.py stamps it (mirroring the
    # ApiBaseException handler), closing the gap this test
    # previously recorded — HTTPException responses used to carry
    # no cache headers at all.
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the twelve most sensitive directives as disabled, mirroring
    # the other interface locks, using substring checks so later
    # additions to the list do not break this test. The full value
    # lives in _SECURITY_HEADERS. Each directive is safe to lock
    # here for the same reasons as on the other routes: the SPA has
    # no camera, microphone, geolocation, payment, clipboard-read,
    # display-capture, fullscreen, motion-sensor, compass, XR, or
    # idle-detection flow (verified by grep in the earlier sweeps).
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
async def test_get_stripe_settings_with_missing_role_returns_404_with_cache_and_security_headers(client: AsyncClient):
    """
        The Stripe settings GET:
    """
    # The Stripe settings GET was untested: the stripe test file
    # only locked the unauthenticated webhook POST, so deleting
    # the settings router from api/__init__.py — or dropping the
    # central ApiBaseException no-store lines or the
    # security-headers middleware registration — would previously
    # have gone uncaught here even though every other interface
    # area locks its headers in. The success path is not asserted
    # here: the GET is permission-gated (MANAGE_PAYMENTS_SETTINGS
    # via a router-level dependency) and feature-gated
    # (Feature.STRIPE), so it needs a DB role lookup and a Stripe
    # settings service, and the shared conftest client seeds no
    # role — the SSO/branding tests document the same exclusion
    # for their endpoints. The error path below is deterministic
    # instead, with one ordering difference from the invoice and
    # checkout locks to note: on this router the permission
    # dependency is listed BEFORE the feature gate
    # (stripe_endpoint.py), so the permission check runs first.
    # The mocked host user's role_id points at no row in the
    # fresh test database (Role is in the conftest model set), so
    # the permission dependency raises RoleNotFoundException
    # before the feature gate, the read-scope guard, and the
    # handler run — so no Stripe settings service is ever reached,
    # no stored secret key is read, and no live external call is
    # made. That 404 must still carry the error-response headers:
    # Stripe settings are sensitive payment configuration, so a
    # cached 404 could otherwise be served to a different admin
    # after an account switch on a shared machine.
    response = await client.get("/configurations/stripe")
    assert response.status_code == 404
    body = response.json()
    assert body["code"] == 404
    assert "Role" in body["error"]
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the webhook test in this file:
    # the pure-ASGI middleware stamps every HTTP response with no
    # path exclusions, so this authenticated settings 404 must
    # carry the same headers as the other interface locks.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the twelve most sensitive directives as disabled, mirroring
    # the webhook lock, using substring checks so later additions
    # to the list do not break this test. The full value lives in
    # _SECURITY_HEADERS. Each directive is safe to lock here for
    # the same reasons as on the other routes: the SPA has no
    # camera, microphone, geolocation, payment, clipboard-read,
    # display-capture, fullscreen, motion-sensor, compass, XR, or
    # idle-detection flow (verified by grep in the earlier sweeps
    # and re-verified fresh this run: zero case-insensitive idle
    # matches and zero IdleDetector/requestIdleCallback matches
    # across frontend/app/src, and the remaining flows verified
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
async def test_post_stripe_settings_with_missing_role_returns_404_with_cache_and_security_headers(client: AsyncClient):
    """
        The Stripe settings POST:
    """
    # The Stripe settings POST was untested: the stripe test file
    # locked the webhook POST and the settings GET (missing-role
    # 404), but not the write path, so dropping the settings
    # router from api/__init__.py — or dropping the central
    # ApiBaseException no-store lines or the security-headers
    # middleware registration — would previously have gone
    # uncaught on this route even though every other interface
    # area locks its headers in. The success path is not asserted
    # here: the POST is permission-gated
    # (MANAGE_PAYMENTS_SETTINGS via a router-level dependency)
    # and feature-gated (Feature.STRIPE), so it needs a DB role
    # lookup and a Stripe settings service, and the shared
    # conftest client seeds no role — the same exclusion the
    # settings GET test documents. The error path below is
    # deterministic instead, with the same ordering as the GET:
    # on this router the permission dependency is listed BEFORE
    # the feature gate (stripe_endpoint.py), so the permission
    # check runs first. The mocked host user's role_id points at
    # no row in the fresh test database (Role is in the conftest
    # model set), so the permission dependency raises
    # RoleNotFoundException before the feature gate, the
    # create-scope guard, and the handler run — so no Stripe
    # settings service is ever reached, no secret key is stored,
    # and no live external call is made. The body below is a
    # fully valid CreateStripeSettingDto (dummy placeholder
    # secrets, never persisted) so no 422 can mask the 404
    # regardless of dependency/body validation ordering.
    # That 404 must still carry the error-response headers:
    # Stripe settings are sensitive payment configuration, so a
    # cached 404 could otherwise be served to a different admin
    # after an account switch on a shared machine.
    response = await client.post(
        "/configurations/stripe",
        json={
            "default_currency": "eur",
            "stripe_secret_key": "sk_test_dummy_not_a_real_key",
            "stripe_webhook_secret": "whsec_test_dummy_not_a_real_secret",
            "mode": "recurring",
            "trial_period_days": 14,
            "tenant_id": "test-tenant",
        },
    )
    assert response.status_code == 404
    body = response.json()
    assert body["code"] == 404
    assert "Role" in body["error"]
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the settings GET test in
    # this file: the pure-ASGI middleware stamps every HTTP
    # response with no path exclusions, so this authenticated
    # settings 404 must carry the same headers as the other
    # interface locks.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened:
    # lock the twelve most sensitive directives as disabled,
    # mirroring the other interface locks, using substring
    # checks so later additions to the list do not break this
    # test. The full value lives in _SECURITY_HEADERS. Each
    # directive is safe to lock here for the same reasons as on
    # the other routes: the SPA has no camera, microphone,
    # geolocation, payment, clipboard-read, display-capture,
    # fullscreen, motion-sensor, compass, XR, or
    # idle-detection flow (verified by grep in the earlier
    # sweeps and re-verified fresh this run: zero
    # case-insensitive idle matches and zero
    # IdleDetector/requestIdleCallback matches across
    # frontend/app/src).
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
async def test_post_stripe_settings_outside_tenant_scope_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        The Stripe settings POST create scope-guard error path:
        the three existing locks cover the webhook POST and the
        settings GET/POST missing-role 404s, but no test asserted
        a 403 on POST /configurations/stripe via the create scope
        guard - function-name grep count 0 for
        configure_stripe_outside_tenant_scope, verified fresh
        this run. Dropping _assert_create_scope
        (stripe_endpoint.py:50-70) would previously have gone
        uncaught, and a tenant caller configuring on the host DB
        would then overwrite the host DB's singleton Stripe
        settings record - including its secret keys - with their
        own tenant's keys, or squat the host slot on creation
        (the guard's own comment). The guard runs in the handler
        body (stripe_endpoint.py:84), after the tenant-context
        check and before any stripe-setting-service call, so no
        settings are written. It cannot be reached the way the
        SSO/storage locks reach their guards (tenant-scoped
        caller, no X-Tenant-ID header): the stripe router is
        feature-gated, and check_feature_access looks the tenant
        up by request.state.tenant_id before the handler runs,
        so with no header the lookup gets None,
        BaseRepository.get returns None, and get_tenant_by_id
        raises TenantNotFoundException - a 404 from the gate,
        never the scope 403. The lock therefore uses the
        mismatched scope the guard is written for, mirroring
        the POST products scope lock: the caller is
        tenant-scoped to 68c302ef6bf7a039b7e9b387 while the
        request carries X-Tenant-ID
        68c302ef6bf7a039b7e9b388, a seeded tenant with the
        STRIPE feature enabled, so the feature gate passes
        (Tenant stays bound to the host DB - init_db excludes
        it from the tenant-DB models, mongodb.py:53-56 - so the
        lookup finds the seeded row) and the guard raises
        ForbiddenException before any configure. The router
        carries a MANAGE_PAYMENTS_SETTINGS permission
        dependency, listed BEFORE the feature gate, so it runs
        first: the seeded role (id
        68c302ef6bf7a039b7e9b386) must carry that permission.
        get_role_detail calls get_role_by_id with no tenant
        argument (user_access_management.py), so
        _caller_may_access sees a None caller tenant and
        returns True (role_service.py:18-19), and the seeded
        row is visible regardless of the caller's tenant scope
        - the same mechanism the products scope lock relies on.
        The override's RoleDto carries the same permission, and
        the caller override mirrors the products lock's pattern
        (per-test MeResponseDto, restored in finally). The body
        is valid on purpose, reusing the POST 404 lock's body
        (dummy placeholder secrets, never persisted):
        CreateStripeSettingDto requires a 3-letter
        default_currency, non-blank stripe_secret_key and
        stripe_webhook_secret, a mode, trial_period_days
        0..365, and a tenant_id - an invalid body would fail
        validation with 422 and could mask the 403 depending
        on validation-vs-dependency ordering; a valid body
        makes the guard error deterministic either way. The
        central ApiBaseException handler maps
        ForbiddenException to 403 (api/__init__.py:98-103)
        with {"error": ..., "code": 403} and the no-store/Pragma
        error headers. A future change that drops the guard
        would break this lock while leaving the POST 404 lock
        green, so the paths are locked separately.
    """
    from beanie import PydanticObjectId

    from api import app
    from api.common.enums.gender import Gender
    from api.domain.dtos.auth_dto import MeResponseDto
    from api.domain.dtos.role_dto import RoleDto
    from api.domain.entities.role import Role
    from api.domain.entities.tenant import Feature, Tenant
    from api.domain.enum.feature import Feature as FeatureEnum
    from api.domain.enum.permission import Permission
    from api.infrastructure.security.current_user import get_current_user

    await Tenant(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b388"),
        name="stripe-scope-tenant",
        subdomain="stripe-scope.fsrapp.com",
        features=[Feature(name=FeatureEnum.STRIPE, enabled=True)],
    ).insert()
    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Tenant stripe administrator",
        description="Role carrying MANAGE_PAYMENTS_SETTINGS for the mocked caller",
        permissions=[Permission.MANAGE_PAYMENTS_SETTINGS],
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
                name="Tenant stripe administrator",
                description="Role carrying MANAGE_PAYMENTS_SETTINGS for the mocked caller",
                created_at="2024-10-01T00:00:00Z",
                updated_at="2024-10-01T00:00:00Z",
                permissions=[Permission.MANAGE_PAYMENTS_SETTINGS],
            ),
            subscription=None,
        )

    original_override = app.dependency_overrides.get(get_current_user)
    app.dependency_overrides[get_current_user] = override_get_current_user_tenant_scoped
    try:
        response = await client.post(
            "/configurations/stripe",
            headers={"X-Tenant-ID": "68c302ef6bf7a039b7e9b388"},
            json={
                "default_currency": "eur",
                "stripe_secret_key": "sk_test_dummy_not_a_real_key",
                "stripe_webhook_secret": "whsec_test_dummy_not_a_real_secret",
                "mode": "recurring",
                "trial_period_days": 14,
                "tenant_id": "test-tenant",
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
    # configure handler takes no Response param and sets no cache
    # headers at all, so on this path they come from the central
    # ApiBaseException handler, and a cached 403 could otherwise
    # be served to a different admin after an account switch on
    # a shared machine.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the settings GET test in this
    # file: the pure-ASGI middleware stamps every HTTP response
    # with no path exclusions, so this authenticated settings 403
    # must carry the same headers as the other interface locks.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened:
    # lock the twelve most sensitive directives as disabled,
    # mirroring the other interface locks, using substring
    # checks so later additions to the list do not break this
    # test. The full value lives in _SECURITY_HEADERS. Each
    # directive is safe to lock here for the same reasons as on
    # the other routes: the SPA has no camera, microphone,
    # geolocation, payment, clipboard-read, display-capture,
    # fullscreen, motion-sensor, compass, XR, or
    # idle-detection flow (verified by grep in the earlier
    # sweeps and re-verified fresh this run: zero
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
    # Postconditions: the guard fires before any stripe-setting
    # service call, so the configure is side-effect free - the
    # seeded role is still there with
    # MANAGE_PAYMENTS_SETTINGS and the seeded tenant is still
    # there with the STRIPE feature enabled. No StripeSettings
    # row is asserted: StripeSettings is not in the conftest
    # model set, so it cannot be queried from this test, and
    # the guard firing before the service call is what
    # guarantees nothing was written - the role and tenant rows
    # are the observable postconditions.
    stored_role = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored_role is not None
    assert stored_role.permissions == [Permission.MANAGE_PAYMENTS_SETTINGS]
    stored_tenant = await Tenant.find_one(
        Tenant.id == PydanticObjectId("68c302ef6bf7a039b7e9b388")
    )
    assert stored_tenant is not None
    assert stored_tenant.features == [Feature(name=FeatureEnum.STRIPE, enabled=True)]


@pytest.mark.asyncio
async def test_get_stripe_settings_outside_tenant_scope_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        The Stripe settings GET read scope-guard error path:
        the four existing locks cover the webhook POST, the
        settings GET/POST missing-role 404s, and the POST
        create-scope 403, but no test asserted a 403 on GET
        /configurations/stripe via the read scope guard -
        function-name grep count 0 for
        get_stripe_settings_outside_tenant_scope, verified fresh
        this run. Dropping _assert_read_scope
        (stripe_endpoint.py:92-110) would previously have gone
        uncaught, and a tenant caller reading on the host DB
        could then read a tenant-stamped settings record
        sitting in the host DB - including its stored secret
        keys - as the guard's own comment describes (the
        service checks the stored record's tenant stamp, but
        not which database served the request). The guard runs
        first in the handler body (stripe_endpoint.py:118),
        before the response cache headers are set and before
        the tenant-context check and any
        stripe-setting-service call, so no read happens and
        no settings leak. It cannot be reached the way the
        SSO/storage locks reach their guards (tenant-scoped
        caller, no X-Tenant-ID header): the stripe router is
        feature-gated, and check_feature_access looks the
        tenant up by request.state.tenant_id before the handler
        runs, so with no header the lookup gets None,
        BaseRepository.get returns None, and get_tenant_by_id
        raises TenantNotFoundException - a 404 from the gate,
        never the scope 403. The lock therefore uses the
        mismatched scope the guard is written for, mirroring
        the POST create-scope lock in this file: the caller is
        tenant-scoped to 68c302ef6bf7a039b7e9b387 while the
        request carries X-Tenant-ID
        68c302ef6bf7a039b7e9b388, a seeded tenant with the
        STRIPE feature enabled, so the feature gate passes
        (Tenant stays bound to the host DB - init_db excludes
        it from the tenant-DB models, mongodb.py:53-56 - so the
        lookup finds the seeded row) and the guard raises
        ForbiddenException before any read. The router carries
        a MANAGE_PAYMENTS_SETTINGS permission dependency,
        listed BEFORE the feature gate, so it runs first: the
        seeded role (id 68c302ef6bf7a039b7e9b386) must carry
        that permission. get_role_detail calls get_role_by_id
        with no tenant argument
        (user_access_management.py), so _caller_may_access sees
        a None caller tenant and returns True
        (role_service.py:18-19), and the seeded row is visible
        regardless of the caller's tenant scope - the same
        mechanism the POST scope lock relies on. The override's
        RoleDto carries the same permission, and the caller
        override mirrors the POST lock's pattern (per-test
        MeResponseDto, restored in finally). The GET takes no
        body or query params, so no 422 can mask the 403. The
        central ApiBaseException handler maps
        ForbiddenException to 403 (api/__init__.py:98-103)
        with {"error": ..., "code": 403} and the no-store/Pragma
        error headers. A future change that drops the guard
        would break this lock while leaving the GET 404 lock
        green, so the paths are locked separately.
    """
    from beanie import PydanticObjectId

    from api import app
    from api.common.enums.gender import Gender
    from api.domain.dtos.auth_dto import MeResponseDto
    from api.domain.dtos.role_dto import RoleDto
    from api.domain.entities.role import Role
    from api.domain.entities.tenant import Feature, Tenant
    from api.domain.enum.feature import Feature as FeatureEnum
    from api.domain.enum.permission import Permission
    from api.infrastructure.security.current_user import get_current_user

    await Tenant(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b388"),
        name="stripe-scope-tenant",
        subdomain="stripe-scope.fsrapp.com",
        features=[Feature(name=FeatureEnum.STRIPE, enabled=True)],
    ).insert()
    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Tenant stripe administrator",
        description="Role carrying MANAGE_PAYMENTS_SETTINGS for the mocked caller",
        permissions=[Permission.MANAGE_PAYMENTS_SETTINGS],
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
                name="Tenant stripe administrator",
                description="Role carrying MANAGE_PAYMENTS_SETTINGS for the mocked caller",
                created_at="2024-10-01T00:00:00Z",
                updated_at="2024-10-01T00:00:00Z",
                permissions=[Permission.MANAGE_PAYMENTS_SETTINGS],
            ),
            subscription=None,
        )

    original_override = app.dependency_overrides.get(get_current_user)
    app.dependency_overrides[get_current_user] = override_get_current_user_tenant_scoped
    try:
        response = await client.get(
            "/configurations/stripe",
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
    # read-scope guard raises before the handler sets its own
    # no-store/Pragma headers, so on this path they come from
    # the central ApiBaseException handler, and a cached 403
    # could otherwise be served to a different admin after an
    # account switch on a shared machine.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the settings GET test in this
    # file: the pure-ASGI middleware stamps every HTTP response
    # with no path exclusions, so this authenticated settings 403
    # must carry the same headers as the other interface locks.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened:
    # lock the twelve most sensitive directives as disabled,
    # mirroring the other interface locks, using substring
    # checks so later additions to the list do not break this
    # test. The full value lives in _SECURITY_HEADERS. Each
    # directive is safe to lock here for the same reasons as on
    # the other routes: the SPA has no camera, microphone,
    # geolocation, payment, clipboard-read, display-capture,
    # fullscreen, motion-sensor, compass, XR, or
    # idle-detection flow (verified by grep in the earlier
    # sweeps and re-verified fresh this run: zero
    # case-insensitive idle matches and zero
    # IdleDetector/requestIdleCallback matches across
    # frontend/app/src).
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
    # Postconditions: the guard fires before any stripe-setting
    # service call, so the read is side-effect free - the
    # seeded role is still there with
    # MANAGE_PAYMENTS_SETTINGS and the seeded tenant is still
    # there with the STRIPE feature enabled. No StripeSettings
    # row is asserted: StripeSettings is not in the conftest
    # model set, so it cannot be queried from this test, and
    # the guard firing before the service call is what
    # guarantees nothing was read - the role and tenant rows
    # are the observable postconditions.
    stored_role = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored_role is not None
    assert stored_role.permissions == [Permission.MANAGE_PAYMENTS_SETTINGS]
    stored_tenant = await Tenant.find_one(
        Tenant.id == PydanticObjectId("68c302ef6bf7a039b7e9b388")
    )
    assert stored_tenant is not None
    assert stored_tenant.features == [Feature(name=FeatureEnum.STRIPE, enabled=True)]


@pytest.mark.asyncio
async def test_get_stripe_settings_with_feature_disabled_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        The Stripe settings GET feature-gate error path:
        every other feature-gated router in the app (billing,
        checkout, prices, invoice, product, AI, and the tenant
        trial-plan route) already locks its feature-disabled 403,
        but the Stripe settings router had none - function-name
        grep count 0 for stripe_settings_with_feature_disabled
        and grep count 0 for "is not enabled" across
        backend/tests, verified fresh this run. Dropping the
        router-level check_feature_access(Feature.STRIPE)
        dependency (stripe_endpoint.py:26-35) would previously
        have gone uncaught on this router, and a host caller
        without the Stripe feature would then reach the
        settings handler instead of failing closed before it.
        The gate runs after the router's MANAGE_PAYMENTS_SETTINGS
        permission dependency (listed first), so the permission
        check runs first: the seeded role (id
        68c302ef6bf7a039b7e9b386) must carry that permission, and
        get_role_detail calls get_role_by_id with no tenant
        argument (user_access_management.py), so the seeded row
        is visible regardless of the caller's tenant scope - the
        same mechanism the scope locks in this file rely on. The
        caller is a host caller (tenant_id None, no X-Tenant-ID
        header) whose role carries no HOST_MANAGE_TENANTS, so
        the host-scope branch of check_feature_access raises
        FeatureNotEnabledException("stripe") before the handler
        runs - so no Stripe settings service is ever reached, no
        stored secret key is read, and no live external call is
        made. GET takes no body, so unlike POST/PATCH there is
        no validation that could mask the 403. The shared
        conftest mock cannot be used directly: it is a plain
        UserDto with no role attribute, so the gate would fail
        with an AttributeError 500 instead of the deterministic
        403 - the caller override mirrors the scope lock's
        pattern (per-test MeResponseDto, restored in finally).
        The central ApiBaseException handler maps
        ForbiddenException to 403 (api/__init__.py:98-103)
        with {"error": ..., "code": 403} and the no-store/Pragma
        error headers. A future change that drops the feature
        gate would break this lock while leaving the GET 404
        lock and the scope 403 locks green, so the paths are
        locked separately.
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
        name="Stripe feature administrator",
        description="Role carrying MANAGE_PAYMENTS_SETTINGS for the mocked caller",
        permissions=[Permission.MANAGE_PAYMENTS_SETTINGS],
    ).insert()

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
                name="Stripe feature administrator",
                description="Role carrying MANAGE_PAYMENTS_SETTINGS for the mocked caller",
                created_at="2024-10-01T00:00:00Z",
                updated_at="2024-10-01T00:00:00Z",
                permissions=[Permission.MANAGE_PAYMENTS_SETTINGS],
            ),
            subscription=None,
        )

    original_override = app.dependency_overrides.get(get_current_user)
    app.dependency_overrides[get_current_user] = override_get_current_user_with_role
    try:
        response = await client.get("/configurations/stripe")
    finally:
        if original_override is None:
            app.dependency_overrides.pop(get_current_user, None)
        else:
            app.dependency_overrides[get_current_user] = original_override
    assert response.status_code == 403
    body = response.json()
    assert body["code"] == 403
    assert body["error"] == "Feature 'stripe' is not enabled."
    # The 403 must still carry the error-response headers: the
    # settings GET handler takes a Response param but only sets
    # cache headers on the success path, so on this path they
    # come from the central ApiBaseException handler, and a
    # cached 403 could otherwise be served to a different admin
    # after an account switch on a shared machine.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the other tests in this file:
    # the pure-ASGI middleware stamps every HTTP response with no
    # path exclusions, so this authenticated settings 403 must
    # carry the same headers as the other interface locks.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened:
    # lock the twelve most sensitive directives as disabled,
    # mirroring the other interface locks, using substring
    # checks so later additions to the list do not break this
    # test. The full value lives in _SECURITY_HEADERS. Each
    # directive is safe to lock here for the same reasons as on
    # the other routes: the SPA has no camera, microphone,
    # geolocation, payment, clipboard-read, display-capture,
    # fullscreen, motion-sensor, compass, XR, or
    # idle-detection flow (verified by grep in the earlier
    # sweeps and re-verified fresh this run: zero
    # case-insensitive idle matches and zero
    # IdleDetector/requestIdleCallback matches across
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
    # Postconditions: the gate fires before any stripe-setting
    # service call, so the read is side-effect free - the
    # seeded role is still there with
    # MANAGE_PAYMENTS_SETTINGS and no HOST_MANAGE_TENANTS.
    # No StripeSettings row is asserted: StripeSettings is not
    # in the conftest model set, so it cannot be queried from
    # this test, and the gate firing before the handler is what
    # guarantees nothing was read - the role row is the
    # observable postcondition.
    stored_role = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored_role is not None
    assert stored_role.permissions == [Permission.MANAGE_PAYMENTS_SETTINGS]


@pytest.mark.asyncio
async def test_post_stripe_settings_non_string_default_currency_returns_422_with_security_headers(client: AsyncClient):
    """
        The Stripe settings POST with a non-string
        default_currency:
    """
    # This is the FIRST lock of the Stripe settings configure
    # per-field validation sweep: CreateStripeSettingDto has
    # six fields (default_currency, stripe_webhook_secret,
    # mode, trial_period_days, stripe_secret_key, tenant_id)
    # and none of them had a non-string lock, so a regression
    # that loosened validation on this payment-configuration
    # endpoint would previously have gone uncaught. This run
    # locks default_currency; the other five fields remain
    # for separate runs, one small fix per run.
    # default_currency is a plain str (min_length=3,
    # max_length=3) on CreateStripeSettingDto
    # (stripe_setting_dto.py), so a JSON list fails field
    # validation with loc ["body", "default_currency"]
    # before the model_validator runs (it runs after field
    # validation, so the secret/currency normalization
    # cannot mask the 422) and before the handler body runs
    # (so the tenant-context check, the create-scope guard,
    # and the stripe-setting service are never reached, no
    # secret key is stored, and no live external call is
    # made). The other five fields are valid on purpose
    # (dummy placeholder secrets, never persisted; a
    # 3-letter currency, recurring mode, 14 trial days, and
    # a tenant_id), so no other 422 can mask the loc.
    # The router dependencies run before body validation, so
    # they must pass for the 422 to be reached: the seeded
    # role (id 68c302ef6bf7a039b7e9b386) carries
    # MANAGE_PAYMENTS_SETTINGS, the seeded tenant (id
    # 68c302ef6bf7a039b7e9b388) has the STRIPE feature
    # enabled, and the caller override is tenant-scoped to
    # the same tenant the X-Tenant-ID header carries, so
    # the feature gate passes and the create-scope guard
    # would pass too if validation passed -- mirroring the
    # POST scope lock in this file, which uses the same
    # seeding. Deliberately no exact error-type assertion,
    # mirroring the checkout non-string email 422 lock.
    # Deliberately no Cache-Control/Pragma assertion: a 422
    # is a FastAPI validation error, not an error response
    # produced by the central ApiBaseException handler, so
    # it carries no no-store headers -- mirroring the
    # billing 422 locks. The security headers ARE locked:
    # the pure-ASGI middleware stamps every HTTP response
    # with no path exclusions, so this authenticated
    # settings 422 must carry the same headers as the other
    # interface locks.
    from beanie import PydanticObjectId, init_beanie
    from pymongo import AsyncMongoClient

    from api import app
    from api.common.enums.gender import Gender
    from api.domain.dtos.auth_dto import MeResponseDto
    from api.domain.dtos.role_dto import RoleDto
    from api.domain.entities.role import Role
    from api.domain.entities.stripe_settings import StripeSettings
    from api.domain.entities.tenant import Feature, Tenant
    from api.domain.enum.feature import Feature as FeatureEnum
    from api.domain.enum.permission import Permission
    from api.infrastructure.security.current_user import get_current_user

    mongo_client = AsyncMongoClient("mongodb://localhost:27012/test_db")
    await init_beanie(
        mongo_client["api_test_db"], document_models=[StripeSettings]
    )

    await Tenant(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b388"),
        name="stripe-422-tenant",
        subdomain="stripe-422.fsrapp.com",
        features=[Feature(name=FeatureEnum.STRIPE, enabled=True)],
    ).insert()
    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Tenant stripe administrator",
        description="Role carrying MANAGE_PAYMENTS_SETTINGS for the mocked caller",
        permissions=[Permission.MANAGE_PAYMENTS_SETTINGS],
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
                name="Tenant stripe administrator",
                description="Role carrying MANAGE_PAYMENTS_SETTINGS for the mocked caller",
                created_at="2024-10-01T00:00:00Z",
                updated_at="2024-10-01T00:00:00Z",
                permissions=[Permission.MANAGE_PAYMENTS_SETTINGS],
            ),
            subscription=None,
        )

    original_override = app.dependency_overrides.get(get_current_user)
    app.dependency_overrides[get_current_user] = override_get_current_user_tenant_scoped
    try:
        response = await client.post(
            "/configurations/stripe",
            headers={"X-Tenant-ID": "68c302ef6bf7a039b7e9b388"},
            json={
                "default_currency": ["eur"],
                "stripe_secret_key": "sk_test_dummy_not_a_real_key",
                "stripe_webhook_secret": "whsec_test_dummy_not_a_real_secret",
                "mode": "recurring",
                "trial_period_days": 14,
                "tenant_id": "test-tenant",
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
        "default_currency" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the other interface locks, using substring
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
    # runs, so no stripe-setting service call is made and no
    # record is created -- the seeded role is still there
    # with MANAGE_PAYMENTS_SETTINGS, the seeded tenant is
    # still there with the STRIPE feature enabled, and no
    # StripeSettings row exists in the test DB, mirroring
    # the storage configure lock (the init_beanie call above
    # registers StripeSettings, which is not in the conftest
    # model set, so the row can be queried here).
    stored_role = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored_role is not None
    assert stored_role.permissions == [Permission.MANAGE_PAYMENTS_SETTINGS]
    stored_tenant = await Tenant.find_one(
        Tenant.id == PydanticObjectId("68c302ef6bf7a039b7e9b388")
    )
    assert stored_tenant is not None
    assert stored_tenant.features == [Feature(name=FeatureEnum.STRIPE, enabled=True)]
    assert await StripeSettings.find_one() is None


@pytest.mark.asyncio
async def test_post_stripe_settings_non_string_stripe_webhook_secret_returns_422_with_security_headers(client: AsyncClient):
    """
        The Stripe settings POST with a non-string
        stripe_webhook_secret:
    """
    # This is the SECOND lock of the Stripe settings configure
    # per-field validation sweep: CreateStripeSettingDto has
    # six fields (default_currency, stripe_webhook_secret,
    # mode, trial_period_days, stripe_secret_key, tenant_id)
    # and only default_currency had a non-string lock, so a
    # regression that loosened validation on this payment-
    # configuration endpoint would previously have gone
    # uncaught for this field. This run locks
    # stripe_webhook_secret; mode, trial_period_days,
    # stripe_secret_key, and tenant_id remain for separate
    # runs, one small fix per run.
    # stripe_webhook_secret is a plain str (min_length=1)
    # on CreateStripeSettingDto (stripe_setting_dto.py
    # line 55), so a JSON list fails field validation with
    # loc ["body", "stripe_webhook_secret"] before the
    # model_validator runs (it runs after field validation,
    # so the secret normalization cannot mask the 422) and
    # before the handler body runs (so the tenant-context
    # check, the create-scope guard, and the stripe-setting
    # service are never reached, no secret key is stored,
    # and no live external call is made). The other five
    # fields are valid on purpose (dummy placeholder
    # secrets, never persisted; a 3-letter currency,
    # recurring mode, 14 trial days, and a tenant_id), so
    # no other 422 can mask the loc.
    # The router dependencies run before body validation, so
    # they must pass for the 422 to be reached: the seeded
    # role (id 68c302ef6bf7a039b7e9b386) carries
    # MANAGE_PAYMENTS_SETTINGS, the seeded tenant (id
    # 68c302ef6bf7a039b7e9b388) has the STRIPE feature
    # enabled, and the caller override is tenant-scoped to
    # the same tenant the X-Tenant-ID header carries, so
    # the feature gate passes and the create-scope guard
    # would pass too if validation passed -- mirroring the
    # default_currency lock in this file, which uses the
    # same seeding. Deliberately no exact error-type
    # assertion, mirroring the checkout non-string email
    # 422 lock. Deliberately no Cache-Control/Pragma
    # assertion: a 422 is a FastAPI validation error, not
    # an error response produced by the central
    # ApiBaseException handler, so it carries no no-store
    # headers -- mirroring the billing 422 locks. The
    # security headers ARE locked: the pure-ASGI middleware
    # stamps every HTTP response with no path exclusions,
    # so this authenticated settings 422 must carry the
    # same headers as the other interface locks.
    from beanie import PydanticObjectId, init_beanie
    from pymongo import AsyncMongoClient

    from api import app
    from api.common.enums.gender import Gender
    from api.domain.dtos.auth_dto import MeResponseDto
    from api.domain.dtos.role_dto import RoleDto
    from api.domain.entities.role import Role
    from api.domain.entities.stripe_settings import StripeSettings
    from api.domain.entities.tenant import Feature, Tenant
    from api.domain.enum.feature import Feature as FeatureEnum
    from api.domain.enum.permission import Permission
    from api.infrastructure.security.current_user import get_current_user

    mongo_client = AsyncMongoClient("mongodb://localhost:27012/test_db")
    await init_beanie(
        mongo_client["api_test_db"], document_models=[StripeSettings]
    )

    await Tenant(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b388"),
        name="stripe-422-tenant",
        subdomain="stripe-422.fsrapp.com",
        features=[Feature(name=FeatureEnum.STRIPE, enabled=True)],
    ).insert()
    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Tenant stripe administrator",
        description="Role carrying MANAGE_PAYMENTS_SETTINGS for the mocked caller",
        permissions=[Permission.MANAGE_PAYMENTS_SETTINGS],
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
                name="Tenant stripe administrator",
                description="Role carrying MANAGE_PAYMENTS_SETTINGS for the mocked caller",
                created_at="2024-10-01T00:00:00Z",
                updated_at="2024-10-01T00:00:00Z",
                permissions=[Permission.MANAGE_PAYMENTS_SETTINGS],
            ),
            subscription=None,
        )

    original_override = app.dependency_overrides.get(get_current_user)
    app.dependency_overrides[get_current_user] = override_get_current_user_tenant_scoped
    try:
        response = await client.post(
            "/configurations/stripe",
            headers={"X-Tenant-ID": "68c302ef6bf7a039b7e9b388"},
            json={
                "default_currency": "eur",
                "stripe_secret_key": "sk_test_dummy_not_a_real_key",
                "stripe_webhook_secret": ["whsec_test_dummy_not_a_real_secret"],
                "mode": "recurring",
                "trial_period_days": 14,
                "tenant_id": "test-tenant",
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
        "stripe_webhook_secret" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the other interface locks, using substring
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
    # runs, so no stripe-setting service call is made and no
    # record is created -- the seeded role is still there
    # with MANAGE_PAYMENTS_SETTINGS, the seeded tenant is
    # still there with the STRIPE feature enabled, and no
    # StripeSettings row exists in the test DB, mirroring
    # the default_currency lock (the init_beanie call above
    # registers StripeSettings, which is not in the conftest
    # model set, so the row can be queried here).
    stored_role = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored_role is not None
    assert stored_role.permissions == [Permission.MANAGE_PAYMENTS_SETTINGS]
    stored_tenant = await Tenant.find_one(
        Tenant.id == PydanticObjectId("68c302ef6bf7a039b7e9b388")
    )
    assert stored_tenant is not None
    assert stored_tenant.features == [Feature(name=FeatureEnum.STRIPE, enabled=True)]
    assert await StripeSettings.find_one() is None


async def test_post_stripe_settings_non_string_mode_returns_422_with_security_headers(client: AsyncClient):
    """
        The Stripe settings POST with a non-string
        mode:
    """
    # This is the THIRD lock of the Stripe settings configure
    # per-field validation sweep: CreateStripeSettingDto has
    # six fields (default_currency, stripe_webhook_secret,
    # mode, trial_period_days, stripe_secret_key, tenant_id)
    # and only default_currency and stripe_webhook_secret
    # had non-string locks, so a regression that loosened
    # validation on this payment-configuration endpoint
    # would previously have gone uncaught for this field.
    # This run locks mode; trial_period_days,
    # stripe_secret_key, and tenant_id remain for separate
    # runs, one small fix per run.
    # mode is PaymentType = Literal["one_time", "recurring",
    # "both"] on CreateStripeSettingDto
    # (stripe_setting_dto.py line 56, defined in
    # stripe_settings.py line 7), so a JSON list fails field
    # validation with loc ["body", "mode"] before the
    # model_validator runs (it runs after field validation,
    # so the secret normalization cannot mask the 422 -- and
    # the normalizer only touches str secrets/currency
    # anyway) and before the handler body runs (so the
    # tenant-context check, the create-scope guard, and the
    # stripe-setting service are never reached, no secret
    # key is stored, and no live external call is made).
    # The other five fields are valid on purpose (dummy
    # placeholder secrets, never persisted; a 3-letter
    # currency, 14 trial days, and a tenant_id), so no
    # other 422 can mask the loc.
    # The router dependencies run before body validation, so
    # they must pass for the 422 to be reached: the seeded
    # role (id 68c302ef6bf7a039b7e9b386) carries
    # MANAGE_PAYMENTS_SETTINGS, the seeded tenant (id
    # 68c302ef6bf7a039b7e9b388) has the STRIPE feature
    # enabled, and the caller override is tenant-scoped to
    # the same tenant the X-Tenant-ID header carries, so
    # the feature gate passes and the create-scope guard
    # would pass too if validation passed -- mirroring the
    # stripe_webhook_secret lock in this file, which uses
    # the same seeding. Deliberately no exact error-type
    # assertion, mirroring the checkout non-string email
    # 422 lock. Deliberately no Cache-Control/Pragma
    # assertion: a 422 is a FastAPI validation error, not
    # an error response produced by the central
    # ApiBaseException handler, so it carries no no-store
    # headers -- mirroring the billing 422 locks. The
    # security headers ARE locked: the pure-ASGI middleware
    # stamps every HTTP response with no path exclusions,
    # so this authenticated settings 422 must carry the
    # same headers as the other interface locks.
    from beanie import PydanticObjectId, init_beanie
    from pymongo import AsyncMongoClient

    from api import app
    from api.common.enums.gender import Gender
    from api.domain.dtos.auth_dto import MeResponseDto
    from api.domain.dtos.role_dto import RoleDto
    from api.domain.entities.role import Role
    from api.domain.entities.stripe_settings import StripeSettings
    from api.domain.entities.tenant import Feature, Tenant
    from api.domain.enum.feature import Feature as FeatureEnum
    from api.domain.enum.permission import Permission
    from api.infrastructure.security.current_user import get_current_user

    mongo_client = AsyncMongoClient("mongodb://localhost:27012/test_db")
    await init_beanie(
        mongo_client["api_test_db"], document_models=[StripeSettings]
    )

    await Tenant(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b388"),
        name="stripe-422-tenant",
        subdomain="stripe-422.fsrapp.com",
        features=[Feature(name=FeatureEnum.STRIPE, enabled=True)],
    ).insert()
    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Tenant stripe administrator",
        description="Role carrying MANAGE_PAYMENTS_SETTINGS for the mocked caller",
        permissions=[Permission.MANAGE_PAYMENTS_SETTINGS],
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
                name="Tenant stripe administrator",
                description="Role carrying MANAGE_PAYMENTS_SETTINGS for the mocked caller",
                created_at="2024-10-01T00:00:00Z",
                updated_at="2024-10-01T00:00:00Z",
                permissions=[Permission.MANAGE_PAYMENTS_SETTINGS],
            ),
            subscription=None,
        )

    original_override = app.dependency_overrides.get(get_current_user)
    app.dependency_overrides[get_current_user] = override_get_current_user_tenant_scoped
    try:
        response = await client.post(
            "/configurations/stripe",
            headers={"X-Tenant-ID": "68c302ef6bf7a039b7e9b388"},
            json={
                "default_currency": "eur",
                "stripe_secret_key": "sk_test_dummy_not_a_real_key",
                "stripe_webhook_secret": "whsec_test_dummy_not_a_real_secret",
                "mode": ["recurring"],
                "trial_period_days": 14,
                "tenant_id": "test-tenant",
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
        "mode" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the other interface locks, using substring
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
    # runs, so no stripe-setting service call is made and no
    # record is created -- the seeded role is still there
    # with MANAGE_PAYMENTS_SETTINGS, the seeded tenant is
    # still there with the STRIPE feature enabled, and no
    # StripeSettings row exists in the test DB, mirroring
    # the stripe_webhook_secret lock (the init_beanie call
    # above registers StripeSettings, which is not in the
    # conftest model set, so the row can be queried here).
    stored_role = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored_role is not None
    assert stored_role.permissions == [Permission.MANAGE_PAYMENTS_SETTINGS]
    stored_tenant = await Tenant.find_one(
        Tenant.id == PydanticObjectId("68c302ef6bf7a039b7e9b388")
    )
    assert stored_tenant is not None
    assert stored_tenant.features == [Feature(name=FeatureEnum.STRIPE, enabled=True)]
    assert await StripeSettings.find_one() is None


async def test_post_stripe_settings_non_string_trial_period_days_returns_422_with_security_headers(client: AsyncClient):
    """
        The Stripe settings POST with a non-string
        trial_period_days:
    """
    # This is the FOURTH lock of the Stripe settings
    # configure per-field validation sweep:
    # CreateStripeSettingDto has six fields
    # (default_currency, stripe_webhook_secret, mode,
    # trial_period_days, stripe_secret_key, tenant_id)
    # and only default_currency, stripe_webhook_secret,
    # and mode had non-string locks, so a regression that
    # loosened validation on this payment-configuration
    # endpoint would previously have gone uncaught for
    # this field. This run locks trial_period_days;
    # stripe_secret_key and tenant_id remain for separate
    # runs, one small fix per run.
    # trial_period_days is int = Field(default=14, ge=0,
    # le=365) on CreateStripeSettingDto
    # (stripe_setting_dto.py lines 57-60), so a JSON list
    # fails field validation with loc ["body",
    # "trial_period_days"] before the model_validator runs
    # (it runs after field validation, so the secret
    # normalization cannot mask the 422 -- and the
    # normalizer only touches str secrets/currency anyway)
    # and before the handler body runs (so the
    # tenant-context check, the create-scope guard, and
    # the stripe-setting service are never reached, no
    # secret key is stored, and no live external call is
    # made). Pydantic v2 lax mode coerces numeric strings
    # and bools to int, but a list is not coercible, so
    # the 422 is exact for this payload.
    # The other five fields are valid on purpose (dummy
    # placeholder secrets, never persisted; a 3-letter
    # currency, a recurring mode, and a tenant_id), so no
    # other 422 can mask the loc.
    # The router dependencies run before body validation, so
    # they must pass for the 422 to be reached: the seeded
    # role (id 68c302ef6bf7a039b7e9b386) carries
    # MANAGE_PAYMENTS_SETTINGS, the seeded tenant (id
    # 68c302ef6bf7a039b7e9b388) has the STRIPE feature
    # enabled, and the caller override is tenant-scoped to
    # the same tenant the X-Tenant-ID header carries, so
    # the feature gate passes and the create-scope guard
    # would pass too if validation passed -- mirroring the
    # mode lock in this file, which uses the same seeding.
    # Deliberately no exact error-type assertion,
    # mirroring the checkout non-string email 422 lock.
    # Deliberately no Cache-Control/Pragma assertion: a
    # 422 is a FastAPI validation error, not an error
    # response produced by the central ApiBaseException
    # handler, so it carries no no-store headers --
    # mirroring the billing 422 locks. The security
    # headers ARE locked: the pure-ASGI middleware stamps
    # every HTTP response with no path exclusions, so this
    # authenticated settings 422 must carry the same
    # headers as the other interface locks.
    from beanie import PydanticObjectId, init_beanie
    from pymongo import AsyncMongoClient

    from api import app
    from api.common.enums.gender import Gender
    from api.domain.dtos.auth_dto import MeResponseDto
    from api.domain.dtos.role_dto import RoleDto
    from api.domain.entities.role import Role
    from api.domain.entities.stripe_settings import StripeSettings
    from api.domain.entities.tenant import Feature, Tenant
    from api.domain.enum.feature import Feature as FeatureEnum
    from api.domain.enum.permission import Permission
    from api.infrastructure.security.current_user import get_current_user

    mongo_client = AsyncMongoClient("mongodb://localhost:27012/test_db")
    await init_beanie(
        mongo_client["api_test_db"], document_models=[StripeSettings]
    )

    await Tenant(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b388"),
        name="stripe-422-tenant",
        subdomain="stripe-422.fsrapp.com",
        features=[Feature(name=FeatureEnum.STRIPE, enabled=True)],
    ).insert()
    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Tenant stripe administrator",
        description="Role carrying MANAGE_PAYMENTS_SETTINGS for the mocked caller",
        permissions=[Permission.MANAGE_PAYMENTS_SETTINGS],
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
                name="Tenant stripe administrator",
                description="Role carrying MANAGE_PAYMENTS_SETTINGS for the mocked caller",
                created_at="2024-10-01T00:00:00Z",
                updated_at="2024-10-01T00:00:00Z",
                permissions=[Permission.MANAGE_PAYMENTS_SETTINGS],
            ),
            subscription=None,
        )

    original_override = app.dependency_overrides.get(get_current_user)
    app.dependency_overrides[get_current_user] = override_get_current_user_tenant_scoped
    try:
        response = await client.post(
            "/configurations/stripe",
            headers={"X-Tenant-ID": "68c302ef6bf7a039b7e9b388"},
            json={
                "default_currency": "eur",
                "stripe_secret_key": "sk_test_dummy_not_a_real_key",
                "stripe_webhook_secret": "whsec_test_dummy_not_a_real_secret",
                "mode": "recurring",
                "trial_period_days": [14],
                "tenant_id": "test-tenant",
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
        "trial_period_days" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the other interface locks, using substring
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
    # runs, so no stripe-setting service call is made and no
    # record is created -- the seeded role is still there
    # with MANAGE_PAYMENTS_SETTINGS, the seeded tenant is
    # still there with the STRIPE feature enabled, and no
    # StripeSettings row exists in the test DB, mirroring
    # the mode lock (the init_beanie call above registers
    # StripeSettings, which is not in the conftest model
    # set, so the row can be queried here).
    stored_role = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored_role is not None
    assert stored_role.permissions == [Permission.MANAGE_PAYMENTS_SETTINGS]
    stored_tenant = await Tenant.find_one(
        Tenant.id == PydanticObjectId("68c302ef6bf7a039b7e9b388")
    )
    assert stored_tenant is not None
    assert stored_tenant.features == [Feature(name=FeatureEnum.STRIPE, enabled=True)]
    assert await StripeSettings.find_one() is None


async def test_post_stripe_settings_non_string_stripe_secret_key_returns_422_with_security_headers(client: AsyncClient):
    """
        The Stripe settings POST with a non-string
        stripe_secret_key:
    """
    # This is the FIFTH lock of the Stripe settings
    # configure per-field validation sweep:
    # CreateStripeSettingDto has six fields
    # (default_currency, stripe_webhook_secret, mode,
    # trial_period_days, stripe_secret_key, tenant_id)
    # and only default_currency, stripe_webhook_secret,
    # mode, and trial_period_days had non-string locks,
    # so a regression that loosened validation on this
    # payment-configuration endpoint would previously
    # have gone uncaught for this field. This run locks
    # stripe_secret_key; tenant_id remains for a separate
    # run, one small fix per run.
    # stripe_secret_key is str = Field(min_length=1) on
    # CreateStripeSettingDto (stripe_setting_dto.py line
    # 64), so a JSON list fails field validation with loc
    # ["body", "stripe_secret_key"] before the
    # model_validator runs (it runs after field validation,
    # so the secret normalization cannot mask the 422 --
    # and the normalizer only touches str values anyway,
    # via its isinstance check) and before the handler
    # body runs (so the tenant-context check, the
    # create-scope guard, and the stripe-setting service
    # are never reached, no secret key is stored, and no
    # live external call is made). Pydantic v2 does not
    # coerce lists to str, so the 422 is exact for this
    # payload.
    # The other five fields are valid on purpose (dummy
    # placeholder secrets, never persisted; a 3-letter
    # currency, a recurring mode, an in-range trial period,
    # and a tenant_id), so no other 422 can mask the loc.
    # The router dependencies run before body validation, so
    # they must pass for the 422 to be reached: the seeded
    # role (id 68c302ef6bf7a039b7e9b386) carries
    # MANAGE_PAYMENTS_SETTINGS, the seeded tenant (id
    # 68c302ef6bf7a039b7e9b388) has the STRIPE feature
    # enabled, and the caller override is tenant-scoped to
    # the same tenant the X-Tenant-ID header carries, so
    # the feature gate passes and the create-scope guard
    # would pass too if validation passed -- mirroring the
    # trial_period_days lock in this file, which uses the
    # same seeding.
    # Deliberately no exact error-type assertion,
    # mirroring the checkout non-string email 422 lock.
    # Deliberately no Cache-Control/Pragma assertion: a
    # 422 is a FastAPI validation error, not an error
    # response produced by the central ApiBaseException
    # handler, so it carries no no-store headers --
    # mirroring the billing 422 locks. The security
    # headers ARE locked: the pure-ASGI middleware stamps
    # every HTTP response with no path exclusions, so this
    # authenticated settings 422 must carry the same
    # headers as the other interface locks.
    from beanie import PydanticObjectId, init_beanie
    from pymongo import AsyncMongoClient

    from api import app
    from api.common.enums.gender import Gender
    from api.domain.dtos.auth_dto import MeResponseDto
    from api.domain.dtos.role_dto import RoleDto
    from api.domain.entities.role import Role
    from api.domain.entities.stripe_settings import StripeSettings
    from api.domain.entities.tenant import Feature, Tenant
    from api.domain.enum.feature import Feature as FeatureEnum
    from api.domain.enum.permission import Permission
    from api.infrastructure.security.current_user import get_current_user

    mongo_client = AsyncMongoClient("mongodb://localhost:27012/test_db")
    await init_beanie(
        mongo_client["api_test_db"], document_models=[StripeSettings]
    )

    await Tenant(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b388"),
        name="stripe-422-tenant",
        subdomain="stripe-422.fsrapp.com",
        features=[Feature(name=FeatureEnum.STRIPE, enabled=True)],
    ).insert()
    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Tenant stripe administrator",
        description="Role carrying MANAGE_PAYMENTS_SETTINGS for the mocked caller",
        permissions=[Permission.MANAGE_PAYMENTS_SETTINGS],
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
                name="Tenant stripe administrator",
                description="Role carrying MANAGE_PAYMENTS_SETTINGS for the mocked caller",
                created_at="2024-10-01T00:00:00Z",
                updated_at="2024-10-01T00:00:00Z",
                permissions=[Permission.MANAGE_PAYMENTS_SETTINGS],
            ),
            subscription=None,
        )

    original_override = app.dependency_overrides.get(get_current_user)
    app.dependency_overrides[get_current_user] = override_get_current_user_tenant_scoped
    try:
        response = await client.post(
            "/configurations/stripe",
            headers={"X-Tenant-ID": "68c302ef6bf7a039b7e9b388"},
            json={
                "default_currency": "eur",
                "stripe_secret_key": ["sk_test_dummy_not_a_real_key"],
                "stripe_webhook_secret": "whsec_test_dummy_not_a_real_secret",
                "mode": "recurring",
                "trial_period_days": 14,
                "tenant_id": "test-tenant",
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
        "stripe_secret_key" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the other interface locks, using substring
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
    # runs, so no stripe-setting service call is made and no
    # record is created -- the seeded role is still there
    # with MANAGE_PAYMENTS_SETTINGS, the seeded tenant is
    # still there with the STRIPE feature enabled, and no
    # StripeSettings row exists in the test DB, mirroring
    # the trial_period_days lock (the init_beanie call above
    # registers StripeSettings, which is not in the conftest
    # model set, so the row can be queried here).
    stored_role = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored_role is not None
    assert stored_role.permissions == [Permission.MANAGE_PAYMENTS_SETTINGS]
    stored_tenant = await Tenant.find_one(
        Tenant.id == PydanticObjectId("68c302ef6bf7a039b7e9b388")
    )
    assert stored_tenant is not None
    assert stored_tenant.features == [Feature(name=FeatureEnum.STRIPE, enabled=True)]
    assert await StripeSettings.find_one() is None


async def test_post_stripe_settings_non_string_tenant_id_returns_422_with_security_headers(client: AsyncClient):
    """
        The Stripe settings POST with a non-string
        tenant_id:
    """
    # This is the SIXTH and FINAL lock of the Stripe
    # settings configure per-field validation sweep:
    # CreateStripeSettingDto has six fields
    # (default_currency, stripe_webhook_secret, mode,
    # trial_period_days, stripe_secret_key, tenant_id)
    # and only the other five had non-string locks, so a
    # regression that loosened validation on this
    # payment-configuration endpoint would previously
    # have gone uncaught for this field. This run locks
    # tenant_id; with it the sweep is COMPLETE.
    # tenant_id is a plain required str on
    # CreateStripeSettingDto (stripe_setting_dto.py line
    # 65), so a JSON list fails field validation with loc
    # ["body", "tenant_id"] before the model_validator
    # runs (it runs after field validation, so the secret
    # normalization cannot mask the 422 -- and the
    # normalizer only touches the secrets and currency
    # anyway, via its isinstance checks) and before the
    # handler body runs (so the tenant-context check, the
    # create-scope guard, and the stripe-setting service
    # are never reached, no secret key is stored, and no
    # live external call is made). Pydantic v2 does not
    # coerce lists to str, so the 422 is exact for this
    # payload.
    # The other five fields are valid on purpose (dummy
    # placeholder secrets, never persisted; a 3-letter
    # currency, a recurring mode, and an in-range trial
    # period), so no other 422 can mask the loc.
    # The router dependencies run before body validation, so
    # they must pass for the 422 to be reached: the seeded
    # role (id 68c302ef6bf7a039b7e9b386) carries
    # MANAGE_PAYMENTS_SETTINGS, the seeded tenant (id
    # 68c302ef6bf7a039b7e9b388) has the STRIPE feature
    # enabled, and the caller override is tenant-scoped to
    # the same tenant the X-Tenant-ID header carries, so
    # the feature gate passes and the create-scope guard
    # would pass too if validation passed -- mirroring the
    # stripe_secret_key lock in this file, which uses the
    # same seeding.
    # Deliberately no exact error-type assertion,
    # mirroring the checkout non-string email 422 lock.
    # Deliberately no Cache-Control/Pragma assertion: a
    # 422 is a FastAPI validation error, not an error
    # response produced by the central ApiBaseException
    # handler, so it carries no no-store headers --
    # mirroring the billing 422 locks. The security
    # headers ARE locked: the pure-ASGI middleware stamps
    # every HTTP response with no path exclusions, so this
    # authenticated settings 422 must carry the same
    # headers as the other interface locks.
    from beanie import PydanticObjectId, init_beanie
    from pymongo import AsyncMongoClient

    from api import app
    from api.common.enums.gender import Gender
    from api.domain.dtos.auth_dto import MeResponseDto
    from api.domain.dtos.role_dto import RoleDto
    from api.domain.entities.role import Role
    from api.domain.entities.stripe_settings import StripeSettings
    from api.domain.entities.tenant import Feature, Tenant
    from api.domain.enum.feature import Feature as FeatureEnum
    from api.domain.enum.permission import Permission
    from api.infrastructure.security.current_user import get_current_user

    mongo_client = AsyncMongoClient("mongodb://localhost:27012/test_db")
    await init_beanie(
        mongo_client["api_test_db"], document_models=[StripeSettings]
    )

    await Tenant(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b388"),
        name="stripe-422-tenant",
        subdomain="stripe-422.fsrapp.com",
        features=[Feature(name=FeatureEnum.STRIPE, enabled=True)],
    ).insert()
    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Tenant stripe administrator",
        description="Role carrying MANAGE_PAYMENTS_SETTINGS for the mocked caller",
        permissions=[Permission.MANAGE_PAYMENTS_SETTINGS],
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
                name="Tenant stripe administrator",
                description="Role carrying MANAGE_PAYMENTS_SETTINGS for the mocked caller",
                created_at="2024-10-01T00:00:00Z",
                updated_at="2024-10-01T00:00:00Z",
                permissions=[Permission.MANAGE_PAYMENTS_SETTINGS],
            ),
            subscription=None,
        )

    original_override = app.dependency_overrides.get(get_current_user)
    app.dependency_overrides[get_current_user] = override_get_current_user_tenant_scoped
    try:
        response = await client.post(
            "/configurations/stripe",
            headers={"X-Tenant-ID": "68c302ef6bf7a039b7e9b388"},
            json={
                "default_currency": "eur",
                "stripe_secret_key": "sk_test_dummy_not_a_real_key",
                "stripe_webhook_secret": "whsec_test_dummy_not_a_real_secret",
                "mode": "recurring",
                "trial_period_days": 14,
                "tenant_id": ["test-tenant"],
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
        "tenant_id" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the other interface locks, using substring
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
    # runs, so no stripe-setting service call is made and no
    # record is created -- the seeded role is still there
    # with MANAGE_PAYMENTS_SETTINGS, the seeded tenant is
    # still there with the STRIPE feature enabled, and no
    # StripeSettings row exists in the test DB, mirroring
    # the stripe_secret_key lock (the init_beanie call above
    # registers StripeSettings, which is not in the conftest
    # model set, so the row can be queried here).
    stored_role = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored_role is not None
    assert stored_role.permissions == [Permission.MANAGE_PAYMENTS_SETTINGS]
    stored_tenant = await Tenant.find_one(
        Tenant.id == PydanticObjectId("68c302ef6bf7a039b7e9b388")
    )
    assert stored_tenant is not None
    assert stored_tenant.features == [Feature(name=FeatureEnum.STRIPE, enabled=True)]
    assert await StripeSettings.find_one() is None
