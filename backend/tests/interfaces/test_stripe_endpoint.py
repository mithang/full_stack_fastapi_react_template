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
