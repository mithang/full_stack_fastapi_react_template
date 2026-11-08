import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_post_branding_with_missing_role_returns_404_with_cache_and_security_headers(client: AsyncClient):
    """
        The branding POST:
    """
    # The branding area had no interface test file at all, so
    # deleting the branding router from api/__init__.py — or dropping
    # the central ApiBaseException no-store lines or the
    # security-headers middleware registration — would previously
    # have gone uncaught here even though every other interface
    # area locks its headers in. Branding has no GET route (only
    # POST/PATCH/PUT), so the GET error-path pattern used by the
    # features/audit-logs/SSO/storage tests does not apply cleanly;
    # the POST error path below is the deterministic equivalent.
    # The success path is not asserted here: the POST is
    # permission-gated (FULL_ACCESS via a router-level dependency,
    # with no feature gate in front of it), so it needs a DB role
    # lookup, and the shared conftest client seeds no role. The
    # error path below is deterministic instead: the mocked host
    # user's role_id points at no row in the fresh test database
    # (Role is in the conftest model set), so the permission
    # dependency raises RoleNotFoundException before the handler
    # runs — which matters here because the handler's branding
    # service uses the Branding document, outside the conftest
    # model set, and would fail non-deterministically if reached.
    # The body is {} on purpose: every UpdateBrandingDto field is
    # optional, so body validation passes and cannot mask the 404.
    # That 404 must still carry the error-response headers:
    # branding carries contact info (PII), so a cached error
    # response could otherwise be served to a different admin
    # after an account switch on a shared machine.
    response = await client.post("/brandings/", json={})
    assert response.status_code == 404
    body = response.json()
    assert body["code"] == 404
    assert "Role" in body["error"]
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the storage test: the
    # pure-ASGI middleware stamps every HTTP response with no
    # path exclusions, so the branding POST 404 must carry the
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
    # the storage lock, using substring checks so later additions
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
async def test_patch_branding_with_missing_role_returns_404_with_cache_and_security_headers(client: AsyncClient):
    """
        The branding PATCH (second-path lock, following the POST
        lock above):
    """
    # The POST test locks the branding area's error path, but a
    # second route could lose its router dependency (or gain a
    # handler change that runs before it) while the POST lock still
    # passes, so each route needs its own lock. PATCH is the
    # deterministic second route: it shares the router-level
    # FULL_ACCESS dependency with the POST (no feature gate in
    # front of it), and the dependency raises
    # RoleNotFoundException before the handler runs — which
    # matters here because the handler's branding service uses
    # the Branding document, outside the conftest model set, and
    # would fail non-deterministically if reached. The mocked
    # host user's role_id points at no row in the fresh test
    # database (Role is in the conftest model set). The body is
    # {} on purpose: every UpdateBrandingDto field is optional,
    # so body validation passes and cannot mask the 404, and the
    # branding_id path param is a plain string, so no path
    # validation can mask it either. PUT /logo was not chosen:
    # it takes a multipart file, not a JSON body, so its error
    # path is not the same deterministic shape. That 404 must
    # still carry the error-response headers: branding carries
    # contact info (PII), so a cached error response could
    # otherwise be served to a different admin after an account
    # switch on a shared machine.
    response = await client.patch("/brandings/68c302ef6bf7a039b7e9b387", json={})
    assert response.status_code == 404
    body = response.json()
    assert body["code"] == 404
    assert "Role" in body["error"]
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the POST test: the
    # pure-ASGI middleware stamps every HTTP response with no
    # path exclusions, so the branding PATCH 404 must carry the
    # same headers as the POST 404, including the
    # exception-handler responses.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the twelve most sensitive directives as disabled, mirroring
    # the POST lock, using substring checks so later additions
    # to the list do not break this test. Each directive is safe
    # to lock here for the same reasons as on the POST route:
    # the SPA has no camera, microphone, geolocation, payment,
    # clipboard-read, display-capture, fullscreen, motion-sensor,
    # compass, XR, or idle-detection flow (re-verified fresh this
    # run: zero case-insensitive idle matches across
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
async def test_put_branding_logo_with_missing_role_returns_404_with_cache_and_security_headers(client: AsyncClient):
    """
        The branding PUT /logo (third-path lock, completing the
        branding route set: POST, PATCH, PUT /logo):
    """
    # The PATCH test noted PUT /logo was not chosen then because
    # it takes a multipart file, not a JSON body — but that is
    # not a blocker once the file is valid: the request below
    # carries a real (tiny) PNG part, so multipart parsing cannot
    # 422-mask the error whichever order FastAPI resolves the
    # file param versus the router dependency. Either way the
    # outcome is the same 404: the router-level FULL_ACCESS
    # dependency raises RoleNotFoundException (the mocked host
    # user's role_id points at no row in the fresh test database;
    # Role is in the conftest model set) before the handler runs,
    # so no file reaches storage, no branding record is created
    # or updated, and no scope guard is ever evaluated. That
    # matters here because the handler's branding and file
    # services use documents outside the conftest model set and
    # would fail non-deterministically if reached. That 404 must
    # still carry the error-response headers: branding carries
    # contact info (PII), so a cached error response could
    # otherwise be served to a different admin after an account
    # switch on a shared machine.
    png_1x1 = (
        b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01"
        b"\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde\x00\x00"
        b"\x00\x0cIDATx\x9cc\xf8\x0f\x00\x00\x01\x01\x00\x05"
        b"\x18\xd8N\x00\x00\x00\x00IEND\xaeB`\x82"
    )
    response = await client.put(
        "/brandings/logo",
        files={"file": ("logo.png", png_1x1, "image/png")},
    )
    assert response.status_code == 404
    body = response.json()
    assert body["code"] == 404
    assert "Role" in body["error"]
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the POST/PATCH tests: the
    # pure-ASGI middleware stamps every HTTP response with no
    # path exclusions, so the branding PUT 404 must carry the
    # same headers as the POST/PATCH 404s, including the
    # exception-handler responses.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the twelve most sensitive directives as disabled, mirroring
    # the POST/PATCH locks, using substring checks so later
    # additions to the list do not break this test. Each directive
    # is safe to lock here for the same reasons as on the other
    # branding routes: the SPA has no camera, microphone,
    # geolocation, payment, clipboard-read, display-capture,
    # fullscreen, motion-sensor, compass, XR, or idle-detection
    # flow (re-verified fresh this run: zero case-insensitive
    # idle matches and zero IdleDetector/requestIdleCallback
    # matches across frontend/app/src).
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
async def test_post_branding_outside_tenant_scope_returns_406_with_cache_and_security_headers(client: AsyncClient):
    """
        The branding POST create-scope-guard error path:
    """
    # The branding POST create-scope-guard branch, not yet locked:
    # function-name grep count 0 for
    # post_branding_outside_tenant_scope (verified fresh this
    # run), and no test in this file asserts an error on POST
    # /brandings/ with an "outside your tenant's scope" message -
    # the locks cover only the missing-role 404s (POST, PATCH,
    # PUT /logo). Deleting _assert_create_scope
    # (branding_endpoint.py:36-51) would previously have gone
    # uncaught, and a tenant caller creating on the host DB (no
    # X-Tenant-ID/subdomain) could then permanently occupy the
    # host branding slot with a tenant-stamped record the host
    # could never replace - there is no branding delete endpoint
    # - and the host branding GET would then serve that tenant's
    # branding. The guard runs in the handler body, after the
    # router-level FULL_ACCESS permission dependency and only
    # when no branding record exists (get_branding() is None),
    # so the gate must be satisfied first and the handler must
    # be reachable: the shared conftest mock points at role id
    # 68c302ef6bf7a039b7e9b386 with no row in the fresh test
    # database, so that exact id is seeded here carrying
    # FULL_ACCESS, mirroring the users/billing scope-lock seed
    # precedent. get_role_by_id is called with no tenant filter
    # (user_access_management.py), and _caller_may_access
    # returns True when the caller tenant is None
    # (role_service.py:18-19), so the seeded row is visible
    # regardless of the caller's tenant scope, and FULL_ACCESS
    # in the role's permissions passes the router dependency
    # outright. The caller is then made tenant-scoped by
    # swapping in a per-test MeResponseDto override (tenant_id
    # set), mirroring the users/billing scope locks' override
    # pattern, and restored in finally so no other test's mock
    # is affected. With no X-Tenant-ID header the tenant
    # middleware resolves host scope, so request_tenant_id is
    # None and the guard raises before create_branding runs.
    # The handler calls branding_service.get_branding() before
    # the guard, and Branding is outside the conftest model set
    # (conftest.py:25), so the test initializes Branding on the
    # test DB first: init_beanie on the same URI/db name the
    # conftest fixture uses (mongodb://localhost:27012/test_db,
    # api_test_db). Verified against the beanie 2.2.0 Initializer
    # source that a second init_beanie call only initializes the
    # models passed to it, so the conftest models are untouched,
    # and the fresh test DB has no branding record, so
    # get_branding() returns None and the guard fires. The body
    # is {} on purpose: every UpdateBrandingDto field is
    # optional, so body validation passes and cannot mask the
    # error. Note the status is 406, not 403: BrandingException
    # subclasses InvalidOperationException
    # (exceptions.py:140-143), which the central ApiBaseException
    # handler maps to 406 (api/__init__.py:108-109), with
    # {"error": ..., "code": 406} and the no-store/Pragma error
    # headers; the message keeps the "Branding Error: " prefix,
    # so the assertion is a substring match. A future change
    # that drops the guard would break this lock while leaving
    # the branding POST 404 lock green, so the paths are locked
    # separately.
    from beanie import PydanticObjectId, init_beanie
    from pymongo import AsyncMongoClient

    from api import app
    from api.common.enums.gender import Gender
    from api.domain.dtos.auth_dto import MeResponseDto
    from api.domain.dtos.role_dto import RoleDto
    from api.domain.entities.branding import Branding
    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission
    from api.infrastructure.security.current_user import get_current_user

    mongo_client = AsyncMongoClient("mongodb://localhost:27012/test_db")
    await init_beanie(
        mongo_client["api_test_db"], document_models=[Branding]
    )

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Tenant branding caller",
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
                name="Tenant branding caller",
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
        response = await client.post("/brandings/", json={})
    finally:
        if original_override is None:
            app.dependency_overrides.pop(get_current_user, None)
        else:
            app.dependency_overrides[get_current_user] = original_override
    assert response.status_code == 406
    body = response.json()
    assert body["code"] == 406
    assert "outside your tenant's scope" in body["error"]
    assert "refresh_token" not in response.headers.get("set-cookie", "")
    # The 406 must still carry the error-response headers: the
    # handler sets no-store only on the success path, so on this
    # path they come from the central ApiBaseException handler,
    # and a cached 406 could otherwise be served to a different
    # user after an account switch on a shared machine.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the branding POST 404 test:
    # the pure-ASGI middleware stamps every HTTP response with
    # no path exclusions, so the branding 406 must carry the
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
    # mirroring the branding POST 404 lock, using substring
    # checks so later additions to the list do not break this
    # test. Each directive is safe to lock here for the same
    # reasons as on the other branding routes: the SPA has no
    # camera, microphone, geolocation, payment, clipboard-read,
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
    # Postconditions: the guard fires before create_branding
    # runs, so the request is side-effect free - the seeded role
    # is still there with its permission, and no branding record
    # exists in the test DB for the guard to have squatted.
    stored = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored is not None
    assert stored.permissions == [Permission.FULL_ACCESS]
    assert await Branding.find_one() is None
    await mongo_client.close()


@pytest.mark.asyncio
async def test_patch_branding_outside_tenant_scope_returns_406_with_cache_and_security_headers(client: AsyncClient):
    """
        The branding PATCH update-scope-guard error path:
    """
    # The branding PATCH update-scope-guard branch, not yet locked:
    # function-name grep count 0 for
    # patch_branding_outside_tenant_scope (verified fresh this
    # run), and no test in this file asserts an error on PATCH
    # /brandings/{id} with a "Branding not found." message for a
    # tenant caller - the locks cover only the missing-role 404s
    # (POST, PATCH, PUT /logo) and the POST create-scope 406
    # (previous run). PATCH shares no guard with POST: its
    # scope check lives in BrandingService.update_branding
    # (branding_service.py:87-88), which raises BrandingException
    # ("Branding not found.") when the existing singleton's stamp
    # is not the caller's tenant, before any write - and the
    # endpoint's own id-match guard (branding_endpoint.py:81-83)
    # runs before the service call, so the seeded record's id
    # must be the path id for the service check to be reached.
    # Deleting the service check would previously have gone
    # uncaught, and a tenant caller PATCHing on the host DB (no
    # X-Tenant-ID/subdomain) could then overwrite the host
    # branding with their own values - or, via another tenant's
    # X-Tenant-ID, that tenant's branding - since the repository
    # updates by id alone. The guard runs in the handler body,
    # after the router-level FULL_ACCESS permission dependency,
    # so the gate must be satisfied first and the handler must
    # be reachable: the shared conftest mock points at role id
    # 68c302ef6bf7a039b7e9b386 with no row in the fresh test
    # database, so that exact id is seeded here carrying
    # FULL_ACCESS, mirroring the POST scope-lock seed precedent.
    # get_role_by_id is called with no tenant filter
    # (user_access_management.py), and _caller_may_access
    # returns True when the caller tenant is None
    # (role_service.py:18-19), so the seeded row is visible
    # regardless of the caller's tenant scope, and FULL_ACCESS
    # in the role's permissions passes the router dependency
    # outright. The caller is then made tenant-scoped by
    # swapping in a per-test MeResponseDto override (tenant_id
    # 68c302ef6bf7a039b7e9b387), mirroring the POST scope lock's
    # override pattern, and restored in finally so no other
    # test's mock is affected. The seeded branding record is
    # stamped with a different tenant
    # (68c302ef6bf7a039b7e9b389), so claim_legacy does not apply
    # (stamp is not None) and _caller_may_access returns False
    # regardless of the request scope - no X-Tenant-ID header
    # is sent, so request_tenant_id is None and cannot claim
    # the record either. The handler calls
    # branding_service.get_branding() before the guard, and
    # Branding is outside the conftest model set
    # (conftest.py:25), so the test initializes Branding on the
    # test DB first: init_beanie on the same URI/db name the
    # conftest fixture uses (mongodb://localhost:27012/test_db,
    # api_test_db). Verified against the beanie 2.2.0 Initializer
    # source that a second init_beanie call only initializes the
    # models passed to it, so the conftest models are untouched,
    # and that re-initializing Branding (the POST scope lock
    # already does this in its own test) does not raise - the
    # fresh Initializer re-binds the same collection, and
    # creating the existing tenant_id index again is a no-op.
    # The seeded record has no logo_url, so get_branding()
    # never calls the file service, and the body is {} on
    # purpose: every UpdateBrandingDto field is optional, so
    # body validation passes and cannot mask the error. Note
    # the status is 406, not 403: BrandingException subclasses
    # InvalidOperationException (exceptions.py:140-143), which
    # the central ApiBaseException handler maps to 406
    # (api/__init__.py:108-109), with {"error": ..., "code":
    # 406} and the no-store/Pragma error headers; the message
    # keeps the "Branding Error: " prefix, so the assertion is
    # a substring match, and the same "Branding not found."
    # message is deliberately indistinguishable from an unknown
    # id, so a probe cannot tell a refused record from a
    # missing one. A future change that drops the service check
    # would break this lock while leaving the branding PATCH
    # 404 lock and the POST scope 406 lock green, so the paths
    # are locked separately.
    from beanie import PydanticObjectId, init_beanie
    from pymongo import AsyncMongoClient

    from api import app
    from api.common.enums.gender import Gender
    from api.domain.dtos.auth_dto import MeResponseDto
    from api.domain.dtos.role_dto import RoleDto
    from api.domain.entities.branding import Branding
    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission
    from api.infrastructure.security.current_user import get_current_user

    mongo_client = AsyncMongoClient("mongodb://localhost:27012/test_db")
    await init_beanie(
        mongo_client["api_test_db"], document_models=[Branding]
    )

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Tenant branding caller",
        description="Role carrying FULL_ACCESS for the mocked caller",
        permissions=[Permission.FULL_ACCESS],
    ).insert()

    await Branding(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b38a"),
        tenant_id=PydanticObjectId("68c302ef6bf7a039b7e9b389"),
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
                name="Tenant branding caller",
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
        response = await client.patch("/brandings/68c302ef6bf7a039b7e9b38a", json={})
    finally:
        if original_override is None:
            app.dependency_overrides.pop(get_current_user, None)
        else:
            app.dependency_overrides[get_current_user] = original_override
    assert response.status_code == 406
    body = response.json()
    assert body["code"] == 406
    assert "Branding not found." in body["error"]
    assert "refresh_token" not in response.headers.get("set-cookie", "")
    # The 406 must still carry the error-response headers: the
    # handler sets no-store only on the success path, so on this
    # path they come from the central ApiBaseException handler,
    # and a cached 406 could otherwise be served to a different
    # user after an account switch on a shared machine.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the branding POST scope test:
    # the pure-ASGI middleware stamps every HTTP response with
    # no path exclusions, so the branding 406 must carry the
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
    # mirroring the branding POST scope lock, using substring
    # checks so later additions to the list do not break this
    # test. Each directive is safe to lock here for the same
    # reasons as on the other branding routes: the SPA has no
    # camera, microphone, geolocation, payment, clipboard-read,
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
    # Postconditions: the guard fires before any write, so the
    # request is side-effect free - the seeded role is still
    # there with its permission, and the seeded branding record
    # is untouched: still stamped with the foreign tenant and
    # still carrying its default app name.
    stored_role = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored_role is not None
    assert stored_role.permissions == [Permission.FULL_ACCESS]
    stored = await Branding.find_one(
        Branding.id == PydanticObjectId("68c302ef6bf7a039b7e9b38a")
    )
    assert stored is not None
    assert stored.tenant_id == PydanticObjectId("68c302ef6bf7a039b7e9b389")
    assert stored.app_name == "SaaS Org"
    await mongo_client.close()


@pytest.mark.asyncio
async def test_put_branding_logo_outside_tenant_scope_returns_406_with_cache_and_security_headers(client: AsyncClient):
    """
        The branding PUT /logo update-scope pre-check error path:
    """
    # The branding PUT /logo update-scope pre-check branch, not
    # yet locked: function-name grep count 0 for
    # put_branding_logo_outside_tenant_scope (verified fresh
    # this run), and no test in this file asserts an error on
    # PUT /brandings/logo with a "Branding not found." message
    # for a tenant caller - the locks cover only the
    # missing-role 404s (POST, PATCH, PUT /logo), the POST
    # create-scope 406, and the PATCH update-scope 406. PUT
    # /logo shares no guard with PATCH: its scope check is the
    # endpoint-level pre-check in upload_logo
    # (branding_endpoint.py, update branch), which raises
    # BrandingException ("Branding not found.") when the
    # existing singleton's stamp is not the caller's tenant,
    # before any file reaches storage - and the service-level
    # check in BrandingService.update_branding is only a
    # backstop that runs after the upload. Deleting the
    # pre-check would previously have gone uncaught, and a
    # tenant caller PUTting a logo on the host DB (no
    # X-Tenant-ID/subdomain) would then leave their logo
    # orphaned in the current scope's storage before the
    # service check refused the update - or, via another
    # tenant's X-Tenant-ID, in that tenant's storage. The
    # pre-check runs in the handler body, after the
    # router-level FULL_ACCESS permission dependency and after
    # the size/empty/content-type validations, so the gate
    # must be satisfied first and the request must reach the
    # check: the shared conftest mock points at role id
    # 68c302ef6bf7a039b7e9b386 with no row in the fresh test
    # database, so that exact id is seeded here carrying
    # FULL_ACCESS, mirroring the POST/PATCH scope-lock seed
    # precedent. get_role_by_id is called with no tenant
    # filter (user_access_management.py), and
    # _caller_may_access returns True when the caller tenant
    # is None (role_service.py:18-19), so the seeded row is
    # visible regardless of the caller's tenant scope, and
    # FULL_ACCESS in the role's permissions passes the router
    # dependency outright. The caller is then made
    # tenant-scoped by swapping in a per-test MeResponseDto
    # override (tenant_id 68c302ef6bf7a039b7e9b387),
    # mirroring the POST/PATCH scope locks' override pattern,
    # and restored in finally so no other test's mock is
    # affected. The seeded branding record is stamped with a
    # different tenant (68c302ef6bf7a039b7e9b389), so
    # claim_legacy does not apply (stamp is not None) and the
    # pre-check refuses regardless of the request scope - no
    # X-Tenant-ID header is sent, so request_tenant_id is
    # None and cannot claim the record either. The handler
    # calls branding_service.get_branding() before the guard,
    # and Branding is outside the conftest model set
    # (conftest.py:25), so the test initializes Branding on
    # the test DB first: init_beanie on the same URI/db name
    # the conftest fixture uses (mongodb://localhost:27012/
    # test_db, api_test_db). Verified against the beanie
    # 2.2.0 Initializer source that a second init_beanie call
    # only initializes the models passed to it, so the
    # conftest models are untouched, and that re-initializing
    # Branding (the POST/PATCH scope locks already do this in
    # their own tests) does not raise - the fresh Initializer
    # re-binds the same collection, and creating the existing
    # tenant_id index again is a no-op. The request carries a
    # real (tiny) PNG part on purpose: the content-type check
    # runs before the scope pre-check, so an invalid type
    # would 406-mask with "Unsupported file type" instead of
    # reaching the guard, and multipart parsing must pass so
    # no 422 masks the error. The seeded record has no
    # logo_url, so get_branding() never calls the file
    # service. Note the status is 406, not 403:
    # BrandingException subclasses InvalidOperationException
    # (exceptions.py:140-143), which the central
    # ApiBaseException handler maps to 406
    # (api/__init__.py:108-109), with {"error": ..., "code":
    # 406} and the no-store/Pragma error headers; the message
    # keeps the "Branding Error: " prefix, so the assertion
    # is a substring match, and the same "Branding not
    # found." message is deliberately indistinguishable from
    # an unknown id, so a probe cannot tell a refused record
    # from a missing one. A future change that drops the
    # pre-check would break this lock while leaving the
    # branding PUT /logo 404 lock and the POST/PATCH scope
    # 406 locks green, so the paths are locked separately.
    from beanie import PydanticObjectId, init_beanie
    from pymongo import AsyncMongoClient

    from api import app
    from api.common.enums.gender import Gender
    from api.domain.dtos.auth_dto import MeResponseDto
    from api.domain.dtos.role_dto import RoleDto
    from api.domain.entities.branding import Branding
    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission
    from api.infrastructure.security.current_user import get_current_user

    mongo_client = AsyncMongoClient("mongodb://localhost:27012/test_db")
    await init_beanie(
        mongo_client["api_test_db"], document_models=[Branding]
    )

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Tenant branding caller",
        description="Role carrying FULL_ACCESS for the mocked caller",
        permissions=[Permission.FULL_ACCESS],
    ).insert()

    await Branding(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b38a"),
        tenant_id=PydanticObjectId("68c302ef6bf7a039b7e9b389"),
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
                name="Tenant branding caller",
                description="Role carrying FULL_ACCESS for the mocked caller",
                created_at="2024-10-01T00:00:00Z",
                updated_at="2024-10-01T00:00:00Z",
                permissions=[Permission.FULL_ACCESS],
            ),
            subscription=None,
        )

    original_override = app.dependency_overrides.get(get_current_user)
    app.dependency_overrides[get_current_user] = override_get_current_user_tenant_scoped
    png_1x1 = (
        b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01"
        b"\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde\x00\x00"
        b"\x00\x0cIDATx\x9cc\xf8\x0f\x00\x00\x01\x01\x00\x05"
        b"\x18\xd8N\x00\x00\x00\x00IEND\xaeB`\x82"
    )
    try:
        response = await client.put(
            "/brandings/logo",
            files={"file": ("logo.png", png_1x1, "image/png")},
        )
    finally:
        if original_override is None:
            app.dependency_overrides.pop(get_current_user, None)
        else:
            app.dependency_overrides[get_current_user] = original_override
    assert response.status_code == 406
    body = response.json()
    assert body["code"] == 406
    assert "Branding not found." in body["error"]
    assert "refresh_token" not in response.headers.get("set-cookie", "")
    # The 406 must still carry the error-response headers: the
    # handler sets no-store only on the success path, so on this
    # path they come from the central ApiBaseException handler,
    # and a cached 406 could otherwise be served to a different
    # user after an account switch on a shared machine.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the branding POST/PATCH
    # scope tests: the pure-ASGI middleware stamps every HTTP
    # response with no path exclusions, so the branding 406
    # must carry the same headers as the authenticated calls,
    # including the exception-handler responses.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened:
    # lock the twelve most sensitive directives as disabled,
    # mirroring the branding POST/PATCH scope locks, using
    # substring checks so later additions to the list do not
    # break this test. Each directive is safe to lock here for
    # the same reasons as on the other branding routes: the SPA
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
    # Postconditions: the guard fires before any upload, so the
    # request is side-effect free - the seeded role is still
    # there with its permission, and the seeded branding record
    # is untouched: still stamped with the foreign tenant, still
    # carrying its default app name, and still with no logo_url,
    # so no file was written to storage for the refused call.
    stored_role = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored_role is not None
    assert stored_role.permissions == [Permission.FULL_ACCESS]
    stored = await Branding.find_one(
        Branding.id == PydanticObjectId("68c302ef6bf7a039b7e9b38a")
    )
    assert stored is not None
    assert stored.tenant_id == PydanticObjectId("68c302ef6bf7a039b7e9b389")
    assert stored.app_name == "SaaS Org"
    assert stored.logo_url is None
    await mongo_client.close()


@pytest.mark.asyncio
async def test_put_branding_logo_with_malformed_azure_returns_502_with_cache_and_security_headers(client: AsyncClient):
    """
        The branding PUT /logo Azure 502 path:
    """
    # The branding PUT /logo Azure 502 branch, not yet locked:
    # function-name grep count 0 for
    # put_branding_logo_with_malformed_azure (verified fresh
    # this run), and no test in this file asserts a 502 at all
    # (grep count 0 for "502" across test_branding_endpoint.py).
    # The Azure 502 mapping is locked for the profile-image
    # read path and the profile-picture upload path in
    # test_user_endpoint.py, but PUT /brandings/logo reaches
    # the same fixed constructor through a different caller
    # (FileUpload.upload_file, file_upload.py:55), so a change
    # that drops the 502 mapping on the upload path - or that
    # lets the Azure constructor fall through to the SDK's bare
    # ValueError there - would break nothing in the user tests
    # while the logo upload 500s. The 502 here is deterministic
    # with no network and no live Azure call: the seeded
    # StorageSettings row enables AZURE_BLOB with a malformed
    # connection string ("not-a-connection-string", carrying no
    # key=value pairs, so the SDK's local connection-string
    # parser raises ValueError before any client construction
    # or HTTP request), and AzureBlobStorage.__init__
    # (azure_storage.py, fixed in the 23:33 run) maps that
    # ValueError to AzureBlobStorageException ("Azure Blob
    # Storage connection string is invalid.") before touching
    # the network. The handler chain is: the router-level
    # FULL_ACCESS permission dependency passes on the seeded
    # role (mirroring the PUT /logo 404/406 locks' seed - the
    # shared conftest mock points at role id
    # 68c302ef6bf7a039b7e9b386 with no row in the fresh test
    # database, so that exact id is seeded here carrying
    # FULL_ACCESS; get_role_by_id is called with no tenant
    # filter, and _caller_may_access returns True when the
    # caller tenant is None, so the seeded row is visible
    # regardless of scope), the size/empty/content-type
    # validations pass on the real (tiny) PNG part, so no 406
    # masks the error, branding_service.get_branding() finds
    # no record (Branding is outside the conftest model set,
    # so the test initializes it on the test DB first,
    # mirroring the PUT /logo 406 lock), and the host mock
    # (tenant_id None) passes _assert_create_scope, so the
    # request reaches file_service.upload_file ->
    # FileUpload.upload_file, which finds the enabled Azure row
    # and constructs AzureBlobStorage, which raises; the
    # upload try catches only StorageNotEnabledException, so
    # the exception propagates, and the central handler maps
    # AzureException to 502 (api/__init__.py:110-113) with
    # {"error": ..., "code": 502} and the no-store/Pragma error
    # headers. StorageSettings is outside the conftest model
    # set (conftest.py:25), so the test initializes it on the
    # test DB first: init_beanie on the same URI/db name the
    # conftest fixture uses (mongodb://localhost:27012/
    # test_db, api_test_db), in the same call as Branding,
    # mirroring the branding tests' second-init precedent and
    # the S3/Azure 502 locks. The 502 fires before
    # create_branding, so no branding record is created and no
    # file is written to storage. A future change that drops
    # the 502 mapping, or that lets the Azure constructor fall
    # through to the SDK's bare ValueError on this path, would
    # break this lock while leaving the profile-image 502
    # locks, the profile-picture upload 502 lock, and the
    # branding PUT /logo 404/406 locks green, so the paths are
    # locked separately.
    from beanie import PydanticObjectId, init_beanie
    from pymongo import AsyncMongoClient

    from api.domain.entities.branding import Branding
    from api.domain.entities.role import Role
    from api.domain.entities.storage_settings import StorageProvider, StorageSettings
    from api.domain.enum.permission import Permission

    mongo_client = AsyncMongoClient("mongodb://localhost:27012/test_db")
    await init_beanie(
        mongo_client["api_test_db"], document_models=[Branding, StorageSettings]
    )

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Branding logo storage caller",
        description="Role carrying FULL_ACCESS for the mocked caller",
        permissions=[Permission.FULL_ACCESS],
    ).insert()

    await StorageSettings(
        provider=StorageProvider.AZURE_BLOB,
        is_enabled=True,
        region="eu-central-1",
        azure_connection_string="not-a-connection-string",
        azure_container_name="test-container",
    ).insert()

    png_1x1 = (
        b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01"
        b"\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde\x00\x00"
        b"\x00\x0cIDATx\x9cc\xf8\x0f\x00\x00\x01\x01\x00\x05"
        b"\x18\xd8N\x00\x00\x00\x00IEND\xaeB`\x82"
    )
    response = await client.put(
        "/brandings/logo",
        files={"file": ("logo.png", png_1x1, "image/png")},
    )
    assert response.status_code == 502
    body = response.json()
    assert body["code"] == 502
    # AzureBlobStorageException prefixes its message ("Azure Blob
    # Storage Error: ..."), so assert on the fail-closed reason
    # itself.
    assert "Azure Blob Storage connection string is invalid." in body["error"]
    assert "Azure Blob Storage Error: " in body["error"]
    assert "refresh_token" not in response.headers.get("set-cookie", "")
    # The 502 must still carry the error-response headers: the
    # handler sets no-store only on the success path, so on this
    # path they come from the central ApiBaseException handler,
    # and a cached 502 could otherwise be served to a different
    # user after an account switch on a shared machine.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the branding PUT /logo
    # 404/406 tests: the pure-ASGI middleware stamps every HTTP
    # response with no path exclusions, so the branding 502
    # must carry the same headers as the authenticated calls,
    # including the exception-handler responses.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened:
    # lock the twelve most sensitive directives as disabled,
    # mirroring the branding PUT /logo 404/406 locks, using
    # substring checks so later additions to the list do not
    # break this test. Each directive is safe to lock here for
    # the same reasons as on the other branding routes: the SPA
    # has no camera, microphone, geolocation, payment,
    # clipboard-read, display-capture, fullscreen,
    # motion-sensor, compass, XR, or idle-detection flow
    # (verified by grep in the earlier sweeps and re-verified
    # fresh this run: zero case-insensitive idle matches and
    # zero IdleDetector/requestIdleCallback matches across
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
    # Postconditions: the 502 fires before create_branding, so
    # the request is side-effect free - the seeded role is still
    # there with its permission, the storage row is still the
    # enabled Azure row with the malformed connection string
    # (the constructor raises before any write or upload), and
    # no branding record was created.
    stored_role = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored_role is not None
    assert stored_role.permissions == [Permission.FULL_ACCESS]
    stored_settings = await StorageSettings.find_one(
        StorageSettings.is_enabled == True
    )
    assert stored_settings is not None
    assert stored_settings.provider == StorageProvider.AZURE_BLOB
    assert stored_settings.azure_connection_string == "not-a-connection-string"
    stored_branding = await Branding.find_one()
    assert stored_branding is None
    await mongo_client.close()


@pytest.mark.asyncio
async def test_put_branding_logo_with_blank_azure_returns_502_with_cache_and_security_headers(client: AsyncClient):
    """
        The branding PUT /logo Azure 502 path for a blank connection string:
    """
    # The branding PUT /logo Azure 502 branch for a blank connection
    # string, not yet locked: function-name grep count 0 for
    # put_branding_logo_with_blank_azure (verified fresh this
    # run), and the malformed-connection-string lock added in the
    # previous run covers only the SDK ValueError branch, not the
    # fail-closed blank branch. The Azure 502 mapping is locked
    # for the profile-image read path (blank and malformed) and
    # the profile-picture upload path (malformed) in
    # test_user_endpoint.py, but PUT /brandings/logo reaches the
    # same fixed constructor through a different caller
    # (FileUpload.upload_file, file_upload.py:55), so a change
    # that drops the blank fail-closed raise - or that lets a
    # blank connection string fall through to the SDK's bare
    # ValueError on this path - would break nothing in the user
    # tests while the logo upload 500s. The 502 here is
    # deterministic with no network and no live Azure call: the
    # seeded StorageSettings row enables AZURE_BLOB with a blank
    # connection string (\"\"), and AzureBlobStorage.__init__
    # (azure_storage.py:24-28) raises AzureBlobStorageException
    # (\"Azure Blob Storage connection string is not configured.\")
    # on the blank/whitespace check before touching the SDK or
    # the network. The handler chain is: the router-level
    # FULL_ACCESS permission dependency passes on the seeded
    # role (mirroring the PUT /logo 404/406 locks' seed - the
    # shared conftest mock points at role id
    # 68c302ef6bf7a039b7e9b386 with no row in the fresh test
    # database, so that exact id is seeded here carrying
    # FULL_ACCESS; get_role_by_id is called with no tenant
    # filter, and _caller_may_access returns True when the
    # caller tenant is None, so the seeded row is visible
    # regardless of scope), the size/empty/content-type
    # validations pass on the real (tiny) PNG part, so no 406
    # masks the error, branding_service.get_branding() finds
    # no record (Branding is outside the conftest model set,
    # so the test initializes it on the test DB first,
    # mirroring the PUT /logo 406 lock), and the host mock
    # (tenant_id None) passes _assert_create_scope, so the
    # request reaches file_service.upload_file ->
    # FileUpload.upload_file, which finds the enabled Azure row
    # and constructs AzureBlobStorage, which raises; the
    # upload try catches only StorageNotEnabledException, so
    # the exception propagates, and the central handler maps
    # AzureException to 502 (api/__init__.py:110-113) with
    # {\"error\": ..., \"code\": 502} and the no-store/Pragma error
    # headers. StorageSettings is outside the conftest model
    # set (conftest.py:25), so the test initializes it on the
    # test DB first: init_beanie on the same URI/db name the
    # conftest fixture uses (mongodb://localhost:27012/
    # test_db, api_test_db), in the same call as Branding,
    # mirroring the branding tests' second-init precedent and
    # the S3/Azure 502 locks. The 502 fires before
    # create_branding, so no branding record is created and no
    # file is written to storage. A future change that drops
    # the 502 mapping, or that lets the Azure constructor fall
    # through to the SDK's bare ValueError on this path, would
    # break this lock while leaving the profile-image 502
    # locks, the profile-picture upload 502 lock, the branding
    # PUT /logo 404/406 locks, and the branding PUT /logo
    # malformed-Azure 502 lock green, so the paths are locked
    # separately.
    from beanie import PydanticObjectId, init_beanie
    from pymongo import AsyncMongoClient

    from api.domain.entities.branding import Branding
    from api.domain.entities.role import Role
    from api.domain.entities.storage_settings import StorageProvider, StorageSettings
    from api.domain.enum.permission import Permission

    mongo_client = AsyncMongoClient("mongodb://localhost:27012/test_db")
    await init_beanie(
        mongo_client["api_test_db"], document_models=[Branding, StorageSettings]
    )

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Branding logo storage caller",
        description="Role carrying FULL_ACCESS for the mocked caller",
        permissions=[Permission.FULL_ACCESS],
    ).insert()

    await StorageSettings(
        provider=StorageProvider.AZURE_BLOB,
        is_enabled=True,
        region="eu-central-1",
        azure_connection_string="",
        azure_container_name="test-container",
    ).insert()

    png_1x1 = (
        b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01"
        b"\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde\x00\x00"
        b"\x00\x0cIDATx\x9cc\xf8\x0f\x00\x00\x01\x01\x00\x05"
        b"\x18\xd8N\x00\x00\x00\x00IEND\xaeB`\x82"
    )
    response = await client.put(
        "/brandings/logo",
        files={"file": ("logo.png", png_1x1, "image/png")},
    )
    assert response.status_code == 502
    body = response.json()
    assert body["code"] == 502
    # AzureBlobStorageException prefixes its message ("Azure Blob
    # Storage Error: ..."), so assert on the fail-closed reason
    # itself.
    assert "Azure Blob Storage connection string is not configured." in body["error"]
    assert "Azure Blob Storage Error: " in body["error"]
    assert "refresh_token" not in response.headers.get("set-cookie", "")
    # The 502 must still carry the error-response headers: the
    # handler sets no-store only on the success path, so on this
    # path they come from the central ApiBaseException handler,
    # and a cached 502 could otherwise be served to a different
    # user after an account switch on a shared machine.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the branding PUT /logo
    # 404/406 tests: the pure-ASGI middleware stamps every HTTP
    # response with no path exclusions, so the branding 502
    # must carry the same headers as the authenticated calls,
    # including the exception-handler responses.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened:
    # lock the twelve most sensitive directives as disabled,
    # mirroring the branding PUT /logo 404/406 locks, using
    # substring checks so later additions to the list do not
    # break this test. Each directive is safe to lock here for
    # the same reasons as on the other branding routes: the SPA
    # has no camera, microphone, geolocation, payment,
    # clipboard-read, display-capture, fullscreen,
    # motion-sensor, compass, XR, or idle-detection flow
    # (verified by grep in the earlier sweeps and re-verified
    # fresh this run: zero case-insensitive idle matches and
    # zero IdleDetector/requestIdleCallback matches across
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
    # Postconditions: the 502 fires before create_branding, so
    # the request is side-effect free - the seeded role is still
    # there with its permission, the storage row is still the
    # enabled Azure row with the blank connection string
    # (the constructor raises before any write or upload), and
    # no branding record was created.
    stored_role = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored_role is not None
    assert stored_role.permissions == [Permission.FULL_ACCESS]
    stored_settings = await StorageSettings.find_one(
        StorageSettings.is_enabled == True
    )
    assert stored_settings is not None
    assert stored_settings.provider == StorageProvider.AZURE_BLOB
    assert stored_settings.azure_connection_string == ""
    stored_branding = await Branding.find_one()
    assert stored_branding is None
    await mongo_client.close()


async def test_put_branding_logo_with_unconfigured_s3_returns_502_with_cache_and_security_headers(client: AsyncClient):
    """
        The branding PUT /logo S3 502 path for unconfigured S3
        credentials:
    """
    # The branding PUT /logo S3 502 branch for blank credentials,
    # not yet locked: function-name grep count 0 for
    # put_branding_logo_with_unconfigured_s3 (verified fresh this
    # run; the S3 502 case is locked only for the profile-image
    # GET read path and the profile-picture upload path in
    # test_user_endpoint.py). The Azure upload locks cover the
    # same FileUpload.upload_file call with the other provider
    # branch, but the S3 branch constructs a different storage
    # class, so deleting the fail-closed blank-key raise in
    # S3Storage.__init__ would previously have gone uncaught on
    # this path - boto3 would silently resolve ambient
    # credentials (env vars, shared config, IAM role) and upload
    # the logo to the tenant bucket under the deployment's
    # credentials, hiding a misconfiguration from the client
    # fallbacks that only trigger on rejection. The 502 here is
    # deterministic with no network and no live S3 call: the
    # blank check runs before any boto3 client construction or
    # HTTP request (s3_storage.py), so no credential resolution,
    # signing, or request happens. The handler chain is: the
    # router-level FULL_ACCESS permission dependency passes on
    # the seeded role (mirroring the PUT /logo 404/406 locks'
    # seed - the shared conftest mock points at role id
    # 68c302ef6bf7a039b7e9b386 with no row in the fresh test
    # database, so that exact id is seeded here carrying
    # FULL_ACCESS; get_role_by_id is called with no tenant
    # filter, and _caller_may_access returns True when the
    # caller tenant is None, so the seeded row is visible
    # regardless of scope), the size/empty/content-type
    # validations pass on the real (tiny) PNG part, so no 406
    # masks the error, branding_service.get_branding() finds
    # no record (Branding is outside the conftest model set,
    # so the test initializes it on the test DB first,
    # mirroring the PUT /logo 406 lock), and the host mock
    # (tenant_id None) passes _assert_create_scope, so the
    # request reaches file_service.upload_file ->
    # FileUpload.upload_file, which finds the enabled S3 row
    # and constructs S3Storage, which raises; the upload try
    # catches only StorageNotEnabledException, so the exception
    # propagates, and the central handler maps AwsException to
    # 502 (api/__init__.py:110-117) with {"error": ..., "code":
    # 502} and the no-store/Pragma error headers.
    # StorageSettings is outside the conftest model set
    # (conftest.py:25), so the test initializes it on the test
    # DB first: init_beanie on the same URI/db name the
    # conftest fixture uses (mongodb://localhost:27012/
    # test_db, api_test_db), in the same call as Branding,
    # mirroring the branding tests' second-init precedent and
    # the S3/Azure 502 locks. The 502 fires before
    # create_branding, so no branding record is created and no
    # file is written to storage. A future change that drops
    # the blank fail-closed raise, or that lets blank S3 keys
    # fall through to ambient boto3 credentials on this path,
    # would break this lock while leaving the profile-image S3
    # 502 lock, the profile-picture upload S3 502 lock, the
    # branding PUT /logo 404/406 locks, and the branding PUT
    # /logo Azure 502 locks green, so the paths are locked
    # separately.
    from beanie import PydanticObjectId, init_beanie
    from pymongo import AsyncMongoClient

    from api.domain.entities.branding import Branding
    from api.domain.entities.role import Role
    from api.domain.entities.storage_settings import StorageProvider, StorageSettings
    from api.domain.enum.permission import Permission

    mongo_client = AsyncMongoClient("mongodb://localhost:27012/test_db")
    await init_beanie(
        mongo_client["api_test_db"], document_models=[Branding, StorageSettings]
    )

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Branding logo storage caller",
        description="Role carrying FULL_ACCESS for the mocked caller",
        permissions=[Permission.FULL_ACCESS],
    ).insert()

    await StorageSettings(
        provider=StorageProvider.AWS_S3,
        is_enabled=True,
        region="eu-central-1",
        aws_access_key="",
        aws_secret_key="",
        aws_bucket_name="test-bucket",
    ).insert()

    png_1x1 = (
        b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01"
        b"\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde\x00\x00"
        b"\x00\x0cIDATx\x9cc\xf8\x0f\x00\x00\x01\x01\x00\x05"
        b"\x18\xd8N\x00\x00\x00\x00IEND\xaeB`\x82"
    )
    response = await client.put(
        "/brandings/logo",
        files={"file": ("logo.png", png_1x1, "image/png")},
    )
    assert response.status_code == 502
    body = response.json()
    assert body["code"] == 502
    # S3StorageException prefixes its message ("S3 Storage Error:
    # ..."), so assert on the fail-closed reason itself.
    assert "S3 storage credentials are not configured." in body["error"]
    assert "S3 Storage Error: " in body["error"]
    assert "refresh_token" not in response.headers.get("set-cookie", "")
    # The 502 must still carry the error-response headers: the
    # handler sets no-store only on the success path, so on this
    # path they come from the central ApiBaseException handler,
    # and a cached 502 could otherwise be served to a different
    # user after an account switch on a shared machine.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the branding PUT /logo
    # 404/406 tests: the pure-ASGI middleware stamps every HTTP
    # response with no path exclusions, so the branding 502
    # must carry the same headers as the authenticated calls,
    # including the exception-handler responses.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened:
    # lock the twelve most sensitive directives as disabled,
    # mirroring the branding PUT /logo 404/406 locks, using
    # substring checks so later additions to the list do not
    # break this test. Each directive is safe to lock here for
    # the same reasons as on the other branding routes: the SPA
    # has no camera, microphone, geolocation, payment,
    # clipboard-read, display-capture, fullscreen,
    # motion-sensor, compass, XR, or idle-detection flow
    # (verified by grep in the earlier sweeps and re-verified
    # fresh this run: zero case-insensitive idle matches and
    # zero IdleDetector/requestIdleCallback matches across
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
    # Postconditions: the 502 fires before create_branding, so
    # the request is side-effect free - the seeded role is still
    # there with its permission, the storage row is still the
    # enabled S3 row with blank keys and bucket "test-bucket"
    # (the constructor raises before any write or upload), and
    # no branding record was created.
    stored_role = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored_role is not None
    assert stored_role.permissions == [Permission.FULL_ACCESS]
    stored_settings = await StorageSettings.find_one(
        StorageSettings.is_enabled == True
    )
    assert stored_settings is not None
    assert stored_settings.provider == StorageProvider.AWS_S3
    assert stored_settings.aws_access_key == ""
    assert stored_settings.aws_secret_key == ""
    assert stored_settings.aws_bucket_name == "test-bucket"
    stored_branding = await Branding.find_one()
    assert stored_branding is None
    await mongo_client.close()


@pytest.mark.asyncio
async def test_create_branding_non_string_tenant_id_returns_422_with_security_headers(client: AsyncClient):
    """
    The branding POST with a non-string `tenant_id` (a JSON
    list): `tenant_id` is an `Optional[str]` field of
    UpdateBrandingDto, which the POST /brandings/ endpoint
    takes as its body, and Pydantic v2 does not coerce lists
    to str, so request validation rejects the body with 422
    before the handler body runs.
    """
    # Function-name grep count 0 for
    # create_branding_non_string_tenant_id before appending,
    # verified fresh this run, not assumed. This is the FIRST
    # lock of the branding per-field validation sweep:
    # UpdateBrandingDto has six fields (identity,
    # contact_info, theme_config, tenant_id, logo_url,
    # logo_type); this run locks tenant_id, so five remain
    # for future runs. The other fields are omitted
    # (all optional) -- nothing else can mask the 422. A
    # list is used as the non-string payload because
    # Pydantic v2 lax mode has no list-to-str coercion
    # path, and a blank string would pin the blank-value
    # class, not the non-string class. Note tenant_id is
    # Optional[str] with default None, so None is a valid
    # value -- only the non-string type is locked here.
    # Verified from
    # backend/api/domain/dtos/branding_dto.py that
    # UpdateBrandingDto carries no model_validator of its
    # own (the normalize_app_name validator lives on the
    # nested IdentityDto and only runs when identity is
    # present), so no validator can mask the 422; verified
    # from backend/api/interfaces/api_controllers/
    # branding_endpoint.py that the handler reads
    # data.tenant_id only inside the handler body, after
    # validation, and the _assert_create_scope guard also
    # runs inside the handler body, so neither can mask
    # the 422. The POST carries a router-level FULL_ACCESS
    # permission dependency (a parameter dependency, solved
    # before the endpoint's own body is validated), so the
    # caller role must carry FULL_ACCESS -- otherwise the
    # permission 404 would mask the 422, exactly as in the
    # notification banner locks. The Role row (id
    # 68c302ef6bf7a039b7e9b386) is seeded for that
    # dependency, mirroring the branding scope locks: the
    # dependency looks the role up by the mocked caller's
    # role_id (user_access_management.py get_role_detail),
    # so the default host caller needs no override -- the
    # host scope (no X-Tenant-ID header) is legitimate
    # here because validation fails before the handler's
    # create-scope guard ever runs. Deliberately no exact
    # error-type assertion, mirroring the checkout
    # non-string email 422 lock. Deliberately no
    # Cache-Control/Pragma assertion: a 422 is FastAPI
    # request validation, not an ApiBaseException, so the
    # central handler's no-store headers do not apply to
    # it, mirroring the billing 422 locks. The security
    # headers ARE locked: the pure-ASGI middleware stamps
    # every HTTP response, including validation errors,
    # with no path exclusions.
    from beanie import PydanticObjectId, init_beanie
    from pymongo import AsyncMongoClient

    from api.domain.entities.branding import Branding
    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission

    mongo_client = AsyncMongoClient("mongodb://localhost:27012/test_db")
    await init_beanie(
        mongo_client["api_test_db"], document_models=[Branding]
    )

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Branding administrator",
        description="Role carrying FULL_ACCESS for the mocked caller",
        permissions=[Permission.FULL_ACCESS],
    ).insert()

    response = await client.post(
        "/brandings/",
        json={
            "tenant_id": ["68c302ef6bf7a039b7e9b387"],
        },
    )
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
    # mirroring the branding POST 404 lock, using substring
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
    # runs, so no branding service call is made and no
    # record is created -- the seeded role is still there
    # with FULL_ACCESS and no branding record exists in
    # the test DB, mirroring the branding scope locks (the
    # init_beanie call above registers Branding, which is
    # not in the conftest model set, so the row can be
    # queried here).
    stored_role = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored_role is not None
    assert stored_role.permissions == [Permission.FULL_ACCESS]
    assert await Branding.find_one() is None
    await mongo_client.close()


@pytest.mark.asyncio
async def test_create_branding_non_string_identity_returns_422_with_security_headers(client: AsyncClient):
    """
    The branding POST with a non-string `identity` (a JSON
    list): `identity` is an `Optional[IdentityDto]` field of
    UpdateBrandingDto, which the POST /brandings/ endpoint
    takes as its body, and Pydantic v2 does not coerce lists
    to a model, so request validation rejects the body with
    422 before the handler body runs.
    """
    # Function-name grep count 0 for
    # create_branding_non_string_identity before appending,
    # verified fresh this run, not assumed. This is the
    # SECOND lock of the branding per-field validation
    # sweep: UpdateBrandingDto has six fields (identity,
    # contact_info, theme_config, tenant_id, logo_url,
    # logo_type); tenant_id was locked in the previous run,
    # so this run locks identity and four remain for future
    # runs. The other fields are omitted (all optional) --
    # nothing else can mask the 422. A list is used as the
    # non-string payload because Pydantic v2 lax mode has
    # no list-to-model coercion path, and a blank string
    # would pin the blank-value class, not the non-string
    # class. Note identity is Optional[IdentityDto] with
    # default None, so None is a valid value -- only the
    # non-string type is locked here. Verified from
    # backend/api/domain/dtos/branding_dto.py that
    # IdentityDto's normalize_app_name model_validator runs
    # mode="after", i.e. only once a dict has been validated
    # into an IdentityDto, so it cannot mask the 422 for a
    # list payload; verified from
    # backend/api/interfaces/api_controllers/
    # branding_endpoint.py that the handler reads
    # data.identity only inside the handler body, after
    # validation, and the _assert_create_scope guard also
    # runs inside the handler body, so neither can mask
    # the 422. The POST carries a router-level FULL_ACCESS
    # permission dependency (a parameter dependency, solved
    # before the endpoint's own body is validated), so the
    # caller role must carry FULL_ACCESS -- otherwise the
    # permission 404 would mask the 422, exactly as in the
    # notification banner locks. The Role row (id
    # 68c302ef6bf7a039b7e9b386) is seeded for that
    # dependency, mirroring the branding scope locks: the
    # dependency looks the role up by the mocked caller's
    # role_id (user_access_management.py get_role_detail),
    # so the default host caller needs no override -- the
    # host scope (no X-Tenant-ID header) is legitimate
    # here because validation fails before the handler's
    # create-scope guard ever runs. Deliberately no exact
    # error-type assertion, mirroring the checkout
    # non-string email 422 lock. Deliberately no
    # Cache-Control/Pragma assertion: a 422 is FastAPI
    # request validation, not an ApiBaseException, so the
    # central handler's no-store headers do not apply to
    # it, mirroring the billing 422 locks. The security
    # headers ARE locked: the pure-ASGI middleware stamps
    # every HTTP response, including validation errors,
    # with no path exclusions.
    from beanie import PydanticObjectId, init_beanie
    from pymongo import AsyncMongoClient

    from api.domain.entities.branding import Branding
    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission

    mongo_client = AsyncMongoClient("mongodb://localhost:27012/test_db")
    await init_beanie(
        mongo_client["api_test_db"], document_models=[Branding]
    )

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Branding administrator",
        description="Role carrying FULL_ACCESS for the mocked caller",
        permissions=[Permission.FULL_ACCESS],
    ).insert()

    response = await client.post(
        "/brandings/",
        json={
            "identity": ["Acme Corp"],
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "identity" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the branding POST 404 lock, using substring
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
    # runs, so no branding service call is made and no
    # record is created -- the seeded role is still there
    # with FULL_ACCESS and no branding record exists in
    # the test DB, mirroring the branding scope locks (the
    # init_beanie call above registers Branding, which is
    # not in the conftest model set, so the row can be
    # queried here).
    stored_role = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored_role is not None
    assert stored_role.permissions == [Permission.FULL_ACCESS]
    assert await Branding.find_one() is None
    await mongo_client.close()


async def test_create_branding_non_string_contact_info_returns_422_with_security_headers(client: AsyncClient):
    """
    The branding POST with a non-string `contact_info` (a JSON
    list): `contact_info` is an `Optional[ContactInfo]` field of
    UpdateBrandingDto, which the POST /brandings/ endpoint
    takes as its body, and Pydantic v2 does not coerce lists
    to a model, so request validation rejects the body with
    422 before the handler body runs.
    """
    # Function-name grep count 0 for
    # create_branding_non_string_contact_info before appending,
    # verified fresh this run, not assumed. This is the
    # THIRD lock of the branding per-field validation
    # sweep: UpdateBrandingDto has six fields (identity,
    # contact_info, theme_config, tenant_id, logo_url,
    # logo_type); tenant_id and identity were locked in the
    # previous two runs, so this run locks contact_info and
    # three remain for future runs. The other fields are
    # omitted (all optional) -- nothing else can mask the
    # 422. A list is used as the non-string payload because
    # Pydantic v2 lax mode has no list-to-model coercion
    # path, and a blank string would pin the blank-value
    # class, not the non-string class. Note contact_info is
    # Optional[ContactInfo] with default None, so None is a
    # valid value -- only the non-string type is locked
    # here. Verified from
    # backend/api/domain/entities/branding.py that
    # ContactInfo's normalize_phone_address model_validator
    # runs mode="after", i.e. only once a dict has been
    # validated into a ContactInfo, so it cannot mask the
    # 422 for a list payload; verified from
    # backend/api/interfaces/api_controllers/
    # branding_endpoint.py that the POST takes
    # UpdateBrandingDto as its body (line 50) under the
    # router-level FULL_ACCESS dependency (line 24), and the
    # handler reads data.contact_info only inside the
    # handler body, after validation, and the
    # _assert_create_scope guard also runs inside the
    # handler body, so neither can mask the 422. The POST
    # carries a router-level FULL_ACCESS permission
    # dependency (a parameter dependency, solved before the
    # endpoint's own body is validated), so the caller role
    # must carry FULL_ACCESS -- otherwise the permission
    # 404 would mask the 422, exactly as in the
    # notification banner locks. The Role row (id
    # 68c302ef6bf7a039b7e9b386) is seeded for that
    # dependency, mirroring the branding scope locks: the
    # dependency looks the role up by the mocked caller's
    # role_id (user_access_management.py get_role_detail),
    # so the default host caller needs no override -- the
    # host scope (no X-Tenant-ID header) is legitimate
    # here because validation fails before the handler's
    # create-scope guard ever runs. Deliberately no exact
    # error-type assertion, mirroring the checkout
    # non-string email 422 lock. Deliberately no
    # Cache-Control/Pragma assertion: a 422 is FastAPI
    # request validation, not an ApiBaseException, so the
    # central handler's no-store headers do not apply to
    # it, mirroring the billing 422 locks. The security
    # headers ARE locked: the pure-ASGI middleware stamps
    # every HTTP response, including validation errors,
    # with no path exclusions.
    from beanie import PydanticObjectId, init_beanie
    from pymongo import AsyncMongoClient

    from api.domain.entities.branding import Branding
    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission

    mongo_client = AsyncMongoClient("mongodb://localhost:27012/test_db")
    await init_beanie(
        mongo_client["api_test_db"], document_models=[Branding]
    )

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Branding administrator",
        description="Role carrying FULL_ACCESS for the mocked caller",
        permissions=[Permission.FULL_ACCESS],
    ).insert()

    response = await client.post(
        "/brandings/",
        json={
            "contact_info": ["support@example.com"],
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "contact_info" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the branding POST 404 lock, using substring
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
    # runs, so no branding service call is made and no
    # record is created -- the seeded role is still there
    # with FULL_ACCESS and no branding record exists in
    # the test DB, mirroring the branding scope locks (the
    # init_beanie call above registers Branding, which is
    # not in the conftest model set, so the row can be
    # queried here).
    stored_role = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored_role is not None
    assert stored_role.permissions == [Permission.FULL_ACCESS]
    assert await Branding.find_one() is None
    await mongo_client.close()


async def test_create_branding_non_string_theme_config_returns_422_with_security_headers(client: AsyncClient):
    """
    The branding POST with a non-string `theme_config` (a JSON
    list): `theme_config` is an `Optional[ThemeConfig]` field of
    UpdateBrandingDto, which the POST /brandings/ endpoint
    takes as its body, and Pydantic v2 does not coerce lists
    to a model, so request validation rejects the body with
    422 before the handler body runs.
    """
    # Function-name grep count 0 for
    # create_branding_non_string_theme_config before appending,
    # verified fresh this run, not assumed. This is the
    # FOURTH lock of the branding per-field validation
    # sweep: UpdateBrandingDto has six fields (identity,
    # contact_info, theme_config, tenant_id, logo_url,
    # logo_type); tenant_id, identity and contact_info were
    # locked in the previous three runs, so this run locks
    # theme_config and two remain for future runs. The other
    # fields are omitted (all optional) -- nothing else can
    # mask the 422. A list is used as the non-string payload
    # because Pydantic v2 lax mode has no list-to-model
    # coercion path, and a blank string would pin the
    # blank-value class, not the non-string class. Note
    # theme_config is Optional[ThemeConfig] with default
    # None, so None is a valid value -- only the non-string
    # type is locked here. Verified from
    # backend/api/domain/entities/branding.py that
    # ThemeConfig carries no model_validator at all (only
    # plain fields radius/light/dark), so nothing can mask
    # the 422 for a list payload; verified from
    # backend/api/interfaces/api_controllers/
    # branding_endpoint.py that the POST takes
    # UpdateBrandingDto as its body (line 50) under the
    # router-level FULL_ACCESS dependency (line 24), and the
    # handler reads data.theme_config only inside the
    # handler body, after validation, and the
    # _assert_create_scope guard also runs inside the
    # handler body, so neither can mask the 422. The POST
    # carries a router-level FULL_ACCESS permission
    # dependency (a parameter dependency, solved before the
    # endpoint's own body is validated), so the caller role
    # must carry FULL_ACCESS -- otherwise the permission
    # 404 would mask the 422, exactly as in the
    # notification banner locks. The Role row (id
    # 68c302ef6bf7a039b7e9b386) is seeded for that
    # dependency, mirroring the branding scope locks: the
    # dependency looks the role up by the mocked caller's
    # role_id (user_access_management.py get_role_detail),
    # so the default host caller needs no override -- the
    # host scope (no X-Tenant-ID header) is legitimate
    # here because validation fails before the handler's
    # create-scope guard ever runs. Deliberately no exact
    # error-type assertion, mirroring the checkout
    # non-string email 422 lock. Deliberately no
    # Cache-Control/Pragma assertion: a 422 is FastAPI
    # request validation, not an ApiBaseException, so the
    # central handler's no-store headers do not apply to
    # it, mirroring the billing 422 locks. The security
    # headers ARE locked: the pure-ASGI middleware stamps
    # every HTTP response, including validation errors,
    # with no path exclusions.
    from beanie import PydanticObjectId, init_beanie
    from pymongo import AsyncMongoClient

    from api.domain.entities.branding import Branding
    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission

    mongo_client = AsyncMongoClient("mongodb://localhost:27012/test_db")
    await init_beanie(
        mongo_client["api_test_db"], document_models=[Branding]
    )

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Branding administrator",
        description="Role carrying FULL_ACCESS for the mocked caller",
        permissions=[Permission.FULL_ACCESS],
    ).insert()

    response = await client.post(
        "/brandings/",
        json={
            "theme_config": ["dark"],
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "theme_config" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the branding POST 404 lock, using substring
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
    # runs, so no branding service call is made and no
    # record is created -- the seeded role is still there
    # with FULL_ACCESS and no branding record exists in
    # the test DB, mirroring the branding scope locks (the
    # init_beanie call above registers Branding, which is
    # not in the conftest model set, so the row can be
    # queried here).
    stored_role = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored_role is not None
    assert stored_role.permissions == [Permission.FULL_ACCESS]
    assert await Branding.find_one() is None
    await mongo_client.close()


async def test_create_branding_non_string_logo_url_returns_422_with_security_headers(client: AsyncClient):
    """
    The branding POST with a non-string `logo_url` (a JSON
    list): `logo_url` is an `Optional[str]` field of
    UpdateBrandingDto, which the POST /brandings/ endpoint
    takes as its body, and Pydantic v2 does not coerce lists
    to a string, so request validation rejects the body with
    422 before the handler body runs.
    """
    # Function-name grep count 0 for
    # create_branding_non_string_logo_url before appending,
    # verified fresh this run, not assumed. This is the
    # FIFTH lock of the branding per-field validation
    # sweep: UpdateBrandingDto has six fields (identity,
    # contact_info, theme_config, tenant_id, logo_url,
    # logo_type); tenant_id, identity, contact_info and
    # theme_config were locked in the previous four runs,
    # so this run locks logo_url and one remains
    # (logo_type) for a future run. The other fields are
    # omitted (all optional) -- nothing else can mask the
    # 422. A list is used as the non-string payload
    # because Pydantic v2 lax mode has no list-to-string
    # coercion path, and a blank string would pin the
    # blank-value class, not the non-string class. Note
    # logo_url is Optional[str] with default None, so None
    # is a valid value -- only the non-string type is
    # locked here. Verified from
    # backend/api/domain/dtos/branding_dto.py that
    # UpdateBrandingDto carries no model_validator at all
    # (only plain optional fields), so nothing can mask
    # the 422 for a list payload; verified from
    # backend/api/interfaces/api_controllers/
    # branding_endpoint.py that the POST takes
    # UpdateBrandingDto as its body (line 50) under the
    # router-level FULL_ACCESS dependency (line 24), and
    # the handler reads data.logo_url only inside the
    # handler body, after validation, and the
    # _assert_create_scope guard also runs inside the
    # handler body, so neither can mask the 422. The POST
    # carries a router-level FULL_ACCESS permission
    # dependency (a parameter dependency, solved before the
    # endpoint's own body is validated), so the caller role
    # must carry FULL_ACCESS -- otherwise the permission
    # 404 would mask the 422, exactly as in the
    # notification banner locks. The Role row (id
    # 68c302ef6bf7a039b7e9b386) is seeded for that
    # dependency, mirroring the branding scope locks: the
    # dependency looks the role up by the mocked caller's
    # role_id (user_access_management.py get_role_detail),
    # so the default host caller needs no override -- the
    # host scope (no X-Tenant-ID header) is legitimate
    # here because validation fails before the handler's
    # create-scope guard ever runs. Deliberately no exact
    # error-type assertion, mirroring the checkout
    # non-string email 422 lock. Deliberately no
    # Cache-Control/Pragma assertion: a 422 is FastAPI
    # request validation, not an ApiBaseException, so the
    # central handler's no-store headers do not apply to
    # it, mirroring the billing 422 locks. The security
    # headers ARE locked: the pure-ASGI middleware stamps
    # every HTTP response, including validation errors,
    # with no path exclusions.
    from beanie import PydanticObjectId, init_beanie
    from pymongo import AsyncMongoClient

    from api.domain.entities.branding import Branding
    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission

    mongo_client = AsyncMongoClient("mongodb://localhost:27012/test_db")
    await init_beanie(
        mongo_client["api_test_db"], document_models=[Branding]
    )

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Branding administrator",
        description="Role carrying FULL_ACCESS for the mocked caller",
        permissions=[Permission.FULL_ACCESS],
    ).insert()

    response = await client.post(
        "/brandings/",
        json={
            "logo_url": ["https://example.com/logo.png"],
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "logo_url" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the branding POST 404 lock, using substring
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
    # runs, so no branding service call is made and no
    # record is created -- the seeded role is still there
    # with FULL_ACCESS and no branding record exists in
    # the test DB, mirroring the branding scope locks (the
    # init_beanie call above registers Branding, which is
    # not in the conftest model set, so the row can be
    # queried here).
    stored_role = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored_role is not None
    assert stored_role.permissions == [Permission.FULL_ACCESS]
    assert await Branding.find_one() is None
    await mongo_client.close()


async def test_create_branding_non_string_logo_type_returns_422_with_security_headers(client: AsyncClient):
    """
    The branding POST with a non-string `logo_type` (a JSON
    list): `logo_type` is an `Optional[LogoType]` field of
    UpdateBrandingDto, which the POST /brandings/ endpoint
    takes as its body, where LogoType is the literal
    ("image/jpeg", "image/png"), and Pydantic v2 does not
    coerce lists to a literal member, so request validation
    rejects the body with 422 before the handler body runs.
    """
    # Function-name grep count 0 for
    # create_branding_non_string_logo_type before appending,
    # verified fresh this run, not assumed. This is the
    # SIXTH and FINAL lock of the branding per-field
    # validation sweep: UpdateBrandingDto has six fields
    # (identity, contact_info, theme_config, tenant_id,
    # logo_url, logo_type); tenant_id, identity,
    # contact_info, theme_config and logo_url were locked
    # in the previous five runs, so this run locks
    # logo_type and the sweep is now COMPLETE. The other
    # fields are omitted (all optional) -- nothing else
    # can mask the 422. A list is used as the non-string
    # payload because Pydantic v2 lax mode has no
    # list-to-literal coercion path, and a string outside
    # the literal (e.g. "image/gif") would pin the
    # invalid-value class, not the non-string class. Note
    # logo_type is Optional[LogoType] with default None,
    # so None is a valid value -- only the non-string
    # type is locked here. Verified from
    # backend/api/domain/dtos/branding_dto.py that
    # UpdateBrandingDto carries no model_validator at all
    # (only plain optional fields; the IdentityDto
    # validator is irrelevant because identity is omitted
    # here), so nothing can mask the 422 for a list
    # payload; verified from
    # backend/api/domain/entities/branding.py (line 108)
    # that LogoType is Literal["image/jpeg",
    # "image/png"]; verified from
    # backend/api/interfaces/api_controllers/
    # branding_endpoint.py that the POST takes
    # UpdateBrandingDto as its body (line 50) under the
    # router-level FULL_ACCESS dependency (line 24), and
    # the handler reads data.logo_type only inside the
    # handler body, after validation, and the
    # _assert_create_scope guard also runs inside the
    # handler body, so neither can mask the 422. The POST
    # carries a router-level FULL_ACCESS permission
    # dependency (a parameter dependency, solved before the
    # endpoint's own body is validated), so the caller role
    # must carry FULL_ACCESS -- otherwise the permission
    # 404 would mask the 422, exactly as in the
    # notification banner locks. The Role row (id
    # 68c302ef6bf7a039b7e9b386) is seeded for that
    # dependency, mirroring the branding scope locks: the
    # dependency looks the role up by the mocked caller's
    # role_id (user_access_management.py get_role_detail),
    # so the default host caller needs no override -- the
    # host scope (no X-Tenant-ID header) is legitimate
    # here because validation fails before the handler's
    # create-scope guard ever runs. Deliberately no exact
    # error-type assertion, mirroring the checkout
    # non-string email 422 lock. Deliberately no
    # Cache-Control/Pragma assertion: a 422 is FastAPI
    # request validation, not an ApiBaseException, so the
    # central handler's no-store headers do not apply to
    # it, mirroring the billing 422 locks. The security
    # headers ARE locked: the pure-ASGI middleware stamps
    # every HTTP response, including validation errors,
    # with no path exclusions.
    from beanie import PydanticObjectId, init_beanie
    from pymongo import AsyncMongoClient

    from api.domain.entities.branding import Branding
    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission

    mongo_client = AsyncMongoClient("mongodb://localhost:27012/test_db")
    await init_beanie(
        mongo_client["api_test_db"], document_models=[Branding]
    )

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Branding administrator",
        description="Role carrying FULL_ACCESS for the mocked caller",
        permissions=[Permission.FULL_ACCESS],
    ).insert()

    response = await client.post(
        "/brandings/",
        json={
            "logo_type": ["image/png"],
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "logo_type" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the branding POST 404 lock, using substring
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
    # runs, so no branding service call is made and no
    # record is created -- the seeded role is still there
    # with FULL_ACCESS and no branding record exists in
    # the test DB, mirroring the branding scope locks (the
    # init_beanie call above registers Branding, which is
    # not in the conftest model set, so the row can be
    # queried here).
    stored_role = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored_role is not None
    assert stored_role.permissions == [Permission.FULL_ACCESS]
    assert await Branding.find_one() is None
    await mongo_client.close()


@pytest.mark.asyncio
async def test_patch_branding_non_string_tenant_id_returns_422_with_security_headers(client: AsyncClient):
    """
    The branding PATCH with a non-string `tenant_id` (a JSON
    list): `tenant_id` is an `Optional[str]` field of
    UpdateBrandingDto, which the PATCH /brandings/{branding_id}
    endpoint takes as its body, and Pydantic v2 does not coerce
    lists to str, so request validation rejects the body with
    422 before the handler body runs.
    """
    # Function-name grep count 0 for
    # patch_branding_non_string_tenant_id before appending,
    # verified fresh this run, not assumed. This is the FIRST
    # lock of the branding PATCH per-field validation sweep:
    # the POST sweep locked all six UpdateBrandingDto fields
    # (identity, contact_info, theme_config, tenant_id,
    # logo_url, logo_type) on POST /brandings/, but the PATCH
    # /brandings/{branding_id} route is a separate handler
    # taking the same DTO, so a regression that dropped body
    # validation on the PATCH route would pass the POST locks
    # while accepting a wrong-typed body here. This run locks
    # tenant_id, so five remain for future runs. The other
    # fields are omitted (all optional) -- nothing else can
    # mask the 422. A list is used as the non-string payload
    # because Pydantic v2 lax mode has no list-to-str coercion
    # path, and a blank string would pin the blank-value
    # class, not the non-string class. Note tenant_id is
    # Optional[str] with default None, so None is a valid
    # value -- only the non-string type is locked here.
    # Verified from
    # backend/api/domain/dtos/branding_dto.py that
    # UpdateBrandingDto carries no model_validator of its
    # own (the normalize_app_name validator lives on the
    # nested IdentityDto and only runs when identity is
    # present), so no validator can mask the 422; verified
    # from backend/api/interfaces/api_controllers/
    # branding_endpoint.py that the handler reads
    # data.tenant_id only inside the handler body, after
    # validation, and the branding lookup / id check also
    # run inside the handler body, so neither can mask the
    # 422 -- no Branding record needs seeding, and the
    # branding_id path param is a plain string, so no path
    # validation can mask it either. The PATCH carries the
    # same router-level FULL_ACCESS permission dependency
    # as the POST (a parameter dependency, solved before
    # the endpoint's own body is validated), so the caller
    # role must carry FULL_ACCESS -- otherwise the
    # permission 404 would mask the 422, exactly as in the
    # POST tenant_id lock. The Role row (id
    # 68c302ef6bf7a039b7e9b386) is seeded for that
    # dependency, mirroring the POST locks: the dependency
    # looks the role up by the mocked caller's role_id
    # (user_access_management.py get_role_detail), so the
    # default host caller needs no override -- the host
    # scope (no X-Tenant-ID header) is legitimate here
    # because validation fails before the handler's
    # tenant-scope logic ever runs. Deliberately no exact
    # error-type assertion, mirroring the POST non-string
    # tenant_id 422 lock. Deliberately no Cache-Control /
    # Pragma assertion: a 422 is FastAPI request validation,
    # not an ApiBaseException, so the central handler's
    # no-store headers do not apply to it, mirroring the
    # POST 422 locks. The security headers ARE locked: the
    # pure-ASGI middleware stamps every HTTP response,
    # including validation errors, with no path exclusions.
    from beanie import PydanticObjectId, init_beanie
    from pymongo import AsyncMongoClient

    from api.domain.entities.branding import Branding
    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission

    mongo_client = AsyncMongoClient("mongodb://localhost:27012/test_db")
    await init_beanie(
        mongo_client["api_test_db"], document_models=[Branding]
    )

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Branding administrator",
        description="Role carrying FULL_ACCESS for the mocked caller",
        permissions=[Permission.FULL_ACCESS],
    ).insert()

    response = await client.patch(
        "/brandings/68c302ef6bf7a039b7e9b387",
        json={
            "tenant_id": ["68c302ef6bf7a039b7e9b387"],
        },
    )
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
    # mirroring the branding POST 404 lock, using substring
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
    # runs, so no branding service call is made and no
    # record is created -- the seeded role is still there
    # with FULL_ACCESS and no branding record exists in
    # the test DB, mirroring the branding POST locks (the
    # init_beanie call above registers Branding, which is
    # not in the conftest model set, so the row can be
    # queried here).
    stored_role = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored_role is not None
    assert stored_role.permissions == [Permission.FULL_ACCESS]
    assert await Branding.find_one() is None
    await mongo_client.close()

async def test_patch_branding_non_string_identity_returns_422_with_security_headers(client: AsyncClient):
    """
    The branding PATCH with a non-string `identity` (a JSON
    list): `identity` is an `Optional[IdentityDto]` field of
    UpdateBrandingDto, which the PATCH /brandings/{branding_id}
    endpoint takes as its body, and Pydantic v2 does not coerce
    lists to a model, so request validation rejects the body with
    422 before the handler body runs.
    """
    # Function-name grep count 0 for
    # patch_branding_non_string_identity before appending,
    # verified fresh this run, not assumed. This is the SECOND
    # lock of the branding PATCH per-field validation sweep:
    # the POST sweep locked all six UpdateBrandingDto fields
    # (identity, contact_info, theme_config, tenant_id,
    # logo_url, logo_type) on POST /brandings/, but the PATCH
    # /brandings/{branding_id} route is a separate handler
    # taking the same DTO, so a regression that dropped body
    # validation on the PATCH route would pass the POST locks
    # while accepting a wrong-typed body here. The previous
    # run locked tenant_id on PATCH, so this run locks
    # identity and four remain for future runs. The other
    # fields are omitted (all optional) -- nothing else can
    # mask the 422. A list is used as the non-string payload
    # because Pydantic v2 lax mode has no list-to-model
    # coercion path, and a blank string would pin the
    # blank-value class, not the non-string class. Note
    # identity is Optional[IdentityDto] with default None,
    # so None is a valid value -- only the non-string type
    # is locked here. Verified from
    # backend/api/domain/dtos/branding_dto.py that
    # IdentityDto's normalize_app_name model_validator runs
    # mode="after", i.e. only once a dict has been validated
    # into an IdentityDto, so it cannot mask the 422 for a
    # list payload; verified from
    # backend/api/interfaces/api_controllers/
    # branding_endpoint.py that the PATCH handler reads
    # data.identity only inside the handler body (via the
    # branding service call), after validation, and the
    # branding lookup / id check also run inside the handler
    # body, so neither can mask the 422 -- no Branding
    # record needs seeding, and the branding_id path param
    # is a plain string, so no path validation can mask it
    # either. The PATCH carries the same router-level
    # FULL_ACCESS permission dependency as the POST (a
    # parameter dependency, solved before the endpoint's own
    # body is validated), so the caller role must carry
    # FULL_ACCESS -- otherwise the permission 404 would
    # mask the 422, exactly as in the POST identity lock.
    # The Role row (id 68c302ef6bf7a039b7e9b386) is seeded
    # for that dependency, mirroring the POST locks: the
    # dependency looks the role up by the mocked caller's
    # role_id (user_access_management.py get_role_detail),
    # so the default host caller needs no override -- the
    # host scope (no X-Tenant-ID header) is legitimate here
    # because validation fails before the handler's
    # tenant-scope logic ever runs. Deliberately no exact
    # error-type assertion, mirroring the POST non-string
    # identity 422 lock. Deliberately no Cache-Control /
    # Pragma assertion: a 422 is FastAPI request validation,
    # not an ApiBaseException, so the central handler's
    # no-store headers do not apply to it, mirroring the
    # POST 422 locks. The security headers ARE locked: the
    # pure-ASGI middleware stamps every HTTP response,
    # including validation errors, with no path exclusions.
    from beanie import PydanticObjectId, init_beanie
    from pymongo import AsyncMongoClient

    from api.domain.entities.branding import Branding
    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission

    mongo_client = AsyncMongoClient("mongodb://localhost:27012/test_db")
    await init_beanie(
        mongo_client["api_test_db"], document_models=[Branding]
    )

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Branding administrator",
        description="Role carrying FULL_ACCESS for the mocked caller",
        permissions=[Permission.FULL_ACCESS],
    ).insert()

    response = await client.patch(
        "/brandings/68c302ef6bf7a039b7e9b387",
        json={
            "identity": ["Acme Corp"],
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "identity" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the branding POST 404 lock, using substring
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
    # runs, so no branding service call is made and no
    # record is created -- the seeded role is still there
    # with FULL_ACCESS and no branding record exists in
    # the test DB, mirroring the branding POST locks (the
    # init_beanie call above registers Branding, which is
    # not in the conftest model set, so the row can be
    # queried here).
    stored_role = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored_role is not None
    assert stored_role.permissions == [Permission.FULL_ACCESS]
    assert await Branding.find_one() is None
    await mongo_client.close()


async def test_patch_branding_non_string_contact_info_returns_422_with_security_headers(client: AsyncClient):
    """
    The branding PATCH with a non-string `contact_info` (a JSON
    list): `contact_info` is an `Optional[ContactInfo]` field of
    UpdateBrandingDto, which the PATCH /brandings/{branding_id}
    endpoint takes as its body, and Pydantic v2 does not coerce
    lists to a model, so request validation rejects the body with
    422 before the handler body runs.
    """
    # Function-name grep count 0 for
    # patch_branding_non_string_contact_info before appending,
    # verified fresh this run, not assumed. This is the THIRD
    # lock of the branding PATCH per-field validation sweep:
    # the POST sweep locked all six UpdateBrandingDto fields
    # (identity, contact_info, theme_config, tenant_id,
    # logo_url, logo_type) on POST /brandings/, but the PATCH
    # /brandings/{branding_id} route is a separate handler
    # taking the same DTO, so a regression that dropped body
    # validation on the PATCH route would pass the POST locks
    # while accepting a wrong-typed body here. The previous
    # runs locked tenant_id and identity on PATCH, so this
    # run locks contact_info and three remain for future
    # runs. The other fields are omitted (all optional) --
    # nothing else can mask the 422. A list is used as the
    # non-string payload because Pydantic v2 lax mode has no
    # list-to-model coercion path, and a blank string would
    # pin the blank-value class, not the non-string class.
    # Note contact_info is Optional[ContactInfo] with
    # default None, so None is a valid value -- only the
    # non-string type is locked here. Verified from
    # backend/api/domain/entities/branding.py that
    # ContactInfo's normalize_phone_address model_validator
    # runs mode="after", i.e. only once a dict has been
    # validated into a ContactInfo, so it cannot mask the
    # 422 for a list payload; verified from
    # backend/api/interfaces/api_controllers/
    # branding_endpoint.py that the PATCH handler reads
    # data.contact_info only inside the handler body (via
    # the branding service call), after validation, and the
    # branding lookup / id check also run inside the handler
    # body, so neither can mask the 422 -- no Branding
    # record needs seeding, and the branding_id path param
    # is a plain string, so no path validation can mask it
    # either. The PATCH carries the same router-level
    # FULL_ACCESS permission dependency as the POST (a
    # parameter dependency, solved before the endpoint's own
    # body is validated), so the caller role must carry
    # FULL_ACCESS -- otherwise the permission 404 would
    # mask the 422, exactly as in the POST contact_info
    # lock. The Role row (id
    # 68c302ef6bf7a039b7e9b386) is seeded for that
    # dependency, mirroring the POST locks: the dependency
    # looks the role up by the mocked caller's role_id
    # (user_access_management.py get_role_detail), so the
    # default host caller needs no override -- the host
    # scope (no X-Tenant-ID header) is legitimate here
    # because validation fails before the handler's
    # tenant-scope logic ever runs. Deliberately no exact
    # error-type assertion, mirroring the POST non-string
    # contact_info 422 lock. Deliberately no Cache-Control /
    # Pragma assertion: a 422 is FastAPI request validation,
    # not an ApiBaseException, so the central handler's
    # no-store headers do not apply to it, mirroring the
    # POST 422 locks. The security headers ARE locked: the
    # pure-ASGI middleware stamps every HTTP response,
    # including validation errors, with no path exclusions.
    from beanie import PydanticObjectId, init_beanie
    from pymongo import AsyncMongoClient

    from api.domain.entities.branding import Branding
    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission

    mongo_client = AsyncMongoClient("mongodb://localhost:27012/test_db")
    await init_beanie(
        mongo_client["api_test_db"], document_models=[Branding]
    )

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Branding administrator",
        description="Role carrying FULL_ACCESS for the mocked caller",
        permissions=[Permission.FULL_ACCESS],
    ).insert()

    response = await client.patch(
        "/brandings/68c302ef6bf7a039b7e9b387",
        json={
            "contact_info": ["support@example.com"],
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "contact_info" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the branding POST 404 lock, using substring
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
    # runs, so no branding service call is made and no
    # record is created -- the seeded role is still there
    # with FULL_ACCESS and no branding record exists in
    # the test DB, mirroring the branding POST locks (the
    # init_beanie call above registers Branding, which is
    # not in the conftest model set, so the row can be
    # queried here).
    stored_role = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored_role is not None
    assert stored_role.permissions == [Permission.FULL_ACCESS]
    assert await Branding.find_one() is None
    await mongo_client.close()
