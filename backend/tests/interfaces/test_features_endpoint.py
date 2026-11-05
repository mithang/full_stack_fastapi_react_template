import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_get_features_with_missing_role_returns_404_with_cache_and_security_headers(client: AsyncClient):
    """
        The features GET:
    """
    # The features area had no interface test file at all, so
    # deleting the features router from api/__init__.py — or
    # dropping the central ApiBaseException no-store lines or the
    # security-headers middleware registration — would previously
    # have gone uncaught here even though every other interface
    # area locks its headers in. The success path is not asserted
    # here: the GET is permission-gated (HOST_MANAGE_TENANTS), so
    # it needs a DB role lookup, and the shared conftest client
    # seeds no role — the dashboard test documents the same
    # exclusion for this endpoint. The error path below is
    # deterministic instead: the mocked host user's role_id
    # points at no row in the fresh test database (Role is in
    # the conftest model set), so the permission dependency
    # raises RoleNotFoundException before the handler runs, and
    # the central ApiBaseException handler turns it into a 404.
    # That 404 must still carry the error-response headers: a
    # cached 404 could otherwise be served to a different user
    # after an account switch on a shared machine.
    response = await client.get("/features/")
    assert response.status_code == 404
    body = response.json()
    assert body["code"] == 404
    assert "Role" in body["error"]
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the notification banner test:
    # the pure-ASGI middleware stamps every HTTP response with no
    # path exclusions, so the features 404 must carry the same
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
    # the notification lock, using substring checks so later
    # additions to the list do not break this test. The full value
    # lives in _SECURITY_HEADERS. Each directive is safe to lock
    # here for the same reasons as on the other routes: the SPA
    # has no camera, microphone, geolocation, payment,
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
async def test_get_features_with_host_permission_returns_200_with_cache_and_security_headers(client: AsyncClient):
    """
        The features GET success path:
    """
    # The features 200 branch, not yet locked: function-name
    # grep count 0 for get_features_with_host_permission
    # (verified fresh this run), and the only existing lock in
    # this file fails earlier: the mocked host user's role_id
    # points at no row in the fresh test database, so the
    # permission dependency raises RoleNotFoundException and the
    # handler never runs. The handler itself is a static
    # catalogue (features_endpoint.py:14-22): it returns every
    # FeatureEnum member, so with the permission gate satisfied
    # the 200 body is the six values in definition order. The
    # gate is unlocked by seeding the exact role the shared
    # conftest mock points at - id
    # 68c302ef6bf7a039b7e9b386 - carrying the one permission
    # this route requires, HOST_MANAGE_TENANTS, mirroring the
    # Role-seed precedent in test_account_endpoint.py (the
    # resend-activation-email lock seeds the same id). The
    # dependency (user_access_management.py) fetches the role
    # by id with no tenant filter, and the seeded row is
    # host-stamped (tenant_id None), so a host caller with no
    # X-Tenant-ID header sees it; with tenancy on, the
    # HOST_MANAGE_TENANTS branch grants, and with tenancy off
    # the all() check on the single required permission
    # grants - either way the gate passes. No User row is
    # needed: the mocked current user is the shared conftest
    # override, and the conftest fixture drops the test DB
    # after the test, so the row cannot leak into other
    # tests. Deliberately no refresh-cookie assertion beyond
    # the set-cookie absence: this GET sets no cookie. A
    # future change that drops a feature from the enum, or
    # that reorders it, would break this lock while leaving
    # the 404 lock green, so the two paths are locked
    # separately.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host tenant manager",
        description="Role carrying HOST_MANAGE_TENANTS for the mocked caller",
        permissions=[Permission.HOST_MANAGE_TENANTS],
    ).insert()
    response = await client.get("/features/")
    assert response.status_code == 200
    assert response.json() == ["chat", "report", "analytics", "organization", "teams", "stripe"]
    assert "refresh_token" not in response.headers.get("set-cookie", "")
    # The catalogue is static, but the endpoint is
    # permission-gated (HOST_MANAGE_TENANTS), so it must not be
    # served from a browser or proxy cache: a cached 200 could
    # show the gated catalogue to a different user after an
    # account switch on a shared machine - the same no-store
    # hardening the handler applies on the success path.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the features 404 test:
    # the pure-ASGI middleware stamps every HTTP response with no
    # path exclusions, so the features 200 must carry the same
    # headers as the authenticated GETs.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the twelve most sensitive directives as disabled, mirroring
    # the features 404 lock, using substring checks so later
    # additions to the list do not break this test. The full value
    # lives in _SECURITY_HEADERS. Each directive is safe to lock
    # here for the same reasons as on the 404 path: the SPA has
    # no camera, microphone, geolocation, payment,
    # clipboard-read, display-capture, fullscreen, motion-sensor,
    # compass, XR, or idle-detection flow (verified by grep in
    # the earlier sweeps: zero IdleDetector/requestIdleCallback
    # matches and zero case-insensitive idle matches across
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
    # Postcondition: the read is side-effect free - the seeded
    # role is still there with its permission.
    stored = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored is not None
    assert stored.permissions == [Permission.HOST_MANAGE_TENANTS]
