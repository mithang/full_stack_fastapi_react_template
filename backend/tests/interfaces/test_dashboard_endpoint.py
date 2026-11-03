import pytest
from httpx import AsyncClient

from api import app
from api.common.enums.gender import Gender
from api.domain.dtos.auth_dto import MeResponseDto
from api.domain.dtos.role_dto import RoleDto
from api.infrastructure.security.current_user import get_current_user


@pytest.mark.asyncio
async def test_get_dashboard_metrics_returns_ok_with_cache_and_security_headers(client: AsyncClient):
    """
        The dashboard metrics GET:
    """
    # The dashboard area had no interface test file at all, so
    # deleting the dashboard router from api/__init__.py — or
    # dropping the no-store lines or the security-headers middleware
    # registration — would previously have gone uncaught here even
    # though every other interface area locks its headers in. This
    # GET needs no new fixture: unlike the features GET it carries
    # no permission-check dependency and no DB role lookup, and
    # unlike the billing/AI GETs it needs no live external service.
    # Its scope guard passes for the shared mocked user (tenant_id
    # None, so the host global view applies), and its service only
    # aggregates the fresh test database, so an empty database
    # deterministically yields 200 with zero counts and an empty
    # timeseries.
    response = await client.get("/dashboard/")
    assert response.status_code == 200
    body = response.json()
    assert body["filter"] == "all"
    assert body["total_users"] == 0
    assert body["joined_users"] == 0
    assert body["timeseries"] == []
    # Per-tenant metrics are admin-visible counts, so they must
    # never be served from a browser or proxy cache: a cached 200
    # could serve one tenant's metrics to another admin after an
    # account switch, or hide fresh signups. The handler sets both
    # headers before calling the service, so they hold on the
    # success path.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"
    # Same security-headers lock as the notification banner test:
    # the pure-ASGI middleware stamps every HTTP response with no
    # path exclusions, so the dashboard GET must carry the same
    # headers as the authenticated GETs.
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
async def test_get_dashboard_metrics_outside_tenant_scope_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        Second-path lock for the dashboard area: the success test
    above covers the host global view (shared mocked user, tenant_id
    None, so the scope guard passes), but the scope-guard error path
    was untested — deleting _assert_dashboard_scope, or weakening
    it, would previously have gone uncaught, and a tenant caller
    hitting the host DB would then read cross-tenant user counts
    and signup timeseries presented as their own dashboard. This
    reuses the per-test MeResponseDto override pattern from the
    manage-security test: a tenant-scoped user (tenant_id set) with
    no X-Tenant-ID — the tenant middleware resolves host scope, so
    request_tenant_id is None — raises ForbiddenException before
    any aggregation runs, and the container-resolved UserService
    performs no DB call at resolution time, so the guard is
    reached with no live external call. The shared conftest mock
    cannot be used: it is a plain UserDto with tenant_id None, so
    the guard would pass and the handler would fall through to the
    aggregation instead of the deterministic 403. The original
    override is restored in finally, so no other test's mock is
    affected. The 403 must still carry the error-response headers:
    the handler sets no-store only after the guard, so on this path
    they come from the central ApiBaseException handler, and a
    cached 403 could otherwise be served to a different user after
    an account switch on a shared machine.
    """
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
                name="No permissions",
                created_at="2024-10-01T00:00:00Z",
                updated_at="2024-10-01T00:00:00Z",
                permissions=[],
            ),
            subscription=None,
        )

    original_override = app.dependency_overrides.get(get_current_user)
    app.dependency_overrides[get_current_user] = override_get_current_user_tenant_scoped
    try:
        response = await client.get("/dashboard/")
    finally:
        if original_override is None:
            app.dependency_overrides.pop(get_current_user, None)
        else:
            app.dependency_overrides[get_current_user] = original_override
    assert response.status_code == 403
    body = response.json()
    assert body["code"] == 403
    assert "outside your tenant's scope" in body["error"]
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the dashboard success test:
    # the pure-ASGI middleware stamps every HTTP response with no
    # path exclusions, so the dashboard 403 must carry the same
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
    # the dashboard success lock, using substring checks so later
    # additions to the list do not break this test. Each directive
    # is safe to lock here for the same reasons as on the success
    # path: the SPA has no camera, microphone, geolocation,
    # payment, clipboard-read, display-capture, fullscreen,
    # motion-sensor, compass, XR, or idle-detection flow
    # (re-verified fresh this run: zero case-insensitive idle
    # matches across frontend/app/src, and the remaining flows
    # verified absent in the earlier sweeps).
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
