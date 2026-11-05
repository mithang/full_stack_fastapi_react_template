import pytest
from httpx import AsyncClient

from api import app
from api.common.enums.gender import Gender
from api.domain.dtos.auth_dto import MeResponseDto
from api.domain.dtos.permission_dto import PermissionDto
from api.domain.dtos.role_dto import RoleDto
from api.domain.enum.permission import Permission
from api.infrastructure.security.current_user import get_current_user


@pytest.mark.asyncio
async def test_list_permissions_from_host(client: AsyncClient):
    """
        List all the permissions:
    """
    response = await client.get("/permissions/")
    assert response.status_code == 200
    # The endpoint comment requires this GET never to be served from a
    # browser or proxy cache (it lists permissions, and the list is
    # scope-dependent: host-level permissions are filtered out for
    # tenant users), but no test locked the headers in — deleting the
    # two header lines would have gone uncaught, as with the role,
    # user, tenant, and app-configuration GETs in iterations
    # 1785-1808. This is the first interface test for an endpoint
    # outside those four files: it needs no new fixture, since the
    # shared conftest client already overrides get_current_user with
    # a host user (tenant_id None), and the endpoint has no
    # permission-check dependency and no database use.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # The security-headers middleware (security_headers_middleware.py)
    # must stamp every response, but no test locked its headers in —
    # deleting the middleware registration would have gone uncaught,
    # as the no-store lines above did before iterations 1785-1819.
    # The test client runs the real app over ASGI transport, so the
    # pure-ASGI middleware applies here exactly as in production.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: the
    # middleware's permissions-policy is a long fixed list, and a
    # regression that dropped a directive (or replaced the value with
    # an empty one) would still pass the presence check above. The
    # twelve directives below are the ones whose absence would matter
    # most on this origin — the SPA uses no camera, microphone,
    # geolocation (verified by grep in the middleware's own comment),
    # and no Payment Request API, and it never reads the clipboard
    # (only writeText calls, verified by grep) — so lock them as
    # disabled here, using substring checks so later additions to
    # the list do not break this test. The full value lives in
    # _SECURITY_HEADERS. The sixth, display-capture, is safe to lock
    # here: the SPA has no screen-sharing flow (zero getDisplayMedia
    # calls, verified by grep this run). The seventh, fullscreen,
    # is safe to lock here: the SPA has no fullscreen flow (zero
    # requestFullscreen calls and zero <video>/<audio> elements,
    # verified by grep this run). The eighth, accelerometer, is safe
    # to lock here: the SPA has no motion-sensor flow (zero
    # DeviceMotion/DeviceOrientation/Accelerometer/Gyroscope/
    # Magnetometer matches, verified by grep this run). The ninth,
    # gyroscope, is safe to lock here: the SPA has no gyroscope
    # flow (zero Gyroscope/DeviceOrientation matches, verified by
    # grep this run), and the middleware value already contains
    # gyroscope=(). The tenth, magnetometer, is safe to lock here:
    # the SPA has no compass flow (zero Magnetometer matches,
    # verified by grep this run), and the middleware value already
    # contains magnetometer=(). The eleventh, xr-spatial-tracking,
    # is safe to lock here: the SPA has no XR flow (zero
    # navigator.xr / XRSession / immersive-ar / immersive-vr /
    # requestSession matches, verified by grep this run), and the
    # middleware value already contains xr-spatial-tracking=().
    # The twelfth, idle-detection, is safe to lock here: the SPA has
    # no idle-detection flow (zero IdleDetector/requestIdleCallback
    # matches, verified by grep this run), and the middleware value
    # already contains idle-detection=().
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

    data = [PermissionDto.model_validate(item) for item in response.json()]

    # Host caller (tenant_id None): the full enum, unfiltered.
    assert [item.name for item in data] == [perm.value for perm in Permission]


@pytest.mark.asyncio
async def test_list_permissions_from_tenant(client: AsyncClient):
    """
        List permissions for a tenant user:
    """
    # The host branch is locked above, but the tenant branch of
    # permissions_endpoint.py:24-30 was not: a tenant caller must
    # get every permission except the host-level ones, and deleting
    # the filter (or the tenant_id check) would previously have
    # gone uncaught - a tenant admin would then see
    # "host:manage_tenants" in the role-permission picker even
    # though assigning it can never grant anything on a tenant.
    # The shared conftest override returns a host user
    # (tenant_id None), so this test swaps in a tenant-scoped
    # override, mirroring the dashboard 403 lock's override
    # pattern, and restores the original in finally so no other
    # test's mock is affected. The endpoint has no permission
    # check and no database use, so no fixture or seeded row is
    # needed beyond the override.
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
                name="Tenant admin",
                created_at="2024-10-01T00:00:00Z",
                updated_at="2024-10-01T00:00:00Z",
                permissions=[],
            ),
            subscription=None,
        )

    original_override = app.dependency_overrides.get(get_current_user)
    app.dependency_overrides[get_current_user] = override_get_current_user_tenant_scoped
    try:
        response = await client.get("/permissions/")
    finally:
        if original_override is None:
            app.dependency_overrides.pop(get_current_user, None)
        else:
            app.dependency_overrides[get_current_user] = original_override
    assert response.status_code == 200
    # Same no-store lock as the host test: the list is
    # scope-dependent, so a cached 200 could show the host list
    # to a tenant user after an account switch on a shared machine.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the host test: the pure-ASGI
    # middleware stamps every HTTP response with no path
    # exclusions, so the tenant 200 must carry the same headers
    # as the host 200.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened:
    # lock the twelve most sensitive directives as disabled,
    # mirroring the host lock, using substring checks so later
    # additions to the list do not break this test. The full
    # value lives in _SECURITY_HEADERS. Each directive is safe
    # to lock here for the same reasons as on the host lock:
    # the SPA has no camera, microphone, geolocation, payment,
    # clipboard-read, display-capture, fullscreen, motion-sensor,
    # compass, XR, or idle-detection flow (verified by grep in
    # the earlier sweeps).
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

    # This GET sets no cookie: the endpoint only sets the two
    # cache headers above, and the middleware stamps headers
    # only. A refresh cookie here would mean the response
    # carried an auth side effect it must not have.
    assert "set-cookie" not in response.headers

    data = [PermissionDto.model_validate(item) for item in response.json()]

    # Tenant caller: the full enum in definition order, minus
    # every host-level permission. Exactly one enum member
    # starts with "host:" today (HOST_MANAGE_TENANTS =
    # "host:manage_tenants", verified fresh from
    # permission.py), so the filtered list has 18 entries; the
    # comprehension below keeps the lock correct if a second
    # host permission is ever added, and the explicit
    # host:manage_tenants exclusion catches a regression that
    # drops the filter while keeping the list shape.
    expected = [perm.value for perm in Permission if not perm.value.startswith("host:")]
    assert [item.name for item in data] == expected
    assert "host:manage_tenants" not in [item.name for item in data]


def test_permission_dto_extends_pydantic_base_model():
    """
    Regression test: PermissionDto must extend pydantic's BaseModel
    directly, not openai.BaseModel (fixed in the 06:14 run — the
    OpenAI SDK's BaseModel is its API-response model class, so the
    permissions DTO was needlessly coupled to the OpenAI SDK).
    openai.BaseModel itself subclasses pydantic's BaseModel, so an
    issubclass check would not catch a revert — the direct-bases
    check below does.
    """
    from pydantic import BaseModel as PydanticBaseModel

    assert PermissionDto.__bases__ == (PydanticBaseModel,)
