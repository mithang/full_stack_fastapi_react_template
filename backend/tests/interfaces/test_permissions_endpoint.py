import pytest
from httpx import AsyncClient

from api.domain.dtos.permission_dto import PermissionDto
from api.domain.enum.permission import Permission


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
    # six directives below are the ones whose absence would matter
    # most on this origin — the SPA uses no camera, microphone,
    # geolocation (verified by grep in the middleware's own comment),
    # and no Payment Request API, and it never reads the clipboard
    # (only writeText calls, verified by grep) — so lock them as
    # disabled here, using substring checks so later additions to
    # the list do not break this test. The full value lives in
    # _SECURITY_HEADERS. The sixth, display-capture, is safe to lock
    # here: the SPA has no screen-sharing flow (zero getDisplayMedia
    # calls, verified by grep this run).
    permissions_policy = response.headers["permissions-policy"]
    assert "camera=()" in permissions_policy
    assert "microphone=()" in permissions_policy
    assert "geolocation=()" in permissions_policy
    assert "payment=()" in permissions_policy
    assert "clipboard-read=()" in permissions_policy
    assert "display-capture=()" in permissions_policy

    data = [PermissionDto.model_validate(item) for item in response.json()]

    # Host caller (tenant_id None): the full enum, unfiltered.
    assert [item.name for item in data] == [perm.value for perm in Permission]
