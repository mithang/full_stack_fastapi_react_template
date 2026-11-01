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

    data = [PermissionDto.model_validate(item) for item in response.json()]

    # Host caller (tenant_id None): the full enum, unfiltered.
    assert [item.name for item in data] == [perm.value for perm in Permission]
