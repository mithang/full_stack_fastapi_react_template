import pytest
from httpx import AsyncClient

from api.domain.dtos.role_dto import CreateRoleDto, CreateRoleResponseDto, RoleListDto, UpdateRoleDto, RoleDto
from api.domain.enum.permission import Permission


async def create_role(client: AsyncClient) -> CreateRoleResponseDto:
    new_role = CreateRoleDto(
        name="Test Role",
        description="A role for testing purposes",
    )
    response = await client.post("/roles/", json=new_role.model_dump())
    assert response.status_code == 201
    # The security-headers middleware (security_headers_middleware.py)
    # stamps every HTTP response, not just GETs, but until iteration
    # 1852 only GET responses and the user-create POST locked its
    # headers in — deleting the middleware registration would have
    # gone uncaught on role-create responses too. The test client
    # runs the real app over ASGI transport, so the pure-ASGI
    # middleware applies here exactly as in production.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the six most sensitive directives as disabled, as on the
    # permissions GET in iteration 1865 and the user-create POST in
    # iteration 1866, using substring checks so later additions to
    # the list do not break this test. The full value lives in
    # _SECURITY_HEADERS. The fifth, clipboard-read, is safe to lock
    # here: the SPA never reads the clipboard (only writeText calls,
    # verified by grep in iteration 1914). The sixth, display-capture,
    # is safe to lock here: the SPA has no screen-sharing flow (zero
    # getDisplayMedia calls, verified by grep this run).
    permissions_policy = response.headers["permissions-policy"]
    assert "camera=()" in permissions_policy
    assert "microphone=()" in permissions_policy
    assert "geolocation=()" in permissions_policy
    assert "payment=()" in permissions_policy
    assert "clipboard-read=()" in permissions_policy
    assert "display-capture=()" in permissions_policy
    return CreateRoleResponseDto.model_validate(response.json())


@pytest.mark.asyncio
async def test_list_roles_from_host(client: AsyncClient):
    """
        List all the roles:
    """
    response = await client.get("/roles/?skip=0&limit=10")
    assert response.status_code == 200
    # The endpoint comment requires this GET never to be served from a
    # browser or proxy cache (it lists roles with their permissions),
    # but no test locked the headers in — deleting the two header
    # lines would have gone uncaught, as with the app-configuration
    # GET in iteration 1785 and the tenant list GET in iteration 1786.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # The security-headers middleware (security_headers_middleware.py)
    # must stamp every response, but only the permissions GET locked
    # its headers in (iteration 1820) — deleting the middleware
    # registration would have gone uncaught on this route too.
    # The test client runs the real app over ASGI transport, so the
    # pure-ASGI middleware applies here exactly as in production.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the six most sensitive directives as disabled, mirroring the
    # tenant-list GET lock (iteration 1870), using substring checks
    # so later additions to the list do not break this test. The
    # full value lives in _SECURITY_HEADERS. The fifth, clipboard-read,
    # is safe to lock here: the SPA never reads the clipboard (only
    # writeText calls, verified by grep this run). The sixth,
    # display-capture, is safe to lock here: the SPA has no
    # screen-sharing flow (zero getDisplayMedia calls, verified by
    # grep this run).
    permissions_policy = response.headers["permissions-policy"]
    assert "camera=()" in permissions_policy
    assert "microphone=()" in permissions_policy
    assert "geolocation=()" in permissions_policy
    assert "payment=()" in permissions_policy
    assert "clipboard-read=()" in permissions_policy
    assert "display-capture=()" in permissions_policy

    data = RoleListDto.model_validate(response.json())

    assert data.roles == []
    assert data.total == 0
    assert data.hasNext == False
    assert data.hasPrevious == False
    assert data.skip == 0
    assert data.limit == 10

@pytest.mark.asyncio
async def test_create_role_in_host(client: AsyncClient):
    """
        Create a new role:
    """
    new_role_response = await create_role(client)

    # Verify the role was created by listing roles again
    response = await client.get("/roles/?skip=0&limit=10")
    assert response.status_code == 200
    # The endpoint comment requires this GET never to be served from a
    # browser or proxy cache (it lists roles with their permissions),
    # but no test locked the headers in — deleting the two header
    # lines would have gone uncaught, as with the single-role
    # verification GET in iteration 1794 and the role list GET in
    # iteration 1787.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # The security-headers middleware (security_headers_middleware.py)
    # must stamp every response, but only the role list GET locked
    # its headers in — deleting the middleware registration would
    # have gone uncaught on this verification GET too. The test
    # client runs the real app over ASGI transport, so the pure-ASGI
    # middleware applies here exactly as in production.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the six most sensitive directives as disabled, mirroring the
    # role-list GET lock (iteration 1882), using substring checks
    # so later additions to the list do not break this test. The
    # full value lives in _SECURITY_HEADERS. The fifth, clipboard-read,
    # is safe to lock here: the SPA never reads the clipboard (only
    # writeText calls, verified by grep this run). The sixth,
    # display-capture, is safe to lock here: the SPA has no
    # screen-sharing flow (zero getDisplayMedia calls, verified by
    # grep this run).
    permissions_policy = response.headers["permissions-policy"]
    assert "camera=()" in permissions_policy
    assert "microphone=()" in permissions_policy
    assert "geolocation=()" in permissions_policy
    assert "payment=()" in permissions_policy
    assert "clipboard-read=()" in permissions_policy
    assert "display-capture=()" in permissions_policy

    data = RoleListDto.model_validate(response.json())
    assert data.total == 1
    assert data.roles[0].id == new_role_response.id

@pytest.mark.asyncio
async def test_get_role_by_id_from_host(client: AsyncClient):
    """
        Get a role by ID:
    """
    new_role_response = await create_role(client)
    response = await client.get(f"/roles/{new_role_response.id}")
    assert response.status_code == 200
    # The endpoint comment requires this GET never to be served from a
    # browser or proxy cache (it returns a single role's name and
    # permissions), but no test locked the headers in — deleting the
    # two header lines would have gone uncaught, as with the user
    # single GET in iteration 1789, the user list GET in iteration
    # 1788, and the role list GET in iteration 1787.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # The security-headers middleware (security_headers_middleware.py)
    # must stamp every response, but only the role list and
    # create-role verification GETs locked its headers in — deleting
    # the middleware registration would have gone uncaught on this
    # single-role GET too. The test client runs the real app over
    # ASGI transport, so the pure-ASGI middleware applies here
    # exactly as in production.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the six most sensitive directives as disabled, mirroring the
    # role-list GET lock (iteration 1882), using substring checks
    # so later additions to the list do not break this test. The
    # full value lives in _SECURITY_HEADERS. The fifth, clipboard-read,
    # is safe to lock here: the SPA never reads the clipboard (only
    # writeText calls, verified by grep this run). The sixth,
    # display-capture, is safe to lock here: the SPA has no
    # screen-sharing flow (zero getDisplayMedia calls, verified by
    # grep this run).
    permissions_policy = response.headers["permissions-policy"]
    assert "camera=()" in permissions_policy
    assert "microphone=()" in permissions_policy
    assert "geolocation=()" in permissions_policy
    assert "payment=()" in permissions_policy
    assert "clipboard-read=()" in permissions_policy
    assert "display-capture=()" in permissions_policy

    data = RoleDto.model_validate(response.json())
    assert data.name == "Test Role"


@pytest.mark.asyncio
async def test_update_role_by_id_from_host(client: AsyncClient):
    """
        Update a role by ID:
    """
    new_role_response = await create_role(client)
    response = await client.get(f"/roles/{new_role_response.id}")
    assert response.status_code == 200
    # The endpoint comment requires this GET never to be served from a
    # browser or proxy cache (it returns a single role's name and
    # permissions), but no test locked the headers in — deleting the
    # two header lines would have gone uncaught, as with the single
    # role GET in iteration 1790 and the tenant search GETs in
    # iterations 1791-1792.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # The security-headers middleware (security_headers_middleware.py)
    # must stamp every response, but only the role list, create-role
    # verification, and single-role GETs locked its headers in —
    # deleting the middleware registration would have gone uncaught
    # on this pre-update GET too. The test client runs the real app
    # over ASGI transport, so the pure-ASGI middleware applies here
    # exactly as in production.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the six most sensitive directives as disabled, mirroring the
    # role-create default-permissions verification GET lock
    # (iteration 1888), using substring checks so later additions to
    # the list do not break this test. The full value lives in
    # _SECURITY_HEADERS. The fifth, clipboard-read, is safe to lock
    # here: the SPA never reads the clipboard (only writeText calls,
    # verified by grep this run). The sixth, display-capture,
    # is safe to lock here: the SPA has no screen-sharing flow (zero
    # getDisplayMedia calls, verified by grep this run).
    permissions_policy = response.headers["permissions-policy"]
    assert "camera=()" in permissions_policy
    assert "microphone=()" in permissions_policy
    assert "geolocation=()" in permissions_policy
    assert "payment=()" in permissions_policy
    assert "clipboard-read=()" in permissions_policy
    assert "display-capture=()" in permissions_policy

    data = RoleDto.model_validate(response.json())

    # Update the role's name
    updated_data = UpdateRoleDto(name="Test Role Updated")
    response = await client.put(f"/roles/{new_role_response.id}", json=updated_data.model_dump())
    assert response.status_code == 200
    # Same security-header lock as the user-update PUT in this suite
    # (iteration 1855): the middleware stamps every HTTP response, so
    # it stamps this PUT response too, but until now only its status
    # and body were asserted — deleting the middleware registration
    # would have gone uncaught on role-update responses.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the six most sensitive directives as disabled, mirroring the
    # role pre-update GET lock (iteration 1889), using substring
    # checks so later additions to the list do not break this test.
    # The full value lives in _SECURITY_HEADERS. The fifth,
    # clipboard-read, is safe to lock here: the SPA never reads the
    # clipboard (only writeText calls, verified by grep this run).
    # The sixth, display-capture, is safe to lock here: the SPA has
    # no screen-sharing flow (zero getDisplayMedia calls, verified
    # by grep this run), and the middleware already emits it.
    permissions_policy = response.headers["permissions-policy"]
    assert "camera=()" in permissions_policy
    assert "microphone=()" in permissions_policy
    assert "geolocation=()" in permissions_policy
    assert "payment=()" in permissions_policy
    assert "clipboard-read=()" in permissions_policy
    assert "display-capture=()" in permissions_policy
    new_role_updated_data = RoleDto.model_validate(response.json())
    assert new_role_updated_data.name == "Test Role Updated"
    assert data.name != new_role_updated_data.name


@pytest.mark.asyncio
async def test_delete_role_by_id_from_host(client: AsyncClient):
    """
        Delete a role by ID:
    """
    new_role_response = await create_role(client)
    response = await client.delete(f"/roles/{new_role_response.id}")
    assert response.status_code == 202
    # Same security-header lock as the tenant-delete and user-delete
    # DELETE responses (iterations 1857-1858): the middleware stamps
    # every HTTP response, so it stamps this DELETE response too, but
    # until now only its status was asserted — deleting the middleware
    # registration would have gone uncaught on role-delete responses.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the five most sensitive directives as disabled, mirroring the
    # role-update PUT lock (iteration 1890), using substring checks
    # so later additions to the list do not break this test. The
    # full value lives in _SECURITY_HEADERS. The fifth,
    # clipboard-read, is safe to lock here: the SPA never reads the
    # clipboard (only writeText calls, verified by grep this run).
    permissions_policy = response.headers["permissions-policy"]
    assert "camera=()" in permissions_policy
    assert "microphone=()" in permissions_policy
    assert "geolocation=()" in permissions_policy
    assert "payment=()" in permissions_policy
    assert "clipboard-read=()" in permissions_policy

    # Verify the role was deleted by attempting to get the role again
    response = await client.get(f"/roles/{new_role_response.id}")
    assert response.status_code == 404
    # Same central-handler no-store lock as the nonexistent-role 404
    # above (iteration 1810): the deleted role's GET raises
    # RoleNotFoundException via the service, so this 404 also goes
    # through api_exception_handler.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # The security-headers middleware (security_headers_middleware.py)
    # must stamp every response, but only the role list, create-role
    # verification, single-role, and pre-update GETs locked its headers
    # in — deleting the middleware registration would have gone
    # uncaught on this delete-verification 404 too. The middleware is
    # app-level pure ASGI, so it stamps exception-handler responses
    # exactly as it stamps success responses, and the test client runs
    # the real app over ASGI transport.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the five most sensitive directives as disabled, mirroring the
    # role-delete DELETE lock (iteration 1937), using substring checks
    # so later additions to the list do not break this test. The
    # full value lives in _SECURITY_HEADERS. The fifth,
    # clipboard-read, is safe to lock here: the SPA never reads the
    # clipboard (only writeText calls, verified by grep this run).
    permissions_policy = response.headers["permissions-policy"]
    assert "camera=()" in permissions_policy
    assert "microphone=()" in permissions_policy
    assert "geolocation=()" in permissions_policy
    assert "payment=()" in permissions_policy
    assert "clipboard-read=()" in permissions_policy


@pytest.mark.asyncio
async def test_get_nonexistent_role_by_id_from_host(client: AsyncClient):
    """
        Attempt to get a non-existent role by ID:
    """
    response = await client.get("/roles/68c3031f449ed3590028c778")
    assert response.status_code == 404
    # The 404 comes from the central ApiBaseException handler, not from
    # the endpoint's own Response: the endpoint sets no-store headers
    # before the lookup, but the exception path discards them, so until
    # iteration 1810 this error response carried no cache headers at
    # all. Lock the handler's headers in here, the same no-store
    # hardening as the success-path GET locks.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # The security-headers middleware (security_headers_middleware.py)
    # must stamp every response, but this 404 GET locked only no-store
    # — deleting the middleware registration would have gone uncaught
    # on this route too. The middleware is app-level pure ASGI
    # (api/__init__.py add_middleware), so it stamps exception-handler
    # 404s exactly as success responses, and the test client runs the
    # real app over ASGI transport.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the five most sensitive directives as disabled, mirroring the
    # role post-delete 404 lock (iteration 1938), using substring
    # checks so later additions to the list do not break this test.
    # The full value lives in _SECURITY_HEADERS. The fifth,
    # clipboard-read, is safe to lock here: the SPA never reads the
    # clipboard (only writeText calls, verified by grep this run).
    permissions_policy = response.headers["permissions-policy"]
    assert "camera=()" in permissions_policy
    assert "microphone=()" in permissions_policy
    assert "geolocation=()" in permissions_policy
    assert "payment=()" in permissions_policy
    assert "clipboard-read=()" in permissions_policy

    assert response.json()["error"] == "Role with identifier 68c3031f449ed3590028c778 not found."


@pytest.mark.asyncio
async def test_list_of_roles_paginated_in_host(client: AsyncClient):
    """
        List roles with pagination:
    """
    for i in range(3):
        new_role = CreateRoleDto(
          name=f"Test Role {i}",
          description=f"A role for testing purposes {i}",
        )
        response = await client.post("/roles/", json=new_role.model_dump())
        assert response.status_code == 201
        # The security-headers middleware (security_headers_middleware.py)
        # stamps every HTTP response, and the shared create_role helper
        # already locks its headers on the identical POST — but these
        # paginated-setup POSTs asserted only status 201, so deleting
        # the middleware registration would have gone uncaught on this
        # path too. The test client runs the real app over ASGI
        # transport, so the pure-ASGI middleware applies here exactly
        # as in production.
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["x-frame-options"] == "DENY"
        assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
        assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
        assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
        assert "permissions-policy" in response.headers
        # Presence alone would not catch the value being weakened: lock
        # the five most sensitive directives as disabled, mirroring the
        # paginated page GET locks in this test, using substring
        # checks so later additions to the list do not break this test.
        # The full value lives in _SECURITY_HEADERS. The fifth,
        # clipboard-read, is safe to lock here: the SPA never reads the
        # clipboard (no readText in frontend/app/src, only writeText
        # calls in ai-chat and copy-text).
        permissions_policy = response.headers["permissions-policy"]
        assert "camera=()" in permissions_policy
        assert "microphone=()" in permissions_policy
        assert "geolocation=()" in permissions_policy
        assert "payment=()" in permissions_policy
        assert "clipboard-read=()" in permissions_policy
    # Create a single user and return the response

    # Verify the user was created by listing users again
    response = await client.get("/roles/?skip=0&limit=1")
    assert response.status_code == 200
    # The endpoint comment requires this GET never to be served from a
    # browser or proxy cache (it lists roles with their permissions),
    # but no test locked the headers in for the paginated pages —
    # deleting the two header lines would have gone uncaught on these
    # pages even though the unpaginated list GET is locked, as with
    # the create-role list verification GET in iteration 1795.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # The security-headers middleware (security_headers_middleware.py)
    # must stamp every response, but this paginated page locked only
    # no-store — deleting the middleware registration would have gone
    # uncaught on this page too. The test client runs the real app
    # over ASGI transport, so the pure-ASGI middleware applies here
    # exactly as in production.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the five most sensitive directives as disabled, mirroring the
    # role-list GET lock (iteration 1882), using substring checks
    # so later additions to the list do not break this test. The
    # full value lives in _SECURITY_HEADERS. The fifth,
    # clipboard-read, is safe to lock here: the SPA never reads the
    # clipboard (no readText in frontend/app/src, only writeText
    # calls in ai-chat and copy-text).
    permissions_policy = response.headers["permissions-policy"]
    assert "camera=()" in permissions_policy
    assert "microphone=()" in permissions_policy
    assert "geolocation=()" in permissions_policy
    assert "payment=()" in permissions_policy
    assert "clipboard-read=()" in permissions_policy

    data = RoleListDto.model_validate(response.json())
    assert data.total == 3
    assert len(data.roles) == 1
    assert data.hasNext == True
    assert data.hasPrevious == False
    assert data.skip == 0
    assert data.limit == 1

    response = await client.get("/roles/?skip=1&limit=1")
    assert response.status_code == 200
    # Same no-store lock as the first paginated page (iteration 1796):
    # the list endpoint sets both headers unconditionally, so the
    # assertion holds for page 2 as well, and deleting the header
    # lines would otherwise go uncaught on this page.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # The security-headers middleware (security_headers_middleware.py)
    # must stamp every response, but this paginated page locked only
    # no-store — deleting the middleware registration would have gone
    # uncaught on this page too. The test client runs the real app
    # over ASGI transport, so the pure-ASGI middleware applies here
    # exactly as in production.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the five most sensitive directives as disabled, mirroring the
    # paginated page 1 lock (iteration 1885), using substring checks
    # so later additions to the list do not break this test. The
    # full value lives in _SECURITY_HEADERS. The fifth,
    # clipboard-read, is safe to lock here: the SPA never reads the
    # clipboard (no readText in frontend/app/src, only writeText
    # calls in ai-chat and copy-text).
    permissions_policy = response.headers["permissions-policy"]
    assert "camera=()" in permissions_policy
    assert "microphone=()" in permissions_policy
    assert "geolocation=()" in permissions_policy
    assert "payment=()" in permissions_policy
    assert "clipboard-read=()" in permissions_policy
    data = RoleListDto.model_validate(response.json())
    assert data.total == 3
    assert len(data.roles) == 1
    assert data.hasNext == True
    assert data.hasPrevious == True
    assert data.skip == 1
    assert data.limit == 1

    response = await client.get("/roles/?skip=2&limit=1")
    assert response.status_code == 200
    # Same no-store lock as paginated pages 1-2 (iterations 1796-1797):
    # the list endpoint sets both headers unconditionally, so the
    # assertion holds for the last page as well, and deleting the
    # header lines would otherwise go uncaught on this page.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # The security-headers middleware (security_headers_middleware.py)
    # must stamp every response, but this paginated page locked only
    # no-store — deleting the middleware registration would have gone
    # uncaught on this page too. The test client runs the real app
    # over ASGI transport, so the pure-ASGI middleware applies here
    # exactly as in production, and pages 1-2 already lock the same
    # headers, so the assertion holds for the last page as well.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the five most sensitive directives as disabled, mirroring the
    # paginated page 2 lock (iteration 1886), using substring checks
    # so later additions to the list do not break this test. The
    # full value lives in _SECURITY_HEADERS. The fifth, clipboard-read,
    # is safe to lock here: the SPA never reads the clipboard.
    permissions_policy = response.headers["permissions-policy"]
    assert "camera=()" in permissions_policy
    assert "microphone=()" in permissions_policy
    assert "geolocation=()" in permissions_policy
    assert "payment=()" in permissions_policy
    assert "clipboard-read=()" in permissions_policy
    data = RoleListDto.model_validate(response.json())
    assert data.total == 3
    assert len(data.roles) == 1
    assert data.hasNext == False
    assert data.hasPrevious == True
    assert data.skip == 2
    assert data.limit == 1


@pytest.mark.asyncio
async def test_create_role_with_default_permissions_in_host(client: AsyncClient):
    """
        Create a new role with default permissions:
    """
    new_role_response = await create_role(client)

    # Verify the role was created by listing roles again
    response = await client.get(f"/roles/{new_role_response.id}")
    assert response.status_code == 200
    # The endpoint comment requires this GET never to be served from a
    # browser or proxy cache (it returns a single role's name and
    # permissions), but no test locked the headers in — deleting the
    # two header lines would have gone uncaught, as with the pre-update
    # single-role GET in iteration 1793 and the single-role GET in
    # iteration 1790.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # The security-headers middleware (security_headers_middleware.py)
    # must stamp every response, but this verification GET locked only
    # no-store — deleting the middleware registration would have gone
    # uncaught here too. The test client runs the real app over ASGI
    # transport, so the pure-ASGI middleware applies here exactly as
    # in production, and the single-role GET already locks the same
    # headers, so the assertion holds for this verification GET as well.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the five most sensitive directives as disabled, mirroring the
    # paginated role-list page 3 lock (iteration 1887), using
    # substring checks so later additions to the list do not break
    # this test. The full value lives in _SECURITY_HEADERS. The fifth,
    # clipboard-read, is safe to lock here: the SPA never reads the
    # clipboard (only writeText calls, verified by grep this run).
    permissions_policy = response.headers["permissions-policy"]
    assert "camera=()" in permissions_policy
    assert "microphone=()" in permissions_policy
    assert "geolocation=()" in permissions_policy
    assert "payment=()" in permissions_policy
    assert "clipboard-read=()" in permissions_policy
    data = RoleDto.model_validate(response.json())
    assert data.permissions == [Permission.USER_VIEW_ONLY, Permission.ROLE_VIEW_ONLY]
