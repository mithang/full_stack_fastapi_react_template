import pytest
from httpx import AsyncClient
from api.domain.dtos.user_dto import CreateUserResponseDto, UpdateUserDto, UserListDto, CreateUserDto, UserDto
from api.common.enums.gender import Gender


async def create_user(client: AsyncClient) -> CreateUserResponseDto:
    new_user = CreateUserDto(
        email="test@example.com",
        first_name="Test",
        last_name="User",
        gender=Gender.OTHER,
        password="Test@123!"
    )
    response = await client.post("/users/", json=new_user.model_dump())
    assert response.status_code == 201
    # The security-headers middleware (security_headers_middleware.py)
    # stamps every HTTP response, not just GETs, but until now only
    # GET responses locked its headers in — deleting the middleware
    # registration would have gone uncaught on mutation responses
    # too. The test client runs the real app over ASGI transport, so
    # the pure-ASGI middleware applies here exactly as in production.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the four most sensitive directives as disabled, as on the
    # permissions GET in iteration 1865, using substring checks so
    # later additions to the list do not break this test. The full
    # value lives in _SECURITY_HEADERS.
    permissions_policy = response.headers["permissions-policy"]
    assert "camera=()" in permissions_policy
    assert "microphone=()" in permissions_policy
    assert "geolocation=()" in permissions_policy
    assert "payment=()" in permissions_policy
    return CreateUserResponseDto.model_validate(response.json())


@pytest.mark.asyncio
async def test_list_users_from_host(client: AsyncClient):
    """
        List all the users:
    """
    response = await client.get("/users/?skip=0&limit=10")
    assert response.status_code == 200
    # The endpoint comment requires this GET never to be served from a
    # browser or proxy cache (it lists the tenant's users with names,
    # emails, and roles), but no test locked the headers in — deleting
    # the two header lines would have gone uncaught, as with the
    # app-configuration GET in iteration 1785, the tenant list GET in
    # iteration 1786, and the role list GET in iteration 1787.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # The security-headers middleware (security_headers_middleware.py)
    # must stamp every response, but only the permissions and roles
    # GETs locked its headers in (iterations 1820-1821) — deleting the
    # middleware registration would have gone uncaught on this route
    # too. The test client runs the real app over ASGI transport, so
    # the pure-ASGI middleware applies here exactly as in production.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the four most sensitive directives as disabled, mirroring the
    # user-create POST lock in this file (iteration 1866) and the
    # app-config helper tenant-create POST lock (iteration 1894),
    # using substring checks so later additions to the list do not
    # break this test. The full value lives in _SECURITY_HEADERS.
    permissions_policy = response.headers["permissions-policy"]
    assert "camera=()" in permissions_policy
    assert "microphone=()" in permissions_policy
    assert "geolocation=()" in permissions_policy
    assert "payment=()" in permissions_policy

    data = UserListDto.model_validate(response.json())

    assert data.users == []
    assert data.total == 0
    assert data.hasNext == False
    assert data.hasPrevious == False
    assert data.skip == 0
    assert data.limit == 10


@pytest.mark.asyncio
async def test_create_user_in_host(client: AsyncClient):
    """
        Create a new user:
    """
    new_user_response = await create_user(client)

    # Verify the user was created by listing users again
    response = await client.get("/users/?skip=0&limit=10")
    assert response.status_code == 200
    # Same no-store lock as the list GETs (iterations 1788/1799-1801):
    # this verification GET hits the same list endpoint, which sets
    # both headers unconditionally, but asserted only status 200, so
    # deleting the header lines would have gone uncaught here.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # The security-headers middleware (security_headers_middleware.py)
    # must stamp every response, but this create-verification GET
    # locked only no-store — deleting the middleware registration
    # would have gone uncaught here too. The test client runs the
    # real app over ASGI transport, so the pure-ASGI middleware
    # applies here exactly as in production, and the user list GET
    # already locks the same headers, so the assertion holds for
    # this verification GET as well.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the four most sensitive directives as disabled, mirroring the
    # user-list GET lock in this file (iteration 1895), using
    # substring checks so later additions to the list do not break
    # this test. The full value lives in _SECURITY_HEADERS.
    permissions_policy = response.headers["permissions-policy"]
    assert "camera=()" in permissions_policy
    assert "microphone=()" in permissions_policy
    assert "geolocation=()" in permissions_policy
    assert "payment=()" in permissions_policy
    data = UserListDto.model_validate(response.json())
    assert data.total == 1
    assert data.users[0].id == new_user_response.id



@pytest.mark.asyncio
async def test_get_user_by_id_from_host(client: AsyncClient):
    """
        Get a user by ID:
    """
    new_user_response = await create_user(client)
    response = await client.get(f"/users/{new_user_response.id}")
    assert response.status_code == 200
    # The endpoint comment requires this GET never to be served from a
    # browser or proxy cache (it returns one user's personal data),
    # but no test locked the headers in — deleting the two header
    # lines would have gone uncaught, as with the user list GET in
    # iteration 1788, the role list GET in iteration 1787, and the
    # tenant list GET in iteration 1786.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # The security-headers middleware (security_headers_middleware.py)
    # must stamp every response, but this single-user GET locked only
    # no-store — deleting the middleware registration would have gone
    # uncaught here too. The test client runs the real app over ASGI
    # transport, so the pure-ASGI middleware applies here exactly as
    # in production, and the user list GET already locks the same
    # headers, so the assertion holds for this single-user GET as well.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the four most sensitive directives as disabled, mirroring the
    # user create-verification GET lock in this file (iteration 1896),
    # using substring checks so later additions to the list do not
    # break this test. The full value lives in _SECURITY_HEADERS.
    permissions_policy = response.headers["permissions-policy"]
    assert "camera=()" in permissions_policy
    assert "microphone=()" in permissions_policy
    assert "geolocation=()" in permissions_policy
    assert "payment=()" in permissions_policy
    data = UserDto.model_validate(response.json())
    assert data.email == "test@example.com"


@pytest.mark.asyncio
async def test_update_user_by_id_from_host(client: AsyncClient):
    """
        Update a user by ID:
    """
    new_user_response = await create_user(client)
    response = await client.get(f"/users/{new_user_response.id}")
    assert response.status_code == 200
    # Same no-store lock as the single-user GET (iteration 1789):
    # this pre-fetch GET hits the same get_user endpoint, which sets
    # both headers unconditionally, but asserted only status 200, so
    # deleting the header lines would have gone uncaught here.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # The security-headers middleware (security_headers_middleware.py)
    # must stamp every response, but this pre-fetch GET locked only
    # no-store — deleting the middleware registration would have gone
    # uncaught here too. The test client runs the real app over ASGI
    # transport, so the pure-ASGI middleware applies here exactly as
    # in production, and the single-user GET already locks the same
    # headers, so the assertion holds for this pre-fetch GET as well.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the four most sensitive directives as disabled, mirroring the
    # single-user GET lock in this file (iteration 1897), using
    # substring checks so later additions to the list do not break
    # this test. The full value lives in _SECURITY_HEADERS.
    permissions_policy = response.headers["permissions-policy"]
    assert "camera=()" in permissions_policy
    assert "microphone=()" in permissions_policy
    assert "geolocation=()" in permissions_policy
    assert "payment=()" in permissions_policy
    data = UserDto.model_validate(response.json())

    # Update the user's email
    data.gender = Gender.MALE
    updated_data = UpdateUserDto(**data.model_dump())
    response = await client.put(f"/users/{new_user_response.id}", json=updated_data.model_dump())
    assert response.status_code == 200
    # Same security-header lock as the create-user POST in this file
    # (iteration 1852): the middleware stamps every HTTP response, so
    # it stamps this PUT response too, but until now only its status
    # and body were asserted — deleting the middleware registration
    # would have gone uncaught on update responses.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the four most sensitive directives as disabled, mirroring the
    # pre-fetch GET lock in this test (iteration 1898), using
    # substring checks so later additions to the list do not break
    # this test. The full value lives in _SECURITY_HEADERS.
    permissions_policy = response.headers["permissions-policy"]
    assert "camera=()" in permissions_policy
    assert "microphone=()" in permissions_policy
    assert "geolocation=()" in permissions_policy
    assert "payment=()" in permissions_policy
    new_user_updated_data = UserDto.model_validate(response.json())
    assert new_user_updated_data.gender == Gender.MALE


@pytest.mark.asyncio
async def test_delete_user_by_id_from_host(client: AsyncClient):
    """
        Delete a user by ID:
    """
    new_user_response = await create_user(client)
    response = await client.delete(f"/users/{new_user_response.id}")
    assert response.status_code == 202
    # The security-headers middleware (security_headers_middleware.py)
    # stamps every HTTP response, not just GETs, but until this run
    # only GET responses, the create POSTs, and the update PUTs locked
    # its headers in — deleting the middleware registration would
    # have gone uncaught on user-delete responses too. The test
    # client runs the real app over ASGI transport, so the pure-ASGI
    # middleware applies here exactly as in production.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the four most sensitive directives as disabled, mirroring the
    # user update PUT lock in this file (iteration 1899), using
    # substring checks so later additions to the list do not break
    # this test. The full value lives in _SECURITY_HEADERS.
    permissions_policy = response.headers["permissions-policy"]
    assert "camera=()" in permissions_policy
    assert "microphone=()" in permissions_policy
    assert "geolocation=()" in permissions_policy
    assert "payment=()" in permissions_policy

    # Verify the user was deleted by attempting to get the user again
    response = await client.get(f"/users/{new_user_response.id}")
    assert response.status_code == 404
    # Same no-store lock as the nonexistent-user 404 in this file
    # (iteration 1811): the post-delete re-GET 404 comes from the
    # central ApiBaseException handler, whose headers were added in
    # iteration 1810, but no test locked them in for this re-GET —
    # deleting them would have gone uncaught, as with the role
    # post-delete re-GET, which is still unlocked.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"
    # Same security-header lock as the single-user GET: this re-GET
    # goes through the same route and the same pure-ASGI middleware
    # under the test client, but only locked the no-store headers —
    # deleting the middleware registration would have gone uncaught
    # here.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers


@pytest.mark.asyncio
async def test_get_nonexistent_user_by_id_from_host(client: AsyncClient):
    """
        Attempt to get a non-existent user by ID:
    """
    response = await client.get("/users/68c3031f449ed3590028c778")
    assert response.status_code == 404
    # Same no-store lock as the role 404 test (iteration 1810): the 404
    # comes from the central ApiBaseException handler, whose headers were
    # added in iteration 1810, so lock them here rather than relying on
    # the endpoint's own Response, which the exception path discards.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"
    # Same security-header lock as the delete-verification re-GET in
    # this file: this 404 goes through the same route and the same
    # pure-ASGI middleware under the test client, but only locked the
    # no-store headers — deleting the middleware registration would
    # have gone uncaught here.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    assert response.json()["error"] == "User with identifier 68c3031f449ed3590028c778 not found."


@pytest.mark.asyncio
async def test_list_of_users_paginated_in_host(client: AsyncClient):
    """
        List users with pagination:
    """
    for i in range(3):
        new_user = CreateUserDto(
            email=f"test{i}@example.com",
            first_name=f"Test{i}",
            last_name="User",
            gender=Gender.OTHER,
            password="Test@123!"
        )
        response = await client.post("/users/", json=new_user.model_dump())
        assert response.status_code == 201
        # The security-headers middleware (security_headers_middleware.py)
        # stamps every HTTP response, and the shared create_user helper
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
    # Create a single user and return the response

    # Verify the user was created by listing users again
    response = await client.get("/users/?skip=0&limit=1")
    assert response.status_code == 200
    # Same no-store lock as the unpaginated list GET (iteration 1788):
    # the list endpoint sets both headers unconditionally, but the
    # paginated pages asserted only status 200, so deleting the header
    # lines would have gone uncaught on the paginated path.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # The security-headers middleware (security_headers_middleware.py)
    # must stamp every response, but this paginated page 1 GET locked
    # only no-store — deleting the middleware registration would have
    # gone uncaught here too. The test client runs the real app over
    # ASGI transport, so the pure-ASGI middleware applies here exactly
    # as in production, and the unpaginated list GET already locks the
    # same headers, so the assertion holds for this paginated page
    # as well.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    data = UserListDto.model_validate(response.json())
    assert data.total == 3
    assert len(data.users) == 1
    assert data.hasNext == True
    assert data.hasPrevious == False
    assert data.skip == 0
    assert data.limit == 1

    response = await client.get("/users/?skip=1&limit=1")
    assert response.status_code == 200
    # Same no-store lock as page 1 (iteration 1799): this page hits the
    # same list endpoint, which sets both headers unconditionally.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # The security-headers middleware (security_headers_middleware.py)
    # must stamp every response, but this paginated page 2 GET locked
    # only no-store — deleting the middleware registration would have
    # gone uncaught here too. The test client runs the real app over
    # ASGI transport, so the pure-ASGI middleware applies here exactly
    # as in production, and the paginated page 1 GET already locks the
    # same headers, so the assertion holds for this paginated page
    # as well.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    data = UserListDto.model_validate(response.json())
    assert data.total == 3
    assert len(data.users) == 1
    assert data.hasNext == True
    assert data.hasPrevious == True
    assert data.skip == 1
    assert data.limit == 1

    response = await client.get("/users/?skip=2&limit=1")
    assert response.status_code == 200
    # Same no-store lock as pages 1-2 (iterations 1799/1800): this page
    # hits the same list endpoint, which sets both headers
    # unconditionally, but page 3 asserted only status 200, so deleting
    # the header lines would have gone uncaught on this page.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # The security-headers middleware (security_headers_middleware.py)
    # must stamp every response, but this paginated page 3 GET locked
    # only no-store — deleting the middleware registration would have
    # gone uncaught here too. The test client runs the real app over
    # ASGI transport, so the pure-ASGI middleware applies here exactly
    # as in production, and the paginated pages 1-2 GETs already lock
    # the same headers, so the assertion holds for this paginated
    # page as well.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    data = UserListDto.model_validate(response.json())
    assert data.total == 3
    assert len(data.users) == 1
    assert data.hasNext == False
    assert data.hasPrevious == True
    assert data.skip == 2
    assert data.limit == 1
