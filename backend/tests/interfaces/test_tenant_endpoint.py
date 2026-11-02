from unittest.mock import AsyncMock, patch
import pytest
from httpx import AsyncClient
from api.common.enums.gender import Gender
from api.core.exceptions import InvalidSubdomainException
from api.domain.dtos.tenant_dto import CreateTenantDto, CreateTenantResponseDto, PublicTenantDto, TenantListDto
from api.domain.dtos.user_dto import CreateUserResponseDto
from api.infrastructure.background.post_tenant_creation_task_service import PostTenantCreationTaskService

# ------------------------
# Fixture to mock PostTenantCreationTaskService._init_and_run
# ------------------------
@pytest.fixture
def mock_post_tenant_service():
    with patch.object(PostTenantCreationTaskService, "_init_and_run", new_callable=AsyncMock) as mock_task:
        yield mock_task

# ------------------------
# Mock Database for tenant tests
# ------------------------
@pytest.fixture
def mock_db():
    with patch("api.infrastructure.persistence.mongodb.Database", new_callable=AsyncMock) as mock_database:
        yield mock_database



async def create_tenant(client: AsyncClient, mock_post_tenant_service) -> CreateTenantResponseDto:
    new_tenant = CreateTenantDto(
       name="test",
       admin_email="test@test.com",
       admin_password="Test@123!",
       first_name="Test",
       last_name="Admin",
       gender=Gender.MALE,
       subdomain="test.fsrapp.com",
    )
    response = await client.post("/tenants/", json=new_tenant.model_dump())
    assert response.status_code == 201
    # The security-headers middleware (security_headers_middleware.py)
    # stamps every HTTP response, not just GETs, but until this run
    # only GET responses and the user/role-create POSTs locked its
    # headers in — deleting the middleware registration would have
    # gone uncaught on tenant-create responses too. The test client
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
    # permissions GET in iteration 1865 and the user/role-create POSTs
    # in iterations 1866-1867, using substring checks so later
    # additions to the list do not break this test. The full value
    # lives in _SECURITY_HEADERS. The fifth, clipboard-read,
    # is safe to lock here: the SPA never reads the clipboard
    # (only writeText calls, verified by grep in iteration 1914).
    # The sixth, display-capture, is safe to lock here: the SPA
    # never calls getDisplayMedia (verified by grep this run), so
    # no screen-sharing flow exists to break, and a compromised
    # script could otherwise capture the screen on the app origin.
    permissions_policy = response.headers["permissions-policy"]
    assert "camera=()" in permissions_policy
    assert "microphone=()" in permissions_policy
    assert "geolocation=()" in permissions_policy
    assert "payment=()" in permissions_policy
    assert "clipboard-read=()" in permissions_policy
    assert "display-capture=()" in permissions_policy
    mock_post_tenant_service.assert_awaited()

    return CreateUserResponseDto.model_validate(response.json())



@pytest.mark.asyncio
async def test_list_tenants_from_host(client: AsyncClient):
    """
        List all the tenants:
    """
    response = await client.get("/tenants/?skip=0&limit=10")
    assert response.status_code == 200
    # The endpoint comment requires this GET never to be served from a
    # browser or proxy cache (it lists tenants), but no test locked the
    # headers in — deleting the two header lines would have gone
    # uncaught, as with the app-configuration GET in iteration 1785.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"
    # The security-headers middleware (security_headers_middleware.py)
    # must stamp every response, but only the permissions, roles,
    # users, and app-configuration GETs locked its headers in
    # (iterations 1820-1823) — deleting the middleware registration
    # would have gone uncaught on this route too. The test client runs
    # the real app over ASGI transport, so the pure-ASGI middleware
    # applies here exactly as in production.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the seven most sensitive directives as disabled, mirroring the
    # permissions GET lock (iteration 1865), the user/role/tenant
    # create locks (iterations 1866-1868), and the app-config GET
    # lock (iteration 1869), using substring checks so later
    # additions to the list do not break this test. The full value
    # lives in _SECURITY_HEADERS. The fifth, clipboard-read,
    # is safe to lock here: the SPA never reads the clipboard
    # (only writeText calls, verified by grep this run).
    # The sixth, display-capture, is safe to lock here: the SPA
    # never calls getDisplayMedia (verified by grep this run), so
    # no screen-sharing flow exists to break, and a compromised
    # script could otherwise capture the screen on the app origin.
    # The seventh, fullscreen, is safe to lock here: the SPA has
    # no fullscreen flow (zero requestFullscreen calls and zero
    # <video>/<audio> elements in frontend/app/src, verified by
    # grep this run), and the middleware value already contains
    # fullscreen=().
    permissions_policy = response.headers["permissions-policy"]
    assert "camera=()" in permissions_policy
    assert "microphone=()" in permissions_policy
    assert "geolocation=()" in permissions_policy
    assert "payment=()" in permissions_policy
    assert "clipboard-read=()" in permissions_policy
    assert "display-capture=()" in permissions_policy
    assert "fullscreen=()" in permissions_policy

    data = TenantListDto.model_validate(response.json())

    assert data.tenants == []
    assert data.total == 0
    assert data.hasNext == False
    assert data.hasPrevious == False
    assert data.skip == 0
    assert data.limit == 10


@pytest.mark.asyncio
async def test_create_tenant_as_host(client: AsyncClient, mock_post_tenant_service, mock_db):
    """
        Create a new tenant:
    """
    new_tenant_response = await create_tenant(client, mock_post_tenant_service)

    # Verify the user was created by listing users again
    response = await client.get("/tenants/?skip=0&limit=10")
    assert response.status_code == 200
    # Same no-store lock as the tenant list GET (iteration 1786):
    # this verification GET hits the same list endpoint, which sets
    # both headers unconditionally, but asserted only status 200, so
    # deleting the header lines would have gone uncaught here.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"
    # Same security-header lock as the tenant list GET: this
    # verification GET goes through the same list route and the same
    # pure-ASGI middleware under the test client, but only locked the
    # no-store headers — deleting the middleware registration would
    # have gone uncaught here.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the seven most sensitive directives as disabled, mirroring the
    # tenant-list GET lock (iteration 1870) on this same list route,
    # using substring checks so later additions to the list do not
    # break this test. The full value lives in _SECURITY_HEADERS.
    # The fifth, clipboard-read, is safe to lock here: the SPA never
    # reads the clipboard (only writeText calls, verified by grep).
    # The sixth, display-capture, is safe to lock here: the SPA
    # never calls getDisplayMedia (verified by grep this run), so
    # no screen-sharing flow exists to break, and a compromised
    # script could otherwise capture the screen on the app origin.
    # The seventh, fullscreen, is safe to lock here: the SPA has
    # no fullscreen flow (zero requestFullscreen calls, zero
    # getDisplayMedia calls, and zero <video>/<audio> elements
    # in frontend/app/src, verified by grep this run), and the
    # middleware value already contains fullscreen=().
    permissions_policy = response.headers["permissions-policy"]
    assert "camera=()" in permissions_policy
    assert "microphone=()" in permissions_policy
    assert "geolocation=()" in permissions_policy
    assert "payment=()" in permissions_policy
    assert "clipboard-read=()" in permissions_policy
    assert "display-capture=()" in permissions_policy
    assert "fullscreen=()" in permissions_policy
    data = TenantListDto.model_validate(response.json())
    assert data.total == 1
    assert data.tenants[0].id == new_tenant_response.id



@pytest.mark.asyncio
async def test_search_tenant_by_subdomain_as_host(client: AsyncClient, mock_post_tenant_service, mock_db):
    """
        Get a tenant by subdomain:
    """
    new_tenant_response = await create_tenant(client, mock_post_tenant_service)
    response = await client.get(f"/tenants/search_by_subdomain/test.fsrapp.com")
    assert response.status_code == 200
    # The endpoint comment requires this GET never to be served from a
    # browser or proxy cache (a cached 200 could serve one tenant's
    # record to another admin after an account switch on a shared
    # machine), but no test locked the headers in — deleting the two
    # header lines would have gone uncaught, as with the tenant list
    # GET in iteration 1786 and the single-role GET in iteration 1790.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"
    # Same security-header lock as the tenant list GET: this search
    # GET goes through the same pure-ASGI middleware under the test
    # client, but only locked the no-store headers — deleting the
    # middleware registration would have gone uncaught here.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the seven most sensitive directives as disabled, mirroring the
    # tenant-list GET lock (iteration 1870) on this search route,
    # using substring checks so later additions to the list do not
    # break this test. The full value lives in _SECURITY_HEADERS.
    # The fifth, clipboard-read, is safe to lock here: the SPA never
    # reads the clipboard (only writeText calls, verified by grep).
    # The sixth, display-capture, is safe to lock here: the SPA
    # never calls getDisplayMedia (verified by grep this run), so
    # no screen-sharing flow exists to break, and a compromised
    # script could otherwise capture the screen on the app origin.
    # The seventh, fullscreen, is safe to lock here: the SPA never
    # calls requestFullscreen and renders no <video>/<audio> elements
    # (verified by grep this run), so no fullscreen flow exists to
    # break, and a compromised script could otherwise fullscreen-
    # spoof the app UI on the app origin.
    permissions_policy = response.headers["permissions-policy"]
    assert "camera=()" in permissions_policy
    assert "microphone=()" in permissions_policy
    assert "geolocation=()" in permissions_policy
    assert "payment=()" in permissions_policy
    assert "clipboard-read=()" in permissions_policy
    assert "display-capture=()" in permissions_policy
    assert "fullscreen=()" in permissions_policy
    # The search routes return the public shape since iteration 1780:
    # validating against the full TenantDto would fail, because it
    # requires subscription_id, which the public shape deliberately
    # withholds (billing data). Asserting the absence of both withheld
    # fields locks that narrowing in instead of weakening the test.
    assert "subscription_id" not in response.json()
    assert "features" not in response.json()
    data = PublicTenantDto.model_validate(response.json())
    assert data.name == "test"
    assert data.subdomain == "test.fsrapp.com"
    assert data.id == new_tenant_response.id




@pytest.mark.asyncio
async def test_search_tenant_by_name_as_host(client: AsyncClient, mock_post_tenant_service, mock_db):
    """
        Get a tenant by name:
    """
    new_tenant_response = await create_tenant(client, mock_post_tenant_service)
    response = await client.get("/tenants/search_by_name/test")
    assert response.status_code == 200
    # The endpoint sets the same no-store headers as the
    # search_by_subdomain GET (tenant_endpoint.py: search_by_name sets
    # Cache-Control: no-store and Pragma: no-cache so a cached 200 is
    # never served to another admin after an account switch on a shared
    # machine), but no test locked them in — deleting the two header
    # lines would have gone uncaught, as with the search_by_subdomain
    # GET in iteration 1791.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"
    # Same security-header lock as the search_by_subdomain GET (locked
    # in iteration 1845): this search GET goes through the same
    # pure-ASGI middleware under the test client, but only locked the
    # no-store headers — deleting the middleware registration would
    # have gone uncaught here.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the seven most sensitive directives as disabled, mirroring the
    # search_by_subdomain GET lock (iteration 1872) on this search
    # route, using substring checks so later additions to the list do
    # not break this test. The full value lives in _SECURITY_HEADERS.
    # The fifth, clipboard-read, is safe to lock here: the SPA never
    # reads the clipboard (no readText calls, only writeText copies).
    # The sixth, display-capture, is safe to lock here: the SPA
    # never calls getDisplayMedia (verified by grep this run), so
    # no screen-sharing flow exists to break, and a compromised
    # script could otherwise capture the screen on the app origin.
    # The seventh, fullscreen, is safe to lock here: the SPA never
    # calls requestFullscreen and renders no <video>/<audio> elements
    # (verified by grep this run), so no fullscreen flow exists to
    # break, and a compromised script could otherwise fullscreen-
    # spoof the app UI on the app origin.
    permissions_policy = response.headers["permissions-policy"]
    assert "camera=()" in permissions_policy
    assert "microphone=()" in permissions_policy
    assert "geolocation=()" in permissions_policy
    assert "payment=()" in permissions_policy
    assert "clipboard-read=()" in permissions_policy
    assert "display-capture=()" in permissions_policy
    assert "fullscreen=()" in permissions_policy
    # Mirror of the search_by_subdomain test (iteration 1782): the
    # search routes return the public shape since iteration 1780,
    # but only the subdomain route had a success test locking that
    # narrowing in — a regression on search_by_name (returning the
    # full TenantDto with subscription_id/features) would have gone
    # uncaught. Asserting the absence of both withheld fields here
    # closes that gap for the second public search route.
    assert "subscription_id" not in response.json()
    assert "features" not in response.json()
    data = PublicTenantDto.model_validate(response.json())
    assert data.name == "test"
    assert data.subdomain == "test.fsrapp.com"
    assert data.id == new_tenant_response.id


@pytest.mark.asyncio
async def test_delete_tenant_by_id_from_host(client: AsyncClient, mock_post_tenant_service, mock_db):
    """
        Delete a tenant by ID:
    """
    new_tenant_response = await create_tenant(client, mock_post_tenant_service)
    response = await client.delete(f"/tenants/{new_tenant_response.id}")
    assert response.status_code == 202
    # The security-headers middleware (security_headers_middleware.py)
    # stamps every HTTP response, not just GETs, but until this run
    # only GET responses and the create POSTs locked its headers in —
    # deleting the middleware registration would have gone uncaught
    # on tenant-delete responses too. The test client runs the real
    # app over ASGI transport, so the pure-ASGI middleware applies
    # here exactly as in production.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the seven most sensitive directives as disabled, mirroring the
    # tenant search-by-name GET lock (iteration 1873) on this DELETE
    # response, using substring checks so later additions to the list
    # do not break this test. The full value lives in _SECURITY_HEADERS.
    # The fifth, clipboard-read, is safe to lock here: the SPA never
    # reads the clipboard (only writeText calls in ai-chat/copy-text).
    # The sixth, display-capture, is safe to lock here: the SPA
    # never calls getDisplayMedia (verified by grep this run), so
    # no screen-sharing flow exists to break, and a compromised
    # script could otherwise capture the screen on the app origin.
    # The seventh, fullscreen, is safe to lock here: the SPA never
    # calls requestFullscreen and renders no <video>/<audio> elements
    # (verified by grep this run), so no fullscreen flow exists to
    # break, and a compromised script could otherwise fullscreen-
    # spoof the app UI on the app origin.
    permissions_policy = response.headers["permissions-policy"]
    assert "camera=()" in permissions_policy
    assert "microphone=()" in permissions_policy
    assert "geolocation=()" in permissions_policy
    assert "payment=()" in permissions_policy
    assert "clipboard-read=()" in permissions_policy
    assert "display-capture=()" in permissions_policy
    assert "fullscreen=()" in permissions_policy

    # Verify the tenant was deleted by searching for it again. There
    # is no GET /tenants/{id} route, so search_by_name is the
    # post-delete re-GET analogue of the user/role delete tests:
    # find_by_name raises TenantNotFoundException, which subclasses
    # NotFoundException, so this 404 goes through the central
    # api_exception_handler whose no-store headers were added in
    # iteration 1810 — but no test locked them in for this re-GET,
    # so deleting them would have gone uncaught, as with the
    # nonexistent-tenant 404 in this file (iteration 1812).
    response = await client.get("/tenants/search_by_name/test")
    assert response.status_code == 404
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"
    # Same security-header lock as the tenant search-by-name GET
    # (locked in iteration 1846): this delete-verification re-GET
    # goes through the same pure-ASGI middleware under the test
    # client, but only locked the no-store headers — deleting the
    # middleware registration would have gone uncaught on it.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the seven most sensitive directives as disabled, mirroring the
    # tenant DELETE lock (iteration 1874) on this post-delete re-GET
    # response, using substring checks so later additions to the list
    # do not break this test. The full value lives in _SECURITY_HEADERS.
    # The fifth, clipboard-read, is safe to lock here: the SPA never
    # reads the clipboard (only writeText calls in ai-chat/copy-text).
    # The sixth, display-capture, is safe to lock here: the SPA
    # never calls getDisplayMedia (verified by grep this run), so
    # no screen-sharing flow exists to break, and a compromised
    # script could otherwise capture the screen on the app origin.
    # The seventh, fullscreen, is safe to lock here: the SPA never
    # calls requestFullscreen and renders no <video>/<audio> elements
    # (verified by grep this run), so no fullscreen flow exists to
    # break, and a compromised script could otherwise fullscreen-
    # spoof the app UI on the app origin.
    permissions_policy = response.headers["permissions-policy"]
    assert "camera=()" in permissions_policy
    assert "microphone=()" in permissions_policy
    assert "geolocation=()" in permissions_policy
    assert "payment=()" in permissions_policy
    assert "clipboard-read=()" in permissions_policy
    assert "display-capture=()" in permissions_policy
    assert "fullscreen=()" in permissions_policy



@pytest.mark.asyncio
async def test_get_nonexistent_tenant_by_name_as_host(client: AsyncClient,  mock_db):
    """
        Attempt to get a non-existent tenant by name:
    """
    response = await client.get("/tenants/search_by_name/nonexistent-tenant")
    assert response.status_code == 404
    # TenantNotFoundException subclasses NotFoundException, which
    # subclasses ApiBaseException, so this 404 goes through the central
    # api_exception_handler whose no-store headers were added in
    # iteration 1810 — but no test locked them in for this route, so
    # deleting them would have gone uncaught, as with the role 404
    # in iteration 1810 and the user 404 in iteration 1811.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"
    # Same security-header lock as the tenant delete-verification GET
    # (locked in iteration 1847): this 404 goes through the same pure-
    # ASGI middleware under the test client, but only locked the
    # no-store headers — deleting the middleware registration would
    # have gone uncaught on this route too.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the seven most sensitive directives as disabled, mirroring the
    # tenant post-delete re-GET lock (iteration 1875) on this 404
    # response, using substring checks so later additions to the list
    # do not break this test. The full value lives in _SECURITY_HEADERS.
    # The fifth, clipboard-read, is safe to lock here: the SPA never
    # reads the clipboard (only writeText calls in ai-chat/copy-text).
    # The sixth, display-capture, is safe to lock here: the SPA has
    # no screen-sharing flow (zero getDisplayMedia calls in src).
    # The seventh, fullscreen, is safe to lock here: the SPA never
    # calls requestFullscreen and renders no <video>/<audio> elements
    # (verified by grep this run), so no fullscreen flow exists to
    # break, and a compromised script could otherwise fullscreen-
    # spoof the app UI on the app origin.
    permissions_policy = response.headers["permissions-policy"]
    assert "camera=()" in permissions_policy
    assert "microphone=()" in permissions_policy
    assert "geolocation=()" in permissions_policy
    assert "payment=()" in permissions_policy
    assert "clipboard-read=()" in permissions_policy
    assert "display-capture=()" in permissions_policy
    assert "fullscreen=()" in permissions_policy
    assert response.json()["error"] == "Tenant with identifier nonexistent-tenant not found."


@pytest.mark.asyncio
async def test_list_of_tenants_paginated_in_host(client: AsyncClient, mock_post_tenant_service, mock_db):
    """
        List tenants with pagination:
    """
    for i in range(3):
        new_tenant = CreateTenantDto(
            name=f"test-{i}",
            admin_email=f"test-{i}@test.com",
            admin_password="Test@123!",
            first_name=f"Test-{i}",
            last_name=f"Admin-{i}",
            gender=Gender.MALE,
            subdomain=f"test{i}.fsrapp.com",
        )
        response = await client.post("/tenants/", json=new_tenant.model_dump())
        mock_post_tenant_service.assert_awaited()
        assert response.status_code == 201
        # The security-headers middleware (security_headers_middleware.py)
        # stamps every HTTP response, and the shared create_tenant helper
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
        # the seven most sensitive directives as disabled, as on the
        # tenant-create POST in iteration 1868, using substring checks
        # so later additions to the list do not break this test. The
        # full value lives in _SECURITY_HEADERS. The fifth,
        # clipboard-read, is safe to lock here: the SPA never reads
        # the clipboard (no readText/clipboard.read calls in
        # frontend/app/src, only writeText calls in ai-chat and
        # copy-text). The sixth, display-capture, is safe to lock
        # here: the SPA never calls getDisplayMedia (verified by
        # grep this run), so no screen-sharing flow exists to break.
        # The seventh, fullscreen, is safe to lock here: the SPA
        # never calls requestFullscreen and has no video/audio
        # element (verified by grep this run), so no fullscreen
        # flow exists to break.
        permissions_policy = response.headers["permissions-policy"]
        assert "camera=()" in permissions_policy
        assert "microphone=()" in permissions_policy
        assert "geolocation=()" in permissions_policy
        assert "payment=()" in permissions_policy
        assert "clipboard-read=()" in permissions_policy
        assert "display-capture=()" in permissions_policy
        assert "fullscreen=()" in permissions_policy
    # Create a single user and return the response

    # Verify the user was created by listing users again
    response = await client.get("/tenants/?skip=0&limit=1")
    assert response.status_code == 200
    # The list endpoint sets both headers unconditionally
    # (tenant_endpoint.py: list_tenants), so they hold for paginated
    # pages too, but no test locked them in for this paginated path —
    # deleting the two header lines would have gone uncaught, as with
    # the paginated user list pages in iterations 1799-1801.
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
    # Presence alone would not catch the value being weakened: lock
    # the seven most sensitive directives as disabled, as on the
    # tenant-list GET in iteration 1870, using substring checks so
    # later additions to the list do not break this test. The full
    # value lives in _SECURITY_HEADERS. The fifth, clipboard-read,
    # is safe to lock here: the SPA never reads the clipboard
    # (only writeText calls in ai-chat/copy-text, verified by grep).
    # The sixth, display-capture, is safe to lock here: the SPA
    # never calls getDisplayMedia (verified by grep this run), so
    # no screen-sharing flow exists to break. The seventh,
    # fullscreen, is safe to lock here: the SPA never calls
    # requestFullscreen and has no video/audio element (verified
    # by grep this run), so no fullscreen flow exists to break.
    permissions_policy = response.headers["permissions-policy"]
    assert "camera=()" in permissions_policy
    assert "microphone=()" in permissions_policy
    assert "geolocation=()" in permissions_policy
    assert "payment=()" in permissions_policy
    assert "clipboard-read=()" in permissions_policy
    assert "display-capture=()" in permissions_policy
    assert "fullscreen=()" in permissions_policy
    data = TenantListDto.model_validate(response.json())
    assert data.total == 3
    assert len(data.tenants) == 1
    assert data.hasNext == True
    assert data.hasPrevious == False
    assert data.skip == 0
    assert data.limit == 1

    response = await client.get("/tenants/?skip=1&limit=1")
    assert response.status_code == 200
    # Same unconditional headers as page 1 above: the list route sets
    # them before any branch, so they hold for every paginated page.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"
    # Same security-header lock as paginated page 1 above: this page 2
    # GET goes through the same list route and the same pure-ASGI
    # middleware under the test client, but only locked the no-store
    # headers — deleting the middleware registration would have gone
    # uncaught here.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the seven most sensitive directives as disabled, as on paginated
    # page 1 in iteration 1877, using substring checks so later
    # additions to the list do not break this test. The full value
    # lives in _SECURITY_HEADERS. The fifth, clipboard-read, is safe
    # to lock here: the SPA never reads the clipboard (only
    # writeText calls in ai-chat/copy-text, verified by grep).
    # The sixth, display-capture, is safe to lock here: the SPA
    # never calls getDisplayMedia (verified by grep this run), so
    # no screen-sharing flow exists to break. The seventh,
    # fullscreen, is safe to lock here: the SPA never calls
    # requestFullscreen and has no video/audio element (verified
    # by grep this run), so no fullscreen flow exists to break.
    permissions_policy = response.headers["permissions-policy"]
    assert "camera=()" in permissions_policy
    assert "microphone=()" in permissions_policy
    assert "geolocation=()" in permissions_policy
    assert "payment=()" in permissions_policy
    assert "clipboard-read=()" in permissions_policy
    assert "display-capture=()" in permissions_policy
    assert "fullscreen=()" in permissions_policy
    data = TenantListDto.model_validate(response.json())
    assert data.total == 3
    assert len(data.tenants) == 1
    assert data.hasNext == True
    assert data.hasPrevious == True
    assert data.skip == 1
    assert data.limit == 1

    response = await client.get("/tenants/?skip=2&limit=1")
    assert response.status_code == 200
    # Same unconditional headers as pages 1-2 above: the list route sets
    # them before any branch, so they hold for every paginated page.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"
    # Same security-header lock as paginated pages 1-2 above: this
    # page 3 GET goes through the same list route and the same
    # pure-ASGI middleware under the test client, but only locked the
    # no-store headers — deleting the middleware registration would
    # have gone uncaught here.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the seven most sensitive directives as disabled, as on paginated
    # pages 1-2, using substring checks so
    # later additions to the list do not break this test. The full
    # value lives in _SECURITY_HEADERS. The fifth, clipboard-read,
    # is safe to lock here: the SPA never reads the clipboard (only
    # writeText calls in ai-chat/copy-text, verified by grep). The
    # sixth, display-capture, is safe to lock here: the SPA has no
    # screen-sharing flow (zero getDisplayMedia calls, verified by
    # grep), so disabling display capture breaks nothing. The
    # seventh, fullscreen, is safe to lock here: the SPA never calls
    # requestFullscreen and has no video/audio element (verified by
    # grep this run), so no fullscreen flow exists to break.
    permissions_policy = response.headers["permissions-policy"]
    assert "camera=()" in permissions_policy
    assert "microphone=()" in permissions_policy
    assert "geolocation=()" in permissions_policy
    assert "payment=()" in permissions_policy
    assert "clipboard-read=()" in permissions_policy
    assert "display-capture=()" in permissions_policy
    assert "fullscreen=()" in permissions_policy
    data = TenantListDto.model_validate(response.json())
    assert data.total == 3
    assert len(data.tenants) == 1
    assert data.hasNext == False
    assert data.hasPrevious == True
    assert data.skip == 2
    assert data.limit == 1


@pytest.mark.asyncio
async def test_validate_subdomain_when_tenant_creation(client: AsyncClient, mock_db):
    """
        Validate subdomain when creating a tenant:
    """
    with pytest.raises(InvalidSubdomainException) as exc:
        CreateTenantDto(
            name="test",
            admin_email="test@test.com",
            admin_password="Test@123!",
            first_name="Test",
            last_name="Admin",
            gender=Gender.MALE,
            subdomain="test-.fsrapp.com",  # invalid
        )
    assert "invalid format" in str(exc.value)


@pytest.mark.asyncio
async def test_validate_password_when_tenant_creation(client: AsyncClient, mock_db):
    """
        Validate password when creating a tenant:
    """
    new_tenant = CreateTenantDto(
        name="test",
        admin_email="test@test.com",
        admin_password="12",
        first_name="Test",
        last_name="Admin",
        gender=Gender.MALE,
        subdomain="test.fsrapp.com",  # invalid
    )
    response = await client.post("/tenants/", json=new_tenant.model_dump())
    assert response.status_code == 406
    # The security-headers middleware (security_headers_middleware.py)
    # is pure ASGI and stamps every HTTP response, including error
    # responses from mutation routes, but until now only success
    # mutation responses and 404s locked its headers in — deleting
    # the middleware registration would have gone uncaught on this
    # 406 error response too. The test client runs the real app over
    # ASGI transport, so the middleware applies here exactly as in
    # production, and the tenant-create 201 already locks the same
    # headers, so the assertion holds for this error response as well.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the seven most sensitive directives as disabled, as on the
    # tenant responses in iterations 1865-1879, using substring
    # checks so later additions to the list do not break this test.
    # The full value lives in _SECURITY_HEADERS. The fifth,
    # clipboard-read, is safe to lock here: the SPA never reads
    # the clipboard (only writeText calls in ai-chat/copy-text).
    # The sixth, display-capture, is safe to lock here: the SPA has
    # no screen-sharing flow (zero getDisplayMedia calls, verified
    # by grep), so disabling display capture breaks nothing.
    # The seventh, fullscreen, is safe to lock here: the SPA
    # never calls requestFullscreen and has no video/audio
    # element (verified by grep this run), so no fullscreen
    # flow exists to break.
    permissions_policy = response.headers["permissions-policy"]
    assert "camera=()" in permissions_policy
    assert "microphone=()" in permissions_policy
    assert "geolocation=()" in permissions_policy
    assert "payment=()" in permissions_policy
    assert "clipboard-read=()" in permissions_policy
    assert "display-capture=()" in permissions_policy
    assert "fullscreen=()" in permissions_policy
    assert response.json()["error"] == "Password must be at least 8 characters long, include uppercase and lowercase letters, a number, and a special character."
