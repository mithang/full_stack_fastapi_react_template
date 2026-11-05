from unittest.mock import AsyncMock, patch
import pytest
from httpx import AsyncClient
from api import app
from api.common.enums.gender import Gender
from api.domain.dtos.auth_dto import MeResponseDto
from api.domain.dtos.role_dto import RoleDto
from api.infrastructure.security.current_user import get_current_user
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
    # the twelve most sensitive directives as disabled, as on the
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
    # The seventh, fullscreen, is safe to lock here: the SPA has
    # no fullscreen flow (zero requestFullscreen calls and zero
    # <video>/<audio> elements, verified by grep this run), and
    # the middleware value already contains fullscreen=().
    # The eighth, accelerometer, is safe to lock here: the SPA
    # never reads motion sensors (zero Accelerometer/Gyroscope/
    # Magnetometer/DeviceMotion/DeviceOrientation matches in
    # frontend/app/src, verified by grep this run), and the
    # middleware value already contains accelerometer=().
    # The ninth, gyroscope, is safe to lock here: the SPA has
    # no gyroscope flow (zero Gyroscope/DeviceOrientation matches
    # in frontend/app/src, verified by grep this run), and the
    # middleware value already contains gyroscope=().
    # The tenth, magnetometer, is safe to lock here: the SPA has
    # no compass flow (zero Magnetometer matches in
    # frontend/app/src, verified by grep this run), and the
    # middleware value already contains magnetometer=().
    # The eleventh, xr-spatial-tracking, is safe to lock here: the SPA has
    # no XR flow (zero navigator.xr/XRSession/XRSystem/immersive-ar/
    # immersive-vr/requestSession matches in frontend/app/src,
    # verified by grep this run), and the middleware value already
    # contains xr-spatial-tracking=().
    # The twelfth, idle-detection, is safe to lock here: the SPA has
    # no idle-detection flow (zero IdleDetector/idle matches in
    # frontend/app/src, verified by grep this run), and the
    # middleware value already contains idle-detection=()
    # immediately after xr-spatial-tracking=().
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
    # the twelve most sensitive directives as disabled, mirroring the
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
    # The eighth, accelerometer, is safe to lock here: the SPA has
    # no motion-sensor flow (zero DeviceMotion/DeviceOrientation/
    # Accelerometer API uses in frontend/app/src, verified by grep
    # this run), and the middleware value already contains
    # accelerometer=().
    # The ninth, gyroscope, is safe to lock here: the SPA has
    # no gyroscope flow (zero Gyroscope/DeviceOrientation matches
    # in frontend/app/src, verified by grep this run), and the
    # middleware value already contains gyroscope=().
    # The tenth, magnetometer, is safe to lock here: the SPA has
    # no compass flow (zero Magnetometer/magnetometer matches in
    # frontend/app/src, verified by grep this run), and the
    # middleware value already contains magnetometer=().
    # The eleventh, xr-spatial-tracking, is safe to lock here: the SPA has
    # no XR flow (zero navigator.xr/XRSession/XRSystem/immersive-ar/
    # immersive-vr/requestSession matches in frontend/app/src,
    # verified by grep this run), and the middleware value already
    # contains xr-spatial-tracking=().
    # The twelfth, idle-detection, is safe to lock here: the SPA has
    # no idle-detection flow (zero IdleDetector/idle matches in
    # frontend/app/src, verified by grep this run), and the
    # middleware value already contains idle-detection=()
    # immediately after xr-spatial-tracking=().
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
    # the twelve most sensitive directives as disabled, mirroring the
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
    # The eighth, accelerometer, is safe to lock here: the SPA has
    # no motion-sensor flow (zero DeviceMotion/DeviceOrientation/
    # Accelerometer API uses in frontend/app/src, verified by grep
    # this run), and the middleware value already contains
    # accelerometer=().
    # The ninth, gyroscope, is safe to lock here: the SPA has
    # no gyroscope flow (zero Gyroscope/DeviceOrientation matches
    # in frontend/app/src, verified by grep this run), and the
    # middleware value already contains gyroscope=().
    # The tenth, magnetometer, is safe to lock here: the SPA has
    # no compass flow (zero Magnetometer/magnetometer matches in
    # frontend/app/src, verified by grep this run), and the
    # middleware value already contains magnetometer=().
    # The eleventh, xr-spatial-tracking, is safe to lock here: the SPA has
    # no XR flow (zero navigator.xr/XRSession/XRSystem/immersive-ar/
    # immersive-vr/requestSession matches in frontend/app/src,
    # verified by grep this run), and the middleware value already
    # contains xr-spatial-tracking=().
    # The twelfth, idle-detection, is safe to lock here: the SPA has
    # no idle-detection flow (zero IdleDetector/idle matches in
    # frontend/app/src, verified by grep this run), and the
    # middleware value already contains idle-detection=()
    # immediately after xr-spatial-tracking=().
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
    # the twelve most sensitive directives as disabled, mirroring the
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
    # The eighth, accelerometer, is safe to lock here: the SPA has
    # no motion-sensor flow (zero DeviceMotion/DeviceOrientation/
    # Accelerometer/Gyroscope/Magnetometer uses in frontend/app/src,
    # verified by grep this run), and the middleware value already
    # contains accelerometer=().
    # The ninth, gyroscope, is safe to lock here: the SPA has
    # no gyroscope flow (zero Gyroscope/DeviceOrientation matches
    # in frontend/app/src, verified by grep this run), and the
    # middleware value already contains gyroscope=().
    # The tenth, magnetometer, is safe to lock here: the SPA has
    # no compass flow (zero Magnetometer/magnetometer matches in
    # frontend/app/src, verified by grep this run), and the
    # middleware value already contains magnetometer=().
    # The eleventh, xr-spatial-tracking, is safe to lock here: the
    # SPA has no XR flow (zero navigator.xr/XRSession/XRSystem/
    # immersive-ar/immersive-vr/requestSession matches in
    # frontend/app/src and no webxr/three dependency, verified by
    # grep this run), and the middleware value already contains
    # xr-spatial-tracking=() immediately after magnetometer=().
    # The twelfth, idle-detection, is safe to lock here: the SPA has
    # no idle-detection flow (zero IdleDetector/idle matches in
    # frontend/app/src, verified by grep this run), and the
    # middleware value already contains idle-detection=()
    # immediately after xr-spatial-tracking=().
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
    # the twelve most sensitive directives as disabled, mirroring the
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
    # The eighth, accelerometer, is safe to lock here: the SPA has
    # no motion-sensor flow (zero DeviceMotion/DeviceOrientation/
    # Accelerometer/Gyroscope/Magnetometer uses in frontend/app/src,
    # verified by grep this run), and the middleware value already
    # contains accelerometer=().
    # The ninth, gyroscope, is safe to lock here: the SPA has
    # no gyroscope flow (zero Gyroscope/DeviceOrientation matches
    # in frontend/app/src, verified by grep this run), and the
    # middleware value already contains gyroscope=().
    # The tenth, magnetometer, is safe to lock here: the SPA has
    # no compass flow (zero Magnetometer/magnetometer matches in
    # frontend/app/src, verified by grep this run), and the
    # middleware value already contains magnetometer=().
    # The eleventh, xr-spatial-tracking, is safe to lock here: the
    # SPA has no XR flow (zero navigator.xr/XRSession/XRSystem/
    # immersive-ar/immersive-vr/requestSession matches in
    # frontend/app/src and no webxr/three dependency, verified by
    # grep this run), and the middleware value already contains
    # xr-spatial-tracking=() immediately after magnetometer=().
    # The twelfth, idle-detection, is safe to lock here: the SPA has
    # no idle-detection flow (zero IdleDetector/idle matches in
    # frontend/app/src, verified by grep this run), and the
    # middleware value already contains idle-detection=()
    # immediately after xr-spatial-tracking=().
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
    # the twelve most sensitive directives as disabled, mirroring the
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
    # The eighth, accelerometer, is safe to lock here: the SPA has
    # no motion-sensor flow (zero DeviceMotion/DeviceOrientation/
    # Accelerometer/Gyroscope/Magnetometer uses in frontend/app/src,
    # verified by grep this run), and the middleware value already
    # contains accelerometer=().
    # The ninth, gyroscope, is safe to lock here: the SPA has
    # no gyroscope flow (zero Gyroscope/DeviceOrientation matches
    # in frontend/app/src, verified by grep this run), and the
    # middleware value already contains gyroscope=().
    # The tenth, magnetometer, is safe to lock here: the SPA has
    # no compass flow (zero Magnetometer/magnetometer matches in
    # frontend/app/src, verified by grep this run), and the
    # middleware value already contains magnetometer=().
    # The eleventh, xr-spatial-tracking, is safe to lock here: the
    # SPA has no XR flow (zero navigator.xr/XRSession/XRSystem/
    # immersive-ar/immersive-vr/requestSession matches in
    # frontend/app/src and no webxr/three dependency, verified by
    # grep this run), and the middleware value already contains
    # xr-spatial-tracking=() immediately after magnetometer=().
    # The twelfth, idle-detection, is safe to lock here: the SPA has
    # no idle-detection flow (zero IdleDetector/idle matches in
    # frontend/app/src, verified by grep this run), and the
    # middleware value already contains idle-detection=()
    # immediately after xr-spatial-tracking=().
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
    # the twelve most sensitive directives as disabled, mirroring the
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
    # The eighth, accelerometer, is safe to lock here: the SPA has
    # no motion-sensor flow (zero DeviceMotion/DeviceOrientation/
    # Accelerometer/Gyroscope/Magnetometer uses in frontend/app/src,
    # verified by grep this run), and the middleware value already
    # contains accelerometer=().
    # The ninth, gyroscope, is safe to lock here: the SPA has
    # no gyroscope flow (zero Gyroscope/DeviceOrientation matches
    # in frontend/app/src, verified by grep this run), and the
    # middleware value already contains gyroscope=().
    # The tenth, magnetometer, is safe to lock here: the SPA has
    # no compass flow (zero Magnetometer/magnetometer matches in
    # frontend/app/src, verified by grep this run), and the
    # middleware value already contains magnetometer=().
    # The eleventh, xr-spatial-tracking, is safe to lock here: the
    # SPA has no XR flow (zero navigator.xr/XRSession/XRSystem/
    # immersive-ar/immersive-vr/requestSession matches in
    # frontend/app/src and no webxr/three dependency, verified by
    # grep this run), and the middleware value already contains
    # xr-spatial-tracking=() immediately after magnetometer=().
    # The twelfth, idle-detection, is safe to lock here: the SPA has
    # no idle-detection flow (zero IdleDetector/idle matches in
    # frontend/app/src, verified by grep this run), and the
    # middleware value already contains idle-detection=()
    # immediately after xr-spatial-tracking=().
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
    # the twelve most sensitive directives as disabled, mirroring the
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
    # The eighth, accelerometer, is safe to lock here: the SPA has
    # no motion-sensor flow (zero DeviceMotion/DeviceOrientation/
    # Accelerometer/Gyroscope/Magnetometer matches in src), and the
    # middleware value already contains accelerometer=().
    # The ninth, gyroscope, is safe to lock here: the SPA has
    # no gyroscope flow (zero Gyroscope/DeviceOrientation matches
    # in frontend/app/src, verified by grep this run), and the
    # middleware value already contains gyroscope=().
    # The tenth, magnetometer, is safe to lock here: the SPA has
    # no compass flow (zero Magnetometer/magnetometer matches in
    # frontend/app/src, verified by grep this run), and the
    # middleware value already contains magnetometer=().
    # The eleventh, xr-spatial-tracking, is safe to lock here: the
    # SPA has no XR flow (zero navigator.xr/XRSession/XRSystem/
    # immersive-ar/immersive-vr/requestSession matches in
    # frontend/app/src and no webxr/three dependency, verified by
    # grep this run), and the middleware value already contains
    # xr-spatial-tracking=() immediately after magnetometer=().
    # The twelfth, idle-detection, is safe to lock here: the SPA has
    # no idle-detection flow (zero case-insensitive idle matches and
    # zero IdleDetector/requestIdleCallback matches in frontend/app/src,
    # verified by grep this run), and the middleware value already
    # contains idle-detection=() immediately after xr-spatial-tracking=().
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
        # the twelve most sensitive directives as disabled, as on the
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
        # flow exists to break. The eighth, accelerometer, is safe
        # to lock here: the SPA never reads motion sensors (zero
        # Accelerometer/Gyroscope/Magnetometer/DeviceMotion/
        # DeviceOrientation matches in frontend/app/src, verified
        # by grep this run), and the middleware value already
        # contains accelerometer=(). The ninth, gyroscope, is safe
        # to lock here: the SPA has no gyroscope flow (zero
        # Gyroscope/DeviceOrientation matches in frontend/app/src,
        # verified by grep this run), and the middleware value
        # already contains gyroscope=(). The tenth, magnetometer,
        # is safe to lock here: the SPA has no compass flow (zero
        # Magnetometer/magnetometer matches in frontend/app/src,
        # verified by grep this run), and the middleware value
        # already contains magnetometer=(). The eleventh,
        # xr-spatial-tracking, is safe to lock here: the SPA has
        # no XR flow (zero navigator.xr/XRSession/XRSystem/
        # immersive-ar/immersive-vr/requestSession matches in
        # frontend/app/src and no webxr/three dependency, verified
        # by grep this run), and the middleware value already
        # contains xr-spatial-tracking=() immediately after
        # magnetometer=().
        # The twelfth, idle-detection, is safe to lock here: the SPA has
        # no idle-detection flow (zero IdleDetector/idle matches in
        # frontend/app/src, verified by grep this run), and the
        # middleware value already contains idle-detection=()
        # immediately after xr-spatial-tracking=().
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
    # the twelve most sensitive directives as disabled, as on the
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
    # The eighth, accelerometer, is safe to lock here: the SPA has
    # no motion-sensor flow to break (zero DeviceMotion/
    # DeviceOrientation/Accelerometer/Gyroscope/Magnetometer
    # matches in frontend/app/src, verified by grep this run),
    # and the middleware value already contains accelerometer=().
    # The ninth, gyroscope, is safe to lock here: the SPA has no
    # gyroscope flow (zero Gyroscope/DeviceOrientation matches in
    # frontend/app/src, verified by grep this run), and the
    # middleware value already contains gyroscope=().
    # The tenth, magnetometer, is safe to lock here: the SPA has no
    # compass flow (zero Magnetometer/magnetometer matches in
    # frontend/app/src, verified by grep this run), and the
    # middleware value already contains magnetometer=().
    # The eleventh, xr-spatial-tracking, is safe to lock here: the SPA has
    # no XR flow (zero navigator.xr/XRSession/XRSystem/immersive-ar/
    # immersive-vr/requestSession matches in frontend/app/src,
    # verified by grep this run, and no webxr/three entry in
    # frontend/app/package.json), and the middleware value already
    # contains xr-spatial-tracking=() immediately after
    # magnetometer=().
    # The twelfth, idle-detection, is safe to lock here: the SPA has
    # no idle-detection flow (zero IdleDetector/idle matches in
    # frontend/app/src, verified by grep this run), and the
    # middleware value already contains idle-detection=()
    # immediately after xr-spatial-tracking=().
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
    # the twelve most sensitive directives as disabled, as on paginated
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
    # The eighth, accelerometer, is safe to lock here: the SPA has
    # no motion-sensor flow to break (zero DeviceMotion/
    # DeviceOrientation/Accelerometer/Gyroscope/Magnetometer
    # matches in frontend/app/src, verified by grep this run),
    # and the middleware value already contains accelerometer=().
    # The ninth, gyroscope, is safe to lock here: the SPA has no
    # gyroscope flow (zero Gyroscope/DeviceOrientation matches in
    # frontend/app/src, verified by grep this run), and the
    # middleware value already contains gyroscope=().
    # The tenth, magnetometer, is safe to lock here: the SPA has no
    # compass flow (zero Magnetometer/magnetometer matches in
    # frontend/app/src, verified by grep this run), and the
    # middleware value already contains magnetometer=().
    # The eleventh, xr-spatial-tracking, is safe to lock here: the SPA has
    # no XR flow (zero navigator.xr/XRSession/XRSystem/immersive-ar/
    # immersive-vr/requestSession matches in frontend/app/src,
    # verified by grep this run, and no webxr/three entry in
    # frontend/app/package.json), and the middleware value already
    # contains xr-spatial-tracking=() immediately after
    # magnetometer=().
    # The twelfth, idle-detection, is safe to lock here: the SPA has
    # no idle-detection flow (zero IdleDetector/idle matches in
    # frontend/app/src, verified by grep this run), and the
    # middleware value already contains idle-detection=()
    # immediately after xr-spatial-tracking=().
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
    # the twelve most sensitive directives as disabled, as on paginated
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
    # grep this run), so no fullscreen flow exists to break. The
    # eighth, accelerometer, is safe to lock here: the SPA has no
    # motion-sensor flow to break (zero DeviceMotion/
    # DeviceOrientation/Accelerometer/Gyroscope/Magnetometer
    # matches in frontend/app/src, verified by grep this run),
    # and the middleware value already contains accelerometer=().
    # The ninth, gyroscope, is safe to lock here: the SPA has no
    # gyroscope flow (zero Gyroscope/DeviceOrientation matches in
    # frontend/app/src, verified by grep this run), and the
    # middleware value already contains gyroscope=().
    # The tenth, magnetometer, is safe to lock here: the SPA has no
    # compass flow (zero Magnetometer/magnetometer matches in
    # frontend/app/src, verified by grep this run), and the
    # middleware value already contains magnetometer=().
    # The eleventh, xr-spatial-tracking, is safe to lock here: the SPA has
    # no XR flow (zero navigator.xr/XRSession/XRSystem/immersive-ar/
    # immersive-vr/requestSession matches in frontend/app/src,
    # verified by grep this run, and no webxr/three entry in
    # frontend/app/package.json), and the middleware value already
    # contains xr-spatial-tracking=() immediately after
    # magnetometer=().
    # The twelfth, idle-detection, is safe to lock here: the SPA has
    # no idle-detection flow (zero IdleDetector/idle matches in
    # frontend/app/src, verified by grep this run), and the
    # middleware value already contains idle-detection=()
    # immediately after xr-spatial-tracking=().
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
    # the twelve most sensitive directives as disabled, as on the
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
    # The eighth, accelerometer, is safe to lock here: the SPA
    # has no motion-sensor flow (zero DeviceMotion/
    # DeviceOrientation/Accelerometer/Gyroscope/Magnetometer
    # matches in frontend/app/src, verified by grep this run),
    # and the middleware value already contains accelerometer=().
    # The ninth, gyroscope, is safe to lock here: the SPA has no
    # gyroscope flow (zero Gyroscope/DeviceOrientation matches in
    # frontend/app/src, verified by grep this run), and the
    # middleware value already contains gyroscope=().
    # The tenth, magnetometer, is safe to lock here: the SPA has
    # no compass flow (zero Magnetometer/magnetometer matches in
    # frontend/app/src, verified by grep this run), and the
    # middleware value already contains magnetometer=().
    # The eleventh, xr-spatial-tracking, is safe to lock here: the SPA has
    # no XR flow (zero navigator.xr/XRSession/XRSystem/immersive-ar/
    # immersive-vr/requestSession matches in frontend/app/src,
    # verified by grep this run), and the middleware value already
    # contains xr-spatial-tracking=() immediately after magnetometer=().
    # The twelfth, idle-detection, is safe to lock here: the SPA has
    # no idle-detection flow (zero IdleDetector/idle matches in
    # frontend/app/src, verified by grep this run), and the
    # middleware value already contains idle-detection=()
    # immediately after xr-spatial-tracking=().
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
    # Same no-store lock as the post-delete re-GET 404 above: this 406
    # goes through the central api_exception_handler, which sets
    # Cache-Control: no-store and Pragma: no-cache on every
    # ApiBaseException error response — but this test locked only the
    # security headers, so deleting those cache headers would have
    # gone uncaught on this error response.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"
    assert response.json()["error"] == "Password must be at least 8 characters long, include uppercase and lowercase letters, a number, and a special character."


@pytest.mark.asyncio
async def test_activate_trial_plan_with_feature_disabled_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        The tenant trial-activation PATCH was the one
        feature-gated tenant route with no lock: the tenant
        test file locked list, create, search-by-subdomain,
        search-by-name, delete, re-GET-after-delete, and
        validation error paths, but never
        PATCH /tenants/{tenant_id}/activate_trial_plan, so
        dropping that route's per-route STRIPE gate — or
        dropping the central ApiBaseException no-store lines
        or the security-headers middleware registration —
        would previously have gone uncaught on this route.
        The success path is not asserted here: activation
        needs a Stripe trial plan, a billing plan list, and
        a tenant write, none of which the shared conftest
        client provides. The error path below is
        deterministic instead. It differs from the Stripe
        settings routes, whose feature-disabled 403 variant
        stays untested for a structural reason: on the
        settings router the permission dependency is listed
        BEFORE the feature gate, so the DB role lookup
        raises RoleNotFoundException 404 before the gate
        ever runs, and no seeded role exists in the shared
        conftest client to pass it. On this route the gate
        is a handler dependency listed in the signature
        BEFORE the HOST_MANAGE_TENANTS permission
        dependency (tenant_endpoint.py), and the service
        factories ahead of it only resolve container
        singletons without a lookup — so the gate runs
        before the permission check, the scope guard, any
        tenant lookup, the billing plan list, and any
        Stripe trial creation: no side effect, no live
        external call, and the path tenant_id is never
        read. The PATCH carries no body, so no 422 can
        mask the 403. The per-test MeResponseDto override
        (role with no permissions, no tenant) is reused
        from the AI locks because the shared conftest mock
        is a plain UserDto with no role attribute and
        would 500 under the gate; the host-scope branch of
        check_feature_access then raises
        FeatureNotEnabledException("stripe") before the
        handler runs, and the original override is
        restored in finally. That 403 must still carry the
        error-response headers: a cached 403 could
        otherwise be served to a different admin after an
        account switch, and trial activation mutates a
        tenant's subscription.
    """
    async def override_get_current_user_with_role():
        return MeResponseDto(
            first_name="Admin",
            last_name="User",
            id="68c302ef6bf7a039b7e9b385",
            email="admin@example.com",
            gender=Gender.OTHER,
            is_active=True,
            role_id="68c302ef6bf7a039b7e9b386",
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
    app.dependency_overrides[get_current_user] = override_get_current_user_with_role
    try:
        response = await client.patch("/tenants/68c302ef6bf7a039b7e9b385/activate_trial_plan")
    finally:
        if original_override is None:
            app.dependency_overrides.pop(get_current_user, None)
        else:
            app.dependency_overrides[get_current_user] = original_override
    assert response.status_code == 403
    body = response.json()
    assert body["code"] == 403
    assert "stripe" in body["error"]
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the other tenant tests:
    # the pure-ASGI middleware stamps every HTTP response
    # with no path exclusions, so this PATCH 403 must
    # carry the same headers as the tenant GETs and POSTs.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Lock the twelve most sensitive directives as
    # disabled, mirroring the other tenant locks, using
    # substring checks so later additions to the list do
    # not break this test. The idle-detection
    # justification was re-verified fresh this run: zero
    # case-insensitive idle matches and zero
    # IdleDetector/requestIdleCallback matches across
    # frontend/app/src.
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
async def test_get_tenant_features_with_missing_role_returns_404_with_cache_and_security_headers(client: AsyncClient):
    """
        The tenant features GET was the one tenant read with no
        lock: the tenant test file locked list, create,
        search-by-subdomain, search-by-name, delete,
        re-GET-after-delete, validation, and the
        trial-activation PATCH, but never
        GET /tenants/{tenant_id}/features, so dropping that
        route — or dropping the central ApiBaseException
        no-store lines or the security-headers middleware
        registration — would previously have gone uncaught
        on this route. The success path is not asserted
        here: the GET is permission-gated
        (HOST_MANAGE_TENANTS), so it needs a DB role
        lookup, and the shared conftest client seeds no
        role — the /features/ test documents the same
        exclusion for its catalogue endpoint. The error
        path below is deterministic instead: the mocked
        host user's role_id points at no row in the fresh
        test database (Role is in the conftest model set),
        so the permission dependency raises
        RoleNotFoundException before the scope guard, any
        tenant lookup, or any feature data is returned —
        no side effect, and the path tenant_id is never
        read. The GET takes no body or query params, so
        no 422 can mask the 404. That 404 must still carry
        the error-response headers: a cached 404 could
        otherwise be served to a different admin after an
        account switch, and the success path returns one
        tenant's paid-feature enablement.
    """
    response = await client.get("/tenants/68c302ef6bf7a039b7e9b385/features")
    assert response.status_code == 404
    body = response.json()
    assert body["code"] == 404
    assert "Role" in body["error"]
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
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


async def test_update_tenant_feature_with_missing_role_returns_404_with_cache_and_security_headers(client: AsyncClient):
    """
        PATCH /tenants/{tenant_id}/update_feature was the one
        tenant mutation with no lock: the tenant test file
        locked list, create, search-by-subdomain,
        search-by-name, delete, re-GET-after-delete,
        validation, the trial-activation PATCH, and the
        features GET, but never this feature-toggle PATCH,
        so dropping that route — or dropping the central
        ApiBaseException no-store lines or the
        security-headers middleware registration — would
        previously have gone uncaught on this route. The
        success path is not asserted here: the PATCH is
        permission-gated (HOST_MANAGE_TENANTS), so it
        needs a DB role lookup, and the shared conftest
        client seeds no role. The error path below is
        deterministic instead: the mocked host user's
        role_id points at no row in the fresh test
        database (Role is in the conftest model set), so
        the permission dependency raises
        RoleNotFoundException before the scope guard, any
        tenant lookup, or any feature write — no side
        effect, and the path tenant_id is never read. The
        body is a valid FeatureDto (name "stripe",
        enabled true), so no 422 can mask the 404.
        That 404 must still carry the error-response
        headers: a cached 404 could otherwise be served
        to a different admin after an account switch,
        and the success path toggles a tenant's paid
        features.
    """
    response = await client.patch("/tenants/68c302ef6bf7a039b7e9b385/update_feature", json={"name": "stripe", "enabled": True})
    assert response.status_code == 404
    body = response.json()
    assert body["code"] == 404
    assert "Role" in body["error"]
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
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
async def test_update_tenant_with_missing_role_returns_404_with_cache_and_security_headers(client: AsyncClient):
    """
        PUT /tenants/{tenant_id} was the one tenant mutation
        with no lock: the tenant test file locked list,
        create, search-by-subdomain, search-by-name,
        delete, re-GET-after-delete, validation, the
        trial-activation PATCH, the features GET, and the
        update_feature PATCH, but never this tenant
        update PUT, so dropping that route — or dropping
        the central ApiBaseException no-store lines or the
        security-headers middleware registration — would
        previously have gone uncaught on this route. The
        success path is not asserted here: the PUT is
        permission-gated (HOST_MANAGE_TENANTS), so it
        needs a DB role lookup, and the shared conftest
        client seeds no role. The error path below is
        deterministic instead: the mocked host user's
        role_id points at no row in the fresh test
        database (Role is in the conftest model set), so
        the permission dependency raises
        RoleNotFoundException before the scope guard, any
        tenant lookup, or any tenant write — no side
        effect, and the path tenant_id is never read. The
        body is a valid UpdateTenantDto (is_active true;
        all fields optional), so no 422 can mask the 404.
        That 404 must still carry the error-response
        headers: a cached 404 could otherwise be served
        to a different admin after an account switch,
        and the success path overwrites a tenant's
        is_active, custom_domain, or subscription_id.
    """
    response = await client.put("/tenants/68c302ef6bf7a039b7e9b385", json={"is_active": True})
    assert response.status_code == 404
    body = response.json()
    assert body["code"] == 404
    assert "Role" in body["error"]
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
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
async def test_update_tenant_dns_with_missing_role_returns_404_with_cache_and_security_headers(client: AsyncClient):
    """
        POST /tenants/{tenant_id}/update_dns was the one tenant
        mutation with no lock: the tenant test file locked list,
        create, search-by-subdomain, search-by-name,
        delete, re-GET-after-delete, validation, the
        trial-activation PATCH, the features GET, the
        update_feature PATCH, and the update PUT, but never
        this DNS-update POST, so dropping that route — or
        dropping the central ApiBaseException no-store lines
        or the security-headers middleware registration —
        would previously have gone uncaught on this route.
        The success path is not asserted here: the POST is
        permission-gated (HOST_MANAGE_TENANTS or
        MANAGE_TENANT_SETTINGS), so it needs a DB role
        lookup, and the shared conftest client seeds no
        role. The error path below is deterministic
        instead: the mocked host user's role_id points at
        no row in the fresh test database (Role is in the
        conftest model set), so the permission dependency
        raises RoleNotFoundException before the scope
        guard, any tenant lookup, any tenant write, or
        any DNS-update job enqueue — no side effect, and
        the path tenant_id is never read. The body is a
        valid UpdateTenantDto (custom_domain
        app.example.com, which passes the custom-domain
        validator and is not the host main domain), so no
        422 can mask the 404. That 404 must still carry
        the error-response headers: a cached 404 could
        otherwise be served to a different admin after an
        account switch, and the success path overwrites a
        tenant's custom_domain / is_active and enqueues a
        DNS-update job.
    """
    response = await client.post("/tenants/68c302ef6bf7a039b7e9b385/update_dns", json={"custom_domain": "app.example.com"})
    assert response.status_code == 404
    body = response.json()
    assert body["code"] == 404
    assert "Role" in body["error"]
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
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
async def test_check_tenant_dns_with_missing_role_returns_404_with_cache_and_security_headers(client: AsyncClient):
    """
        GET /tenants/{tenant_id}/check_dns was the one tenant
        read with no lock: the tenant test file locked list,
        create, search-by-subdomain, search-by-name,
        delete, re-GET-after-delete, validation, the
        trial-activation PATCH, the features GET, the
        update_feature PATCH, the update PUT, and the
        DNS-update POST, but never this DNS-status GET,
        so dropping that route — or dropping the central
        ApiBaseException no-store lines or the
        security-headers middleware registration — would
        previously have gone uncaught on this route. The
        success path is not asserted here: the GET is
        permission-gated (HOST_MANAGE_TENANTS or
        MANAGE_TENANT_SETTINGS), so it needs a DB role
        lookup, and the shared conftest client seeds no
        role. The error path below is deterministic
        instead: the mocked host user's role_id points at
        no row in the fresh test database (Role is in the
        conftest model set), so the permission dependency
        raises RoleNotFoundException before the scope
        guard, any tenant lookup, or any DNS-update job
        enqueue — no side effect, and the path tenant_id
        is never read. The GET takes no body or query
        params, so no 422 can mask the 404. That 404 must
        still carry the error-response headers: a cached
        404 could otherwise be served to a different admin
        after an account switch, and the success path is a
        side-effect GET that enqueues a DNS-update job
        and returns a status message that changes as
        activation proceeds.
    """
    response = await client.get("/tenants/68c302ef6bf7a039b7e9b385/check_dns")
    assert response.status_code == 404
    body = response.json()
    assert body["code"] == 404
    assert "Role" in body["error"]
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
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
async def test_check_subdomain_availability_returns_200_with_cache_and_security_headers(client: AsyncClient):
    """
        GET /tenants/check_subdomain/{subdomain} was the last
        tenant route with no lock: the tenant test file locked
        list, create, search-by-subdomain, search-by-name,
        delete, re-GET-after-delete, validation, the
        trial-activation PATCH, the features GET, the
        update_feature PATCH, the update PUT, the DNS-update
        POST, and the DNS-check GET, but never this
        availability GET, so dropping the two no-store header
        lines in its handler — or dropping the
        security-headers middleware registration — would
        previously have gone uncaught on this route. The
        success path here is deterministic: this GET is
        public (no permission dependency), so unlike the
        gated tenant routes it needs no seeded role; the
        subdomain "available.fsrapp.com" is valid under the
        default host main domain (fsrapp.com), and the fresh
        test database holds no tenant with it, so the
        service raises TenantNotFoundException and the
        handler returns is_available True — a read-only
        lookup with no side effect, and the GET takes no
        body or query params, so no 422 can mask the 200.
        That 200 must still carry the no-store headers: a
        cached answer could report a subdomain as available
        after it was just registered (or as taken after it
        was freed), and the registration dialog trusts this
        answer before creating the tenant.
    """
    response = await client.get("/tenants/check_subdomain/available.fsrapp.com")
    assert response.status_code == 200
    assert response.json()["is_available"] is True
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
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
async def test_delete_tenant_outside_tenant_scope_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        The tenant DELETE delete-scope-guard error path:
        the tenant test file locked the DELETE route itself
        (host delete, re-GET-after-delete) and the
        missing-role 404s for the PUT, the DNS-update POST,
        the DNS-check GET, the features GET, the
        update_feature PATCH, and the trial-activation
        PATCH, but no test asserted a 403 on DELETE
        /tenants/{id} via _assert_tenant_delete_scope -
        function-name grep count 0 for
        delete_tenant_outside_tenant_scope, verified fresh
        this run. Dropping _assert_tenant_delete_scope
        (tenant_endpoint.py:107-125) would previously have
        gone uncaught, and a tenant caller deleting on the
        host DB could then delete a tenant record sitting
        in the host DB and dispatch its post-deletion job,
        as the guard's own comment describes (the stamp
        check in delete_tenant only compares against the
        record the request's database returned). The guard
        runs first in the handler body
        (tenant_endpoint.py:250), before the try block and
        before any tenant read, deletion, or worker
        dispatch, so no deletion happens. It cannot be
        reached the way the missing-role 404 locks reach
        the route (host caller, no seeded role): the
        permission dependency runs before the guard, so
        the seeded role (id
        68c302ef6bf7a039b7e9b386) must carry the route's
        HOST_MANAGE_TENANTS permission, and the caller
        override mirrors the stripe scope locks'
        pattern (per-test MeResponseDto, restored in
        finally). The caller is tenant-scoped to
        68c302ef6bf7a039b7e9b387 while the request carries
        X-Tenant-ID 68c302ef6bf7a039b7e9b388, so the guard
        fires on the mismatch. The tenant router carries
        no feature gate, so no seeded tenant feature is
        needed to reach the guard; the request scope comes
        from the header alone, and the middleware's
        tenant-DB init targets the default 27017 URI,
        which has no listener in the test/dev environment
        (dev/test Mongo is on 27012 per CONTRIBUTE.md),
        so it falls back to host scope and the guard fires
        on caller-387 vs scope-None - and even if the
        scope resolved to 388 the guard would fire the
        same way (387 vs 388), so the 403 does not depend
        on which of the two scope values the middleware
        produces. get_role_detail calls get_role_by_id
        with no tenant argument
        (user_access_management.py), so _caller_may_access
        sees a None caller tenant and returns True
        (role_service.py:18-19), and the seeded row is
        visible regardless of the caller's tenant scope -
        the same mechanism the stripe scope locks rely on.
        The DELETE takes no body or query params, so no
        422 can mask the 403. The central ApiBaseException
        handler maps ForbiddenException to 403
        (api/__init__.py:98-103) with {"error": ...,
        "code": 403} and the no-store/Pragma error headers.
        A future change that drops the guard would break
        this lock while leaving the DELETE 404 lock green,
        so the paths are locked separately.
    """
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.entities.tenant import Tenant
    from api.domain.enum.permission import Permission

    await Tenant(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b385"),
        name="delete-scope-tenant",
        subdomain="delete-scope.fsrapp.com",
    ).insert()
    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Tenant tenant administrator",
        description="Role carrying HOST_MANAGE_TENANTS for the mocked caller",
        permissions=[Permission.HOST_MANAGE_TENANTS],
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
                name="Tenant tenant administrator",
                description="Role carrying HOST_MANAGE_TENANTS for the mocked caller",
                created_at="2024-10-01T00:00:00Z",
                updated_at="2024-10-01T00:00:00Z",
                permissions=[Permission.HOST_MANAGE_TENANTS],
            ),
            subscription=None,
        )

    original_override = app.dependency_overrides.get(get_current_user)
    app.dependency_overrides[get_current_user] = override_get_current_user_tenant_scoped
    try:
        response = await client.delete(
            "/tenants/68c302ef6bf7a039b7e9b385",
            headers={"X-Tenant-ID": "68c302ef6bf7a039b7e9b388"},
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
    # delete-scope guard raises before the handler's try block,
    # and the DELETE takes no Response param, so on this path
    # the no-store/Pragma headers come from the central
    # ApiBaseException handler, and a cached 403 could
    # otherwise be served to a different admin after an
    # account switch on a shared machine.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the other tenant tests in
    # this file: the pure-ASGI middleware stamps every HTTP
    # response with no path exclusions, so this authenticated
    # tenant 403 must carry the same headers as the other
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
    # Postconditions: the guard fires before any tenant read,
    # deletion, or worker dispatch, so the DELETE is
    # side-effect free - the seeded role is still there with
    # HOST_MANAGE_TENANTS and, decisively, the seeded tenant
    # row still exists: had the guard been dropped, the
    # handler would have deleted it (its id matches the path
    # and, on the host DB, the stamp check would have passed)
    # and dispatched the post-deletion job.
    stored_role = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored_role is not None
    assert stored_role.permissions == [Permission.HOST_MANAGE_TENANTS]
    stored_tenant = await Tenant.find_one(
        Tenant.id == PydanticObjectId("68c302ef6bf7a039b7e9b385")
    )
    assert stored_tenant is not None
    assert stored_tenant.name == "delete-scope-tenant"


@pytest.mark.asyncio
async def test_update_tenant_outside_tenant_scope_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        The tenant PUT update-scope-guard error path:
        the tenant test file locked the PUT route itself
        only as a missing-role 404 (the permission
        dependency raises RoleNotFoundException before
        the scope guard, any tenant lookup, or any tenant
        write) and locked the DELETE route's scope guard
        the previous run, but no test asserted a 403 on
        PUT /tenants/{tenant_id} via
        _assert_tenant_update_scope - function-name grep
        count 0 for update_tenant_outside_tenant_scope,
        verified fresh this run. Dropping
        _assert_tenant_update_scope
        (tenant_endpoint.py:48-66) would previously have
        gone uncaught, and a tenant caller updating on
        the host DB could then overwrite a tenant record
        sitting in the host DB, as the guard's own comment
        describes (the stamp check in update_tenant only
        compares against the record the request's database
        returned). The guard runs first in the handler
        body (tenant_endpoint.py:534), before
        get_tenant_by_id and any tenant write, so no
        update happens. It cannot be reached the way the
        missing-role 404 lock reaches the route (host
        caller, no seeded role): the permission dependency
        runs before the guard, so the seeded role (id
        68c302ef6bf7a039b7e9b386) must carry the route's
        HOST_MANAGE_TENANTS permission, and the caller
        override mirrors the stripe scope locks' and the
        DELETE scope lock's pattern (per-test
        MeResponseDto, restored in finally). The caller
        is tenant-scoped to
        68c302ef6bf7a039b7e9b387 while the request carries
        X-Tenant-ID 68c302ef6bf7a039b7e9b388, so the guard
        fires on the mismatch. The seeded tenant carries
        the caller's own tenant id (387), not the 385 of
        the DELETE lock: without the guard, the stamp
        check at tenant_endpoint.py:535-536 would pass
        (tenant.id == caller tenant id) and the update
        would go through, so the is_active-still-False
        postcondition below is decisive - with the
        DELETE lock's 385-vs-387 split the stamp check
        would instead have 404'd and no write could
        have happened either way. The tenant router
        carries no feature gate, so no seeded tenant
        feature is needed to reach the guard; the request
        scope comes from the header alone, and the
        middleware's tenant-DB init targets the default
        27017 URI, which has no listener in the test/dev
        environment (dev/test Mongo is on 27012 per
        CONTRIBUTE.md), so it falls back to host scope
        and the guard fires on caller-387 vs scope-None -
        and even if the scope resolved to 388 the guard
        would fire the same way (387 vs 388), so the 403
        does not depend on which of the two scope values
        the middleware produces. get_role_detail calls
        get_role_by_id with no tenant argument
        (user_access_management.py), so _caller_may_access
        sees a None caller tenant and returns True
        (role_service.py:18-19), and the seeded row is
        visible regardless of the caller's tenant scope -
        the same mechanism the stripe scope locks rely
        on. The body is a valid UpdateTenantDto
        (is_active true; all fields optional, the same
        body the missing-role 404 lock uses), so no 422
        can mask the 403. The central ApiBaseException
        handler maps ForbiddenException to 403
        (api/__init__.py:98-103) with {"error": ...,
        "code": 403} and the no-store/Pragma error
        headers. A future change that drops the guard
        would break this lock while leaving the PUT 404
        lock green, so the paths are locked separately.
    """
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.entities.tenant import Tenant
    from api.domain.enum.permission import Permission

    await Tenant(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b387"),
        name="update-scope-tenant",
        subdomain="update-scope.fsrapp.com",
    ).insert()
    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Tenant tenant administrator",
        description="Role carrying HOST_MANAGE_TENANTS for the mocked caller",
        permissions=[Permission.HOST_MANAGE_TENANTS],
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
                name="Tenant tenant administrator",
                description="Role carrying HOST_MANAGE_TENANTS for the mocked caller",
                created_at="2024-10-01T00:00:00Z",
                updated_at="2024-10-01T00:00:00Z",
                permissions=[Permission.HOST_MANAGE_TENANTS],
            ),
            subscription=None,
        )

    original_override = app.dependency_overrides.get(get_current_user)
    app.dependency_overrides[get_current_user] = override_get_current_user_tenant_scoped
    try:
        response = await client.put(
            "/tenants/68c302ef6bf7a039b7e9b387",
            json={"is_active": True},
            headers={"X-Tenant-ID": "68c302ef6bf7a039b7e9b388"},
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
    # update-scope guard raises before any tenant read or write,
    # and the PUT takes no Response param, so on this path the
    # no-store/Pragma headers come from the central
    # ApiBaseException handler, and a cached 403 could
    # otherwise be served to a different admin after an
    # account switch on a shared machine.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the other tenant tests in
    # this file: the pure-ASGI middleware stamps every HTTP
    # response with no path exclusions, so this authenticated
    # tenant 403 must carry the same headers as the other
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
    # Postconditions: the guard fires before any tenant read
    # or write, so the PUT is side-effect free - the seeded
    # role is still there with HOST_MANAGE_TENANTS and,
    # decisively, the seeded tenant row still exists with
    # is_active False (its entity default): had the guard
    # been dropped, the handler would have passed its stamp
    # check (seeded tenant id 387 equals the caller tenant
    # id) and set is_active True via update_tenant.
    stored_role = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored_role is not None
    assert stored_role.permissions == [Permission.HOST_MANAGE_TENANTS]
    stored_tenant = await Tenant.find_one(
        Tenant.id == PydanticObjectId("68c302ef6bf7a039b7e9b387")
    )
    assert stored_tenant is not None
    assert stored_tenant.name == "update-scope-tenant"
    assert stored_tenant.is_active is False


async def test_get_tenant_features_outside_tenant_scope_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        The tenant features GET scope-guard error path:
        the tenant test file locked the GET route itself
        only as a missing-role 404 (the permission
        dependency raises RoleNotFoundException before
        the scope guard, any tenant lookup, or any
        feature data is returned) and locked the PUT and
        DELETE routes' scope guards in the previous
        runs, but no test asserted a 403 on
        GET /tenants/{tenant_id}/features via
        _assert_features_read_scope - function-name grep
        count 0 for get_tenant_features_outside_tenant_scope,
        verified fresh this run. Dropping
        _assert_features_read_scope
        (tenant_endpoint.py:128-146) would previously have
        gone uncaught, and a tenant caller reading on
        the host DB could then read the feature
        enablement of a tenant record sitting in the
        host DB (e.g. which paid features it has), as
        the guard's own comment describes (the stamp
        check in get_tenant_features only compares
        against the record the request's database
        returned). The guard runs first in the handler
        body (tenant_endpoint.py:550), before
        get_tenant_by_id and any feature read, so no
        feature data is returned. It cannot be reached
        the way the missing-role 404 lock reaches the
        route (host caller, no seeded role): the
        permission dependency runs before the guard, so
        the seeded role (id
        68c302ef6bf7a039b7e9b386) must carry the route's
        HOST_MANAGE_TENANTS permission, and the caller
        override mirrors the stripe scope locks' and
        the PUT/DELETE scope locks' pattern (per-test
        MeResponseDto, restored in finally). The caller
        is tenant-scoped to
        68c302ef6bf7a039b7e9b387 while the request carries
        X-Tenant-ID 68c302ef6bf7a039b7e9b388, so the guard
        fires on the mismatch. The seeded tenant carries
        the caller's own tenant id (387), not the 385 of
        the DELETE lock: without the guard, the stamp
        check at tenant_endpoint.py:562-563 would pass
        (tenant.id == caller tenant id) and the feature
        list would be returned, so the 403 itself is
        decisive here - with the DELETE lock's 385-vs-387
        split the stamp check would instead have 404'd
        and no feature data could have been returned
        either way. The tenant router carries no feature
        gate, so no seeded tenant feature is needed to
        reach the guard; the request scope comes from
        the header alone, and the middleware's tenant-DB
        init targets the default 27017 URI, which has no
        listener in the test/dev environment (dev/test
        Mongo is on 27012 per CONTRIBUTE.md), so it
        falls back to host scope and the guard fires on
        caller-387 vs scope-None - and even if the scope
        resolved to 388 the guard would fire the same
        way (387 vs 388), so the 403 does not depend on
        which of the two scope values the middleware
        produces. get_role_detail calls
        get_role_by_id with no tenant argument
        (user_access_management.py:39), so
        _caller_may_access sees a None caller tenant
        and returns True (role_service.py:18-19), and
        the seeded row is visible regardless of the
        caller's tenant scope - the same mechanism the
        stripe scope locks rely on. The GET takes no
        body or query params, so no 422 can mask the
        403. The central ApiBaseException handler maps
        ForbiddenException to 403 (api/__init__.py:98-103)
        with {"error": ..., "code": 403} and the
        no-store/Pragma error headers. A future change
        that drops the guard would break this lock while
        leaving the GET 404 lock green, so the paths are
        locked separately.
    """
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.entities.tenant import Tenant
    from api.domain.enum.permission import Permission

    await Tenant(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b387"),
        name="features-scope-tenant",
        subdomain="features-scope.fsrapp.com",
    ).insert()
    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Tenant tenant administrator",
        description="Role carrying HOST_MANAGE_TENANTS for the mocked caller",
        permissions=[Permission.HOST_MANAGE_TENANTS],
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
                name="Tenant tenant administrator",
                description="Role carrying HOST_MANAGE_TENANTS for the mocked caller",
                created_at="2024-10-01T00:00:00Z",
                updated_at="2024-10-01T00:00:00Z",
                permissions=[Permission.HOST_MANAGE_TENANTS],
            ),
            subscription=None,
        )

    original_override = app.dependency_overrides.get(get_current_user)
    app.dependency_overrides[get_current_user] = override_get_current_user_tenant_scoped
    try:
        response = await client.get(
            "/tenants/68c302ef6bf7a039b7e9b387/features",
            headers={"X-Tenant-ID": "68c302ef6bf7a039b7e9b388"},
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
    # features-scope guard raises before any tenant read or
    # feature read, and the GET sets its no-store/Pragma headers
    # only after the guard (tenant_endpoint.py:567-568), so on
    # this path they come from the central ApiBaseException
    # handler, and a cached 403 could otherwise be served to a
    # different admin after an account switch on a shared
    # machine.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the other tenant tests in
    # this file: the pure-ASGI middleware stamps every HTTP
    # response with no path exclusions, so this authenticated
    # tenant 403 must carry the same headers as the other
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
    # Postconditions: the guard fires before any tenant read
    # or feature read, so the GET is side-effect free - the
    # seeded role is still there with HOST_MANAGE_TENANTS
    # and the seeded tenant row still exists with is_active
    # False (its entity default). Had the guard been dropped,
    # the handler would have passed its stamp check (seeded
    # tenant id 387 equals the caller tenant id) and returned
    # the feature list with a 200 instead of this 403.
    stored_role = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored_role is not None
    assert stored_role.permissions == [Permission.HOST_MANAGE_TENANTS]
    stored_tenant = await Tenant.find_one(
        Tenant.id == PydanticObjectId("68c302ef6bf7a039b7e9b387")
    )
    assert stored_tenant is not None
    assert stored_tenant.name == "features-scope-tenant"
    assert stored_tenant.is_active is False


async def test_update_tenant_feature_outside_tenant_scope_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        The tenant feature PATCH scope-guard error path:
        the tenant test file locked the PATCH route itself
        only as a missing-role 404 (the permission
        dependency raises RoleNotFoundException before
        the scope guard, any tenant lookup, or any
        feature write) and locked the GET features, PUT
        and DELETE routes' scope guards in the previous
        runs, but no test asserted a 403 on
        PATCH /tenants/{tenant_id}/update_feature via
        _assert_feature_update_scope - function-name grep
        count 0 for update_tenant_feature_outside_tenant_scope,
        verified fresh this run. Dropping
        _assert_feature_update_scope
        (tenant_endpoint.py:67-83) would previously have
        gone uncaught, and a tenant caller toggling on
        the host DB could then toggle the features of a
        tenant record sitting in the host DB (e.g.
        disable STRIPE or enable a feature that tenant
        never bought), as the guard's own comment
        describes (the stamp check in
        update_tenant_feature only compares against the
        record the request's database returned). The
        guard runs first in the handler body
        (tenant_endpoint.py:595), before
        get_tenant_by_id and any feature write, so no
        write happens. It cannot be reached the way the
        missing-role 404 lock reaches the route (host
        caller, no seeded role): the permission
        dependency runs before the guard, so the seeded
        role (id 68c302ef6bf7a039b7e9b386) must carry the
        route's HOST_MANAGE_TENANTS permission, and the
        caller override mirrors the stripe scope locks'
        and the PUT/DELETE/features scope locks' pattern
        (per-test MeResponseDto, restored in finally).
        The caller is tenant-scoped to
        68c302ef6bf7a039b7e9b387 while the request carries
        X-Tenant-ID 68c302ef6bf7a039b7e9b388, so the guard
        fires on the mismatch. The seeded tenant carries
        the caller's own tenant id (387), not the 385 of
        the DELETE lock: without the guard, the stamp
        check at tenant_endpoint.py:597 would pass
        (tenant.id == caller tenant id) and the PATCH
        body {"name": "stripe", "enabled": true} would
        enable STRIPE on the seeded tenant, so the
        features-still-empty postcondition is decisive
        here - with the DELETE lock's 385-vs-387 split
        the stamp check would instead have 404'd and no
        write could have happened either way. The body
        is a valid FeatureDto (name FeatureEnum "stripe",
        enabled bool, tenant_dto.py:9-11, feature.py:4-11),
        so no 422 can mask the 403; the handler takes no
        Response param, so the 403's no-store/Pragma
        headers come from the central ApiBaseException
        handler (api/__init__.py:98-103). The tenant
        router carries no feature gate, so no seeded
        tenant feature is needed to reach the guard; the
        request scope comes from the header alone, and
        the middleware's tenant-DB init targets the
        default 27017 URI, which has no listener in the
        test/dev environment (dev/test Mongo is on 27012
        per CONTRIBUTE.md), so it falls back to host
        scope and the guard fires on caller-387 vs
        scope-None - and even if the scope resolved to
        388 the guard would fire the same way (387 vs
        388), so the 403 does not depend on which of the
        two scope values the middleware produces.
        get_role_detail calls get_role_by_id with no
        tenant argument (user_access_management.py:39),
        so _caller_may_access sees a None caller tenant
        and returns True (role_service.py:18-19), and
        the seeded row is visible regardless of the
        caller's tenant scope - the same mechanism the
        stripe scope locks rely on. The central
        ApiBaseException handler maps ForbiddenException
        to 403 (api/__init__.py:98-103) with {"error":
        ..., "code": 403} and the no-store/Pragma error
        headers. A future change that drops the guard
        would break this lock while leaving the PATCH 404
        lock green, so the paths are locked separately.
    """
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.entities.tenant import Tenant
    from api.domain.enum.permission import Permission

    await Tenant(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b387"),
        name="update-feature-scope-tenant",
        subdomain="update-feature-scope.fsrapp.com",
    ).insert()
    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Tenant tenant administrator",
        description="Role carrying HOST_MANAGE_TENANTS for the mocked caller",
        permissions=[Permission.HOST_MANAGE_TENANTS],
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
                name="Tenant tenant administrator",
                description="Role carrying HOST_MANAGE_TENANTS for the mocked caller",
                created_at="2024-10-01T00:00:00Z",
                updated_at="2024-10-01T00:00:00Z",
                permissions=[Permission.HOST_MANAGE_TENANTS],
            ),
            subscription=None,
        )

    original_override = app.dependency_overrides.get(get_current_user)
    app.dependency_overrides[get_current_user] = override_get_current_user_tenant_scoped
    try:
        response = await client.patch(
            "/tenants/68c302ef6bf7a039b7e9b387/update_feature",
            json={"name": "stripe", "enabled": True},
            headers={"X-Tenant-ID": "68c302ef6bf7a039b7e9b388"},
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
    # feature-update-scope guard raises before any tenant read or
    # feature write, and the PATCH takes no Response param, so on
    # this path the no-store/Pragma headers come from the central
    # ApiBaseException handler, and a cached 403 could otherwise
    # be served to a different admin after an account switch on
    # a shared machine.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the other tenant tests in
    # this file: the pure-ASGI middleware stamps every HTTP
    # response with no path exclusions, so this authenticated
    # tenant 403 must carry the same headers as the other
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
    # Postconditions: the guard fires before any tenant read
    # or feature write, so the PATCH is side-effect free -
    # the seeded role is still there with HOST_MANAGE_TENANTS
    # and the seeded tenant row still exists with is_active
    # False (its entity default) and no features enabled
    # (entity default, tenant.py:144). Had the guard been
    # dropped, the handler would have passed its stamp check
    # (seeded tenant id 387 equals the caller tenant id)
    # and enabled STRIPE on the tenant instead of this 403.
    stored_role = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored_role is not None
    assert stored_role.permissions == [Permission.HOST_MANAGE_TENANTS]
    stored_tenant = await Tenant.find_one(
        Tenant.id == PydanticObjectId("68c302ef6bf7a039b7e9b387")
    )
    assert stored_tenant is not None
    assert stored_tenant.name == "update-feature-scope-tenant"
    assert stored_tenant.is_active is False
    assert stored_tenant.features == []


@pytest.mark.asyncio
async def test_update_tenant_dns_outside_tenant_scope_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        The tenant DNS-update POST scope-guard error path:
        the tenant test file locked the POST route itself
        only as a missing-role 404 (the permission
        dependency raises RoleNotFoundException before
        the scope guard, any tenant lookup, any tenant
        write, or any DNS-update job enqueue) and locked
        the GET features, PUT, DELETE, and update_feature
        PATCH routes' scope guards in the previous runs,
        but no test asserted a 403 on
        POST /tenants/{tenant_id}/update_dns via
        _assert_update_scope - function-name grep
        count 0 for update_tenant_dns_outside_tenant_scope,
        verified fresh this run. Dropping
        _assert_update_scope
        (tenant_endpoint.py:28-45) would previously have
        gone uncaught, and a tenant caller updating on
        the host DB could then overwrite another tenant
        record's custom_domain / is_active and enqueue
        its DNS-update job, as the guard's own comment
        describes (the stamp check in
        update_tenant_dns_record only compares against
        the record the request's database returned).
        Unlike the trial-activation PATCH, this route
        carries no STRIPE feature gate: the only
        dependency ahead of the guard is the permission
        check, so the guard runs first in the handler
        body (tenant_endpoint.py:378), before
        get_tenant_by_id, any tenant write, or any job
        enqueue, and the scope lock is reachable the
        same way as the update_feature lock. (The
        trial-activation guard is not lockable the same
        way: its feature gate runs before the guard and
        does a tenant lookup by request scope, which
        404s in the test env when the middleware falls
        back to scope None - see the progress log.)
        It cannot be reached the way the missing-role
        404 lock reaches the route (host caller, no
        seeded role): the permission dependency runs
        before the guard, so the seeded role (id
        68c302ef6bf7a039b7e9b386) must carry one of the
        route's permissions - HOST_MANAGE_TENANTS here,
        mirroring the update_feature lock - and the
        caller override mirrors the stripe scope locks'
        and the PUT/DELETE/features/update_feature scope
        locks' pattern (per-test MeResponseDto, restored
        in finally). The caller is tenant-scoped to
        68c302ef6bf7a039b7e9b387 while the request carries
        X-Tenant-ID 68c302ef6bf7a039b7e9b388, so the guard
        fires on the mismatch. The seeded tenant carries
        the caller's own tenant id (387), not the 385 of
        the DELETE lock: without the guard, the stamp
        check at tenant_endpoint.py:386 would pass
        (tenant.id == caller tenant id) and the POST body
        {"custom_domain": "app.example.com"} would
        overwrite the seeded tenant's custom_domain and
        flip its status to activation-progress, so the
        custom_domain-still-None postcondition is
        decisive here - with the DELETE lock's 385-vs-387
        split the stamp check would instead have 404'd
        and no write could have happened either way.
        The body is a valid UpdateTenantDto (custom_domain
        app.example.com, which passes the custom-domain
        validator and is not the host main domain, per
        the 404 lock), so no 422 can mask the 403; the
        handler takes no Response param, so the 403's
        no-store/Pragma headers come from the central
        ApiBaseException handler (api/__init__.py:98-103).
        The tenant router carries no feature gate, so no
        seeded tenant feature is needed to reach the
        guard; the request scope comes from the header
        alone, and the middleware's tenant-DB init targets
        the default 27017 URI, which has no listener in
        the test/dev environment (dev/test Mongo is on
        27012 per CONTRIBUTE.md, and both ports were
        verified closed this run), so it falls back to
        host scope and the guard fires on caller-387 vs
        scope-None - and even if the scope resolved to
        388 the guard would fire the same way (387 vs
        388), so the 403 does not depend on which of the
        two scope values the middleware produces.
        get_role_detail calls get_role_by_id with no
        tenant argument (user_access_management.py:39),
        so _caller_may_access sees a None caller tenant
        and returns True (role_service.py:18-19), and
        the seeded row is visible regardless of the
        caller's tenant scope - the same mechanism the
        stripe scope locks rely on. The central
        ApiBaseException handler maps ForbiddenException
        to 403 (api/__init__.py:98-103) with {"error":
        ..., "code": 403} and the no-store/Pragma error
        headers. A future change that drops the guard
        would break this lock while leaving the POST 404
        lock green, so the paths are locked separately.
    """
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.entities.tenant import Tenant
    from api.domain.enum.permission import Permission

    await Tenant(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b387"),
        name="update-dns-scope-tenant",
        subdomain="update-dns-scope.fsrapp.com",
    ).insert()
    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Tenant tenant administrator",
        description="Role carrying HOST_MANAGE_TENANTS for the mocked caller",
        permissions=[Permission.HOST_MANAGE_TENANTS],
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
                name="Tenant tenant administrator",
                description="Role carrying HOST_MANAGE_TENANTS for the mocked caller",
                created_at="2024-10-01T00:00:00Z",
                updated_at="2024-10-01T00:00:00Z",
                permissions=[Permission.HOST_MANAGE_TENANTS],
            ),
            subscription=None,
        )

    original_override = app.dependency_overrides.get(get_current_user)
    app.dependency_overrides[get_current_user] = override_get_current_user_tenant_scoped
    try:
        response = await client.post(
            "/tenants/68c302ef6bf7a039b7e9b387/update_dns",
            json={"custom_domain": "app.example.com"},
            headers={"X-Tenant-ID": "68c302ef6bf7a039b7e9b388"},
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
    # update-scope guard raises before any tenant read or write
    # or DNS-update job enqueue, and the POST takes no Response
    # param, so on this path the no-store/Pragma headers come
    # from the central ApiBaseException handler, and a cached
    # 403 could otherwise be served to a different admin after
    # an account switch on a shared machine.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the other tenant tests in
    # this file: the pure-ASGI middleware stamps every HTTP
    # response with no path exclusions, so this authenticated
    # tenant 403 must carry the same headers as the other
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
    # Postconditions: the guard fires before any tenant read
    # or write or DNS-update job enqueue, so the POST is
    # side-effect free - the seeded role is still there with
    # HOST_MANAGE_TENANTS and the seeded tenant row still
    # exists with is_active False (its entity default),
    # custom_domain None (its entity default) and
    # custom_domain_status "failed" (its entity default,
    # tenant.py:143). Had the guard been dropped, the
    # handler would have passed its stamp check (seeded
    # tenant id 387 equals the caller tenant id) and
    # overwritten the tenant's custom_domain with
    # app.example.com and flipped its status to
    # activation-progress instead of this 403.
    stored_role = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored_role is not None
    assert stored_role.permissions == [Permission.HOST_MANAGE_TENANTS]
    stored_tenant = await Tenant.find_one(
        Tenant.id == PydanticObjectId("68c302ef6bf7a039b7e9b387")
    )
    assert stored_tenant is not None
    assert stored_tenant.name == "update-dns-scope-tenant"
    assert stored_tenant.is_active is False
    assert stored_tenant.custom_domain is None
    assert stored_tenant.custom_domain_status == "failed"


@pytest.mark.asyncio
async def test_check_tenant_dns_outside_tenant_scope_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        The tenant DNS-check GET scope-guard error path:
        the tenant test file locked this GET route itself
        only as a missing-role 404 (the permission
        dependency raises RoleNotFoundException before
        the scope guard, any tenant lookup, or any
        DNS-update job enqueue) and locked the GET
        features, PUT, DELETE, update_feature PATCH,
        and update_dns POST routes' scope guards in the
        previous runs, but no test asserted a 403 on
        GET /tenants/{tenant_id}/check_dns via
        _assert_update_scope - function-name grep
        count 0 for check_tenant_dns_outside_tenant_scope,
        verified fresh this run. Dropping
        _assert_update_scope
        (tenant_endpoint.py:28-45) would previously have
        gone uncaught, and a tenant caller checking on
        the host DB could then read the DNS status of,
        and enqueue DNS-update jobs for, a tenant-stamped
        record sitting in the host DB (e.g. planted
        before the create guard), as the guard's own
        comment describes (the stamp check in
        check_dns_status only compares against the
        record the request's database returned).
        Unlike the trial-activation PATCH, this route
        carries no STRIPE feature gate: the only
        dependency ahead of the guard is the permission
        check, so the guard runs first in the handler
        body (tenant_endpoint.py:451), before
        get_tenant_by_id, the stamp check, the
        custom-domain guard, or any job enqueue, and
        the scope lock is reachable the same way as the
        update_dns lock. (The trial-activation guard is
        not lockable the same way: its feature gate runs
        before the guard and does a tenant lookup by
        request scope, which 404s in the test env when
        the middleware falls back to scope None - see
        the progress log.)
        It cannot be reached the way the missing-role
        404 lock reaches the route (host caller, no
        seeded role): the permission dependency runs
        before the guard, so the seeded role (id
        68c302ef6bf7a039b7e9b386) must carry one of the
        route's permissions - HOST_MANAGE_TENANTS here,
        mirroring the update_dns lock - and the caller
        override mirrors the stripe scope locks' and
        the PUT/DELETE/features/update_feature/update_dns
        scope locks' pattern (per-test MeResponseDto,
        restored in finally). The caller is tenant-scoped
        to 68c302ef6bf7a039b7e9b387 while the request
        carries X-Tenant-ID 68c302ef6bf7a039b7e9b388, so
        the guard fires on the mismatch. The seeded
        tenant carries the caller's own tenant id (387),
        not the 385 of the DELETE lock: without the
        guard, the stamp check at tenant_endpoint.py:467
        would pass (tenant.id == caller tenant id) and
        the handler would reach the custom-domain guard
        at tenant_endpoint.py:475, which raises
        InvalidOperationException ("No custom domain is
        set for this tenant.", mapped to 406 by the
        central handler at api/__init__.py:108-109)
        because the seeded tenant carries the entity
        defaults (custom_domain None). So the 403
        assertion itself is the lock here - dropping
        the guard turns this request into a 406, not a
        200 - while the postconditions below guard
        against a future reorder that enqueues a
        DNS-update job before the domain check. Seeding
        a custom_domain to make the enqueue decisive was
        deliberately avoided: without the guard the
        handler would call handle_tenant_dns_update.delay()
        with no broker in the test env, an
        environment-dependent outcome, not a clean
        assertion. The GET takes no body or query params,
        so no 422 can mask the 403; the handler's own
        no-store lines run after the guard, so the 403's
        no-store/Pragma headers come from the central
        ApiBaseException handler (api/__init__.py:98-103).
        The tenant router carries no feature gate, so no
        seeded tenant feature is needed to reach the
        guard; the request scope comes from the header
        alone, and the middleware's tenant-DB init targets
        the default 27017 URI, which has no listener in
        the test/dev environment (dev/test Mongo is on
        27012 per CONTRIBUTE.md, and both ports were
        verified closed this run), so it falls back to
        host scope and the guard fires on caller-387 vs
        scope-None - and even if the scope resolved to
        388 the guard would fire the same way (387 vs
        388), so the 403 does not depend on which of the
        two scope values the middleware produces.
        get_role_detail calls get_role_by_id with no
        tenant argument (user_access_management.py:39),
        so _caller_may_access sees a None caller tenant
        and returns True (role_service.py:18-19), and
        the seeded row is visible regardless of the
        caller's tenant scope - the same mechanism the
        stripe scope locks rely on. The central
        ApiBaseException handler maps ForbiddenException
        to 403 (api/__init__.py:98-103) with {"error":
        ..., "code": 403} and the no-store/Pragma error
        headers. A future change that drops the guard
        would break this lock while leaving the GET 404
        lock green, so the paths are locked separately.
    """
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.entities.tenant import Tenant
    from api.domain.enum.permission import Permission

    await Tenant(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b387"),
        name="check-dns-scope-tenant",
        subdomain="check-dns-scope.fsrapp.com",
    ).insert()
    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Tenant tenant administrator",
        description="Role carrying HOST_MANAGE_TENANTS for the mocked caller",
        permissions=[Permission.HOST_MANAGE_TENANTS],
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
                name="Tenant tenant administrator",
                description="Role carrying HOST_MANAGE_TENANTS for the mocked caller",
                created_at="2024-10-01T00:00:00Z",
                updated_at="2024-10-01T00:00:00Z",
                permissions=[Permission.HOST_MANAGE_TENANTS],
            ),
            subscription=None,
        )

    original_override = app.dependency_overrides.get(get_current_user)
    app.dependency_overrides[get_current_user] = override_get_current_user_tenant_scoped
    try:
        response = await client.get(
            "/tenants/68c302ef6bf7a039b7e9b387/check_dns",
            headers={"X-Tenant-ID": "68c302ef6bf7a039b7e9b388"},
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
    # update-scope guard raises before any tenant read, any
    # DNS-update job enqueue, or the handler's own no-store
    # lines, so on this path the no-store/Pragma headers come
    # from the central ApiBaseException handler, and a cached
    # 403 could otherwise be served to a different admin after
    # an account switch on a shared machine.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the other tenant tests in
    # this file: the pure-ASGI middleware stamps every HTTP
    # response with no path exclusions, so this authenticated
    # tenant 403 must carry the same headers as the other
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
    # Postconditions: the guard fires before any tenant read
    # or DNS-update job enqueue, so the GET is side-effect
    # free - the seeded role is still there with
    # HOST_MANAGE_TENANTS and the seeded tenant row still
    # exists with is_active False (its entity default),
    # custom_domain None (its entity default) and
    # custom_domain_status "failed" (its entity default,
    # tenant.py:143). With this seed the tenant row would
    # be unchanged even without the guard (the domain guard
    # at tenant_endpoint.py:475 raises before any enqueue),
    # so these postconditions guard against a future reorder
    # that enqueues before the domain check, while the 403
    # assertion above is the lock on the guard itself.
    stored_role = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored_role is not None
    assert stored_role.permissions == [Permission.HOST_MANAGE_TENANTS]
    stored_tenant = await Tenant.find_one(
        Tenant.id == PydanticObjectId("68c302ef6bf7a039b7e9b387")
    )
    assert stored_tenant is not None
    assert stored_tenant.name == "check-dns-scope-tenant"
    assert stored_tenant.is_active is False
    assert stored_tenant.custom_domain is None
    assert stored_tenant.custom_domain_status == "failed"


@pytest.mark.asyncio
async def test_activate_trial_plan_outside_tenant_scope_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        The tenant trial-activation PATCH scope-guard error
        path: the tenant test file locked this PATCH route
        itself only as a feature-disabled 403 (a host
        caller whose tenant has STRIPE disabled, with no
        seeded role) and locked the GET features, PUT,
        DELETE, update_feature PATCH, update_dns POST, and
        check_dns GET routes' scope guards in the previous
        runs, but no test asserted a 403 on
        PATCH /tenants/{tenant_id}/activate_trial_plan via
        _assert_trial_activation_scope - function-name grep
        count 0 for activate_trial_plan_outside_tenant_scope,
        verified fresh this run. Dropping
        _assert_trial_activation_scope
        (tenant_endpoint.py:86-104) would previously have
        gone uncaught, and a tenant caller activating on
        the host DB could then create a Stripe trial
        subscription for a tenant record sitting in the
        host DB and overwrite its subscription_id, as the
        guard's own comment describes (the stamp check in
        activate_trial_plan only compares against the
        record the request's database returned).
        This guard is not reachable the way the other
        scope locks reach theirs: the STRIPE feature gate
        (check_feature_access, feature_access_management.py)
        is a dependency listed in the handler signature
        BEFORE the HOST_MANAGE_TENANTS permission
        dependency and before the guard, and it does
        tenant_service.get_tenant_by_id(request.state.tenant_id)
        for a tenant caller. In the test env the middleware's
        tenant-DB init targets the settings Mongo URI
        (default 27017, no listener - both 27017 and 27012
        verified closed this run), so it falls back to host
        scope and the gate's lookup of id None raises
        TenantNotFoundException, answering 404 before the
        guard is ever reached - a test asserting 403 with
        the plain pattern would fail if executed, so no
        such lock was written in the earlier sweep. Two
        other approaches were assessed and rejected: seeding
        the request-scope tenant into the tenant DB would
        not help, because that DB is initialised on the
        settings-mongo client rather than the conftest test
        DB, so the seed would not be visible to the gate's
        lookup in the test env; and reordering the production
        dependencies so the guard runs before the gate was
        not needed for the lock and would change which 403
        message some callers receive. Instead this test
        isolates the guard the same way the file's other
        locks isolate the code under test (they override
        get_current_user per test): the gate callable is
        read out of the endpoint signature (FastAPI Depends
        exposes it as .dependency) and overridden to return
        True, so the request reaches the handler body with
        the gate passed. The gate itself stays locked by the
        feature-disabled 403 test above, which exercises the
        real gate; this test locks only the scope guard.
        It cannot be reached the way the missing-role 404
        lock reaches the route (host caller, no seeded
        role): the permission dependency runs before the
        guard, so the seeded role (id
        68c302ef6bf7a039b7e9b386) must carry one of the
        route's permissions - HOST_MANAGE_TENANTS here,
        mirroring the update_dns lock - and the caller
        override mirrors the stripe scope locks' and the
        PUT/DELETE/features/update_feature/update_dns/
        check_dns scope locks' pattern (per-test
        MeResponseDto, restored in finally). The caller is
        tenant-scoped to 68c302ef6bf7a039b7e9b387 while the
        request carries X-Tenant-ID
        68c302ef6bf7a039b7e9b388, so the guard fires on the
        mismatch - and even if the middleware resolves the
        header to scope 388 instead of falling back to
        scope None, the guard fires the same way (387 vs
        388), so the 403 does not depend on which of the
        two scope values the middleware produces. The
        seeded tenant carries the caller's own tenant id
        (387), not the 385 of the DELETE lock: without the
        guard, the stamp check at tenant_endpoint.py:643
        would pass (tenant.id == caller tenant id) and the
        handler would reach billing_record_service.list_plans
        ('host'), a live Stripe call (billing_record_service.py:
        176-179), instead of this 403. The PATCH carries no
        body, so no 422 can mask the 403; the handler takes
        no Response param, so the 403's no-store/Pragma
        headers come from the central ApiBaseException
        handler (api/__init__.py:98-103), which maps
        ForbiddenException to 403 with {"error", "code"}.
        A future change that drops the guard would break
        this lock while leaving the PATCH feature-disabled
        403 lock green, so the paths are locked separately.
    """
    import inspect

    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.entities.tenant import Tenant
    from api.domain.enum.permission import Permission
    from api.interfaces.api_controllers.tenant_endpoint import activate_trial_plan

    await Tenant(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b387"),
        name="trial-activation-scope-tenant",
        subdomain="trial-activation-scope.fsrapp.com",
    ).insert()
    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Tenant tenant administrator",
        description="Role carrying HOST_MANAGE_TENANTS for the mocked caller",
        permissions=[Permission.HOST_MANAGE_TENANTS],
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
                name="Tenant tenant administrator",
                description="Role carrying HOST_MANAGE_TENANTS for the mocked caller",
                created_at="2024-10-01T00:00:00Z",
                updated_at="2024-10-01T00:00:00Z",
                permissions=[Permission.HOST_MANAGE_TENANTS],
            ),
            subscription=None,
        )

    async def override_feature_gate():
        return True

    # The STRIPE gate callable is the Depends default of the
    # _feature_check parameter, created once at import time by
    # check_feature_access(feature_name=Feature.STRIPE); a fresh
    # call would build a different closure and would not match
    # the route's dependency, so it is read out of the endpoint
    # signature instead of reconstructed.
    feature_gate = inspect.signature(activate_trial_plan).parameters["_feature_check"].default.dependency

    original_user_override = app.dependency_overrides.get(get_current_user)
    original_gate_override = app.dependency_overrides.get(feature_gate)
    app.dependency_overrides[get_current_user] = override_get_current_user_tenant_scoped
    app.dependency_overrides[feature_gate] = override_feature_gate
    try:
        response = await client.patch(
            "/tenants/68c302ef6bf7a039b7e9b387/activate_trial_plan",
            headers={"X-Tenant-ID": "68c302ef6bf7a039b7e9b388"},
        )
    finally:
        if original_user_override is None:
            app.dependency_overrides.pop(get_current_user, None)
        else:
            app.dependency_overrides[get_current_user] = original_user_override
        if original_gate_override is None:
            app.dependency_overrides.pop(feature_gate, None)
        else:
            app.dependency_overrides[feature_gate] = original_gate_override
    assert response.status_code == 403
    body = response.json()
    assert body["code"] == 403
    assert "outside your tenant's scope" in body["error"]
    assert "refresh_token" not in response.headers.get("set-cookie", "")
    # The 403 must still carry the error-response headers: the
    # trial-activation-scope guard raises before any tenant read
    # or Stripe work, and the PATCH takes no Response param, so
    # on this path the no-store/Pragma headers come from the
    # central ApiBaseException handler, and a cached 403 could
    # otherwise be served to a different admin after an account
    # switch on a shared machine.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the other tenant tests in
    # this file: the pure-ASGI middleware stamps every HTTP
    # response with no path exclusions, so this authenticated
    # tenant 403 must carry the same headers as the other
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
    # Postconditions: the guard fires before any tenant read
    # or Stripe work, so the PATCH is side-effect free - the
    # seeded role is still there with HOST_MANAGE_TENANTS and
    # the seeded tenant row still exists with is_active False
    # (its entity default), custom_domain None (its entity
    # default), custom_domain_status "failed" (its entity
    # default, tenant.py:143), features [] (its entity
    # default, tenant.py:144) and subscription_id None (its
    # entity default, tenant.py:145). The 403 assertion above
    # is the lock on the guard itself: had the guard been
    # dropped, the handler would have passed its stamp check
    # (seeded tenant id 387 equals the caller tenant id) and
    # reached the live Stripe plan list instead of this 403,
    # and the subscription_id-still-None postcondition proves
    # no trial subscription was created or written.
    stored_role = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored_role is not None
    assert stored_role.permissions == [Permission.HOST_MANAGE_TENANTS]
    stored_tenant = await Tenant.find_one(
        Tenant.id == PydanticObjectId("68c302ef6bf7a039b7e9b387")
    )
    assert stored_tenant is not None
    assert stored_tenant.name == "trial-activation-scope-tenant"
    assert stored_tenant.is_active is False
    assert stored_tenant.custom_domain is None
    assert stored_tenant.custom_domain_status == "failed"
    assert stored_tenant.features == []
    assert stored_tenant.subscription_id is None


@pytest.mark.asyncio
async def test_create_tenant_as_tenant_caller_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        The tenant POST create host-restriction error path:
        the tenant test file locked the POST route itself
        (host create, 201) and the 403 scope guards for the
        DELETE, PUT, DNS-update POST, DNS-check GET, features
        GET, update_feature PATCH, and trial-activation PATCH
        routes, but no test asserted a 403 on POST /tenants/
        via the host-restriction check - function-name grep
        count 0 for create_tenant_as_tenant_caller_returns_403
        and grep count 0 for "restricted to host" across this
        file, verified fresh this run. Dropping the check
        (tenant_endpoint.py:204) would previously have gone
        uncaught, and a tenant caller could then create
        arbitrary new tenants with a caller-chosen admin
        account (email + password), claiming subdomains and
        gaining admin of a fresh tenant, as the guard's own
        comment describes. The check runs first in the handler
        body, before any service call or worker dispatch, so
        no tenant is created and no post-creation job is
        enqueued - unlike the 409 tenant-create path, this
        lock needs no Celery broker care. It cannot be
        reached the way the missing-role 404 locks reach the
        route (host caller, no seeded role): the permission
        dependency runs before the guard, so the seeded role
        (id 68c302ef6bf7a039b7e9b386) must carry the route's
        HOST_MANAGE_TENANTS permission, and the caller
        override mirrors the delete scope lock's pattern
        (per-test MeResponseDto, restored in finally). The
        caller is tenant-scoped to
        68c302ef6bf7a039b7e9b387, so the check fires on
        tenant_id is not None alone - no X-Tenant-ID header
        is needed, and the tenant router carries no feature
        gate. get_role_detail calls get_role_by_id with no
        tenant argument (user_access_management.py), so
        _caller_may_access sees a None caller tenant and
        returns True (role_service.py:18-19), and the seeded
        row is visible regardless of the caller's tenant
        scope - the same mechanism the delete scope lock
        relies on. The body is a valid CreateTenantDto (name,
        subdomain create-scope.fsrapp.com, admin email and
        password, first/last name, gender), so no 422 can mask
        the 403: FastAPI validates the body before the handler
        runs, and the subdomain label "create-scope" passes
        SUBDOMAIN_REGEX (tenant.py:11). The central
        ApiBaseException handler maps ForbiddenException to 403
        (api/__init__.py:98-103) with {"error": ...,
        "code": 403} and the no-store/Pragma error headers.
        A future change that drops the check would break this
        lock while leaving the POST 201 lock green, so the
        paths are locked separately.
    """
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.entities.tenant import Tenant
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Tenant tenant administrator",
        description="Role carrying HOST_MANAGE_TENANTS for the mocked caller",
        permissions=[Permission.HOST_MANAGE_TENANTS],
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
                name="Tenant tenant administrator",
                description="Role carrying HOST_MANAGE_TENANTS for the mocked caller",
                created_at="2024-10-01T00:00:00Z",
                updated_at="2024-10-01T00:00:00Z",
                permissions=[Permission.HOST_MANAGE_TENANTS],
            ),
            subscription=None,
        )

    original_override = app.dependency_overrides.get(get_current_user)
    app.dependency_overrides[get_current_user] = override_get_current_user_tenant_scoped
    try:
        response = await client.post(
            "/tenants/",
            json=CreateTenantDto(
                name="create-scope",
                subdomain="create-scope.fsrapp.com",
                admin_email="create-scope-admin@example.com",
                admin_password="CreateScope123!",
                first_name="Create",
                last_name="Scope",
                gender=Gender.MALE,
            ).model_dump(),
        )
    finally:
        if original_override is None:
            app.dependency_overrides.pop(get_current_user, None)
        else:
            app.dependency_overrides[get_current_user] = original_override
    assert response.status_code == 403
    body = response.json()
    assert body["code"] == 403
    assert "Tenant creation is restricted to host administrators." in body["error"]
    assert "refresh_token" not in response.headers.get("set-cookie", "")
    # The 403 must still carry the error-response headers: the
    # host-restriction check raises before the handler creates
    # any response object, so on this path the no-store/Pragma
    # headers come from the central ApiBaseException handler,
    # and a cached 403 could otherwise be served to a different
    # admin after an account switch on a shared machine.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the other tenant tests in
    # this file: the pure-ASGI middleware stamps every HTTP
    # response with no path exclusions, so this authenticated
    # tenant 403 must carry the same headers as the other
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
    # Postconditions: the check fires before any service call
    # or worker dispatch, so the POST is side-effect free -
    # the seeded role is still there with HOST_MANAGE_TENANTS
    # and, decisively, no tenant row was created with the
    # requested subdomain: had the check been dropped, the
    # handler would have created a tenant named "create-scope"
    # on subdomain create-scope.fsrapp.com (and dispatched the
    # post-creation job for its admin account).
    stored_role = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored_role is not None
    assert stored_role.permissions == [Permission.HOST_MANAGE_TENANTS]
    stored_tenant = await Tenant.find_one(
        Tenant.subdomain == "create-scope.fsrapp.com"
    )
    assert stored_tenant is None



@pytest.mark.asyncio
async def test_create_duplicate_tenant_returns_409_with_cache_and_security_headers(client: AsyncClient):
    """
        The tenant create duplicate-name error path:
        the tenant test file locked the POST route itself
        (host create, 201) and the 403 host-restriction
        guard, but no test asserted a 409 on POST /tenants/
        for a duplicate name - function-name grep count 0
        for create_duplicate_tenant and grep count 0 for
        "already exists" across this file, verified fresh
        this run. Dropping the duplicate check would
        previously have gone uncaught, and a second tenant
        with the same name would then be planted (and the
        post-creation Celery task dispatched for its admin
        account). The check cannot live in the repository's
        DuplicateKeyError catch alone: Tenant.name is
        Indexed(str, unique=True) (tenant.py:134) but
        Settings.indexes also lists plain "name", and
        beanie 2.2.0's init_indexes merges the
        Indexed-derived indexes with Settings.indexes with
        the Settings side winning on the same fields
        (merge_indexes: the right dict overwrites the left
        on identical field tuples), so the unique constraint
        is silently dropped at init_beanie and the catch
        never fires for name duplicates - verified fresh
        this run from the beanie 2.2.0 wheel source
        (odm/utils/init.py init_indexes, odm/fields.py
        merge_indexes, odm/utils/typing.py
        get_index_attributes). The service now checks
        first, mirroring RoleService.create_role and
        UserService.create_user: single_or_none(name=...)
        raises ConflictException("Tenant", name) before
        any write, which subclasses ApiBaseException with
        the message "Tenant with identifier <name> already
        exists." (common/exceptions.py:26-38), and the
        central handler maps it to 409 with {"error": ...,
        "code": 409} plus the no-store/Pragma error
        headers (api/__init__.py:89-90, 121-133). The
        check runs before repository.create, so the
        duplicate path needs no Celery broker care: the
        endpoint's handle_post_tenant_creation.delay runs
        only after service.create_tenant returns, and the
        seeded first tenant is inserted directly, so this
        test makes exactly one API call. The seeded role
        (id 68c302ef6bf7a039b7e9b386) must carry the
        route's HOST_MANAGE_TENANTS permission, since the
        permission dependency runs before the handler, and
        the shared conftest mock is a host caller
        (tenant_id None), so the host-restriction guard
        passes too. The body is the same valid
        CreateTenantDto as the 201 helper (name "test",
        subdomain test.fsrapp.com, admin email and
        password, first/last name, gender), so no 422 can
        mask the 409: FastAPI validates the body before
        the handler runs, and the subdomain label "test"
        passes SUBDOMAIN_REGEX (tenant.py:11) against the
        "fsrapp.com" main domain (config.py:32). A future
        change that drops the service check would break
        this lock while leaving the POST 201 and POST 403
        locks green, so the paths are locked separately.
        Residual, not covered by this lock: concurrent
        duplicate creates can still race past the
        check-then-insert; a true database guarantee needs
        the unique index restored, which needs a migration
        on existing databases (drop the non-unique name_1
        index first, or init_beanie raises
        IndexOptionsConflict) - assess separately. User
        email has the same dropped-unique pattern
        (Indexed unique + plain "email" in Settings
        indexes), but its service check already covers
        the API path; only the race remains there.
    """
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.entities.tenant import Tenant
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host tenant administrator",
        description="Role carrying HOST_MANAGE_TENANTS for the mocked caller",
        permissions=[Permission.HOST_MANAGE_TENANTS],
    ).insert()

    await Tenant(
        name="test",
        subdomain="test.fsrapp.com",
    ).insert()

    response = await client.post(
        "/tenants/",
        json=CreateTenantDto(
            name="test",
            subdomain="test.fsrapp.com",
            admin_email="test@test.com",
            admin_password="Test@123!",
            first_name="Test",
            last_name="Admin",
            gender=Gender.MALE,
        ).model_dump(),
    )
    assert response.status_code == 409
    body = response.json()
    assert body["code"] == 409
    assert "Tenant with identifier test already exists." in body["error"]
    assert "refresh_token" not in response.headers.get("set-cookie", "")
    # The 409 must still carry the error-response headers: the
    # duplicate check raises before the handler creates any
    # response object, so on this path the no-store/Pragma headers
    # come from the central ApiBaseException handler, and a cached
    # 409 could otherwise be served to a different admin after an
    # account switch on a shared machine.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the other tenant tests in
    # this file: the pure-ASGI middleware stamps every HTTP
    # response with no path exclusions, so this authenticated
    # tenant 409 must carry the same headers as the other
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
    # Postconditions: the duplicate check fires before any
    # write, so the request is side-effect free - still
    # exactly one tenant named "test" (the seeded one), and
    # the seeded role is still there with HOST_MANAGE_TENANTS.
    # Had the check been dropped, the handler would have
    # created a second "test" tenant on subdomain
    # test.fsrapp.com (and dispatched the post-creation job
    # for its admin account).
    duplicates = await Tenant.find(Tenant.name == "test").to_list()
    assert len(duplicates) == 1
    assert duplicates[0].subdomain == "test.fsrapp.com"
    stored_role = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored_role is not None
    assert stored_role.permissions == [Permission.HOST_MANAGE_TENANTS]


@pytest.mark.asyncio
async def test_create_tenant_with_duplicate_subdomain_returns_409_with_cache_and_security_headers(client: AsyncClient):
    """
        The tenant create duplicate-subdomain error path:
        the duplicate-name 409 lock covers a second tenant
        with the same name, but a different name on an
        existing subdomain had no lock - function-name grep
        count 0 for duplicate subdomain and grep count 0
        for "subdomain.*already exists" across this file,
        verified fresh this run. Tenant.subdomain is a plain
        field (tenant.py:135): no Indexed unique annotation
        and only a plain "subdomain" entry in
        Settings.indexes, so there is no database guarantee
        at all, and create_tenant had no service check for
        it either - a second POST /tenants/ with a different
        name but an existing subdomain previously returned
        201 and dispatched the post-creation Celery task
        for the colliding tenant. The service now checks
        first, mirroring the duplicate-name guard:
        single_or_none(subdomain=...) raises
        ConflictException("Tenant", subdomain) before any
        write, which subclasses ApiBaseException with the
        message "Tenant with identifier <subdomain> already
        exists." (common/exceptions.py:26-38), and the
        central handler maps it to 409 with {"error": ...,
        "code": 409} plus the no-store/Pragma error
        headers (api/__init__.py:89-90, 121-133). The
        check runs before repository.create, so the
        duplicate path needs no Celery broker care: the
        endpoint's handle_post_tenant_creation.delay runs
        only after service.create_tenant returns, and the
        seeded first tenant is inserted directly, so this
        test makes exactly one API call. The seeded role
        (id 68c302ef6bf7a039b7e9b386) must carry the
        route's HOST_MANAGE_TENANTS permission, since the
        permission dependency runs before the handler, and
        the shared conftest mock is a host caller
        (tenant_id None), so the host-restriction guard
        passes too. The body is a valid CreateTenantDto
        with a different name ("other") but the seeded
        subdomain dup.fsrapp.com, so the name guard passes
        and only the subdomain guard fires - no 422 can
        mask the 409: FastAPI validates the body before
        the handler runs, and the subdomain label "dup"
        passes SUBDOMAIN_REGEX (tenant.py:11) against the
        "fsrapp.com" main domain (config.py:32). The
        subdomain is already trimmed/lowercased by its
        AfterValidator, so the stored and incoming values
        compare exactly. A future change that drops the
        subdomain check would break this lock while
        leaving the POST 201, POST 403, and duplicate-name
        409 locks green, so the paths are locked
        separately. Residual, not covered by this lock:
        concurrent duplicate creates can still race past
        the check-then-insert; a true database guarantee
        needs a unique index on subdomain, which needs a
        migration on existing databases - assess separately.
    """
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.entities.tenant import Tenant
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host tenant administrator",
        description="Role carrying HOST_MANAGE_TENANTS for the mocked caller",
        permissions=[Permission.HOST_MANAGE_TENANTS],
    ).insert()

    await Tenant(
        name="seeded",
        subdomain="dup.fsrapp.com",
    ).insert()

    response = await client.post(
        "/tenants/",
        json=CreateTenantDto(
            name="other",
            subdomain="dup.fsrapp.com",
            admin_email="other@test.com",
            admin_password="Test@123!",
            first_name="Other",
            last_name="Admin",
            gender=Gender.MALE,
        ).model_dump(),
    )
    assert response.status_code == 409
    body = response.json()
    assert body["code"] == 409
    assert "Tenant with identifier dup.fsrapp.com already exists." in body["error"]
    assert "refresh_token" not in response.headers.get("set-cookie", "")
    # The 409 must still carry the error-response headers: the
    # duplicate check raises before the handler creates any
    # response object, so on this path the no-store/Pragma headers
    # come from the central ApiBaseException handler, and a cached
    # 409 could otherwise be served to a different admin after an
    # account switch on a shared machine.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the other tenant tests in
    # this file: the pure-ASGI middleware stamps every HTTP
    # response with no path exclusions, so this authenticated
    # tenant 409 must carry the same headers as the other
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
    # Postconditions: the duplicate check fires before any
    # write, so the request is side-effect free - still
    # exactly one tenant on subdomain dup.fsrapp.com (the
    # seeded one, named "seeded"), and the seeded role is
    # still there with HOST_MANAGE_TENANTS. Had the check
    # been dropped, the handler would have created a second
    # tenant on dup.fsrapp.com (and dispatched the
    # post-creation job for its admin account).
    duplicates = await Tenant.find(Tenant.subdomain == "dup.fsrapp.com").to_list()
    assert len(duplicates) == 1
    assert duplicates[0].name == "seeded"
    stored_role = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored_role is not None
    assert stored_role.permissions == [Permission.HOST_MANAGE_TENANTS]


@pytest.mark.asyncio
async def test_update_tenant_with_duplicate_custom_domain_returns_409_with_cache_and_security_headers(client: AsyncClient):
    """
        The tenant update duplicate-custom-domain error path:
        the tenant test file locked the POST create
        duplicate-name and duplicate-subdomain 409s, but no
        test asserted a 409 on PUT /tenants/{tenant_id}
        for a custom domain another tenant already holds -
        function-name grep count 0 for duplicate custom
        domain and grep count 0 for "custom_domain.*already
        exists" across this file, verified fresh this run.
        Dropping the duplicate check would previously have
        gone uncaught, and a second tenant would then sit
        on a domain another tenant already holds. That
        matters because the middleware resolves the tenant
        for a request host via find_by_custom_domain
        (tenant_middleware.py:45), which is single_or_none
        - first match wins - so two tenants on one domain
        would route that domain's traffic to whichever row
        sorts first, serving the wrong tenant's data. The
        domain has no unique index to fall back on either:
        Tenant.custom_domain is a plain field (tenant.py)
        with only a plain "custom_domain" entry in
        Settings.indexes, no Indexed unique annotation, so
        the repository has no DuplicateKeyError catch to
        fire. The service now checks first, mirroring the
        create_tenant name/subdomain guards: a non-None
        custom_domain is looked up with
        single_or_none(custom_domain=...) and raises
        ConflictException("Tenant", custom_domain) before
        any write when a different tenant holds it, which
        subclasses ApiBaseException with the message
        "Tenant with identifier <domain> already exists."
        (common/exceptions.py:26-38), and the central
        handler maps it to 409 with {"error": ..., "code":
        409} plus the no-store/Pragma error headers
        (api/__init__.py:89-90, 121-133). A None domain
        means "leave unchanged" (the update dumps
        exclude_none=True) and is not checked, and
        re-supplying the tenant's own domain is allowed
        (same id), so the check cannot false-positive on
        an unchanged update. The seeded role (id
        68c302ef6bf7a039b7e9b386) must carry the route's
        HOST_MANAGE_TENANTS permission, since the
        permission dependency runs before the handler, and
        the shared conftest mock is a host caller
        (tenant_id None), so the host scope guard passes
        too. The body is a valid UpdateTenantDto (only
        custom_domain set, all fields optional), so no 422
        can mask the 409, and "app.example.com" passes
        the CustomDomain validator (tenant.py
        validate_custom_domain: trimmed, urlparse
        hostname lowercased, matches CUSTOM_DOMAIN_REGEX,
        not the "fsrapp.com" main domain). The seeded
        holder tenant is inserted directly, so this test
        makes exactly one API call and enqueues no Celery
        job: the 409 fires before any write or DNS job.
        A future change that drops the service check would
        break this lock while leaving the PUT 404 and PUT
        403 locks and the POST duplicate-name/subdomain
        409 locks green, so the paths are locked
        separately. Residual, not covered by this lock:
        the update_dns endpoint writes custom_domain
        directly in the endpoint (tenant_endpoint.py
        update_tenant_dns_record) and has no duplicate
        check of its own - assess separately; concurrent
        duplicate updates can still race past the
        check-then-insert, and a true database guarantee
        needs a unique index on custom_domain, which
        needs a migration on existing databases - assess
        separately.
    """
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.entities.tenant import Tenant
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host tenant administrator",
        description="Role carrying HOST_MANAGE_TENANTS for the mocked caller",
        permissions=[Permission.HOST_MANAGE_TENANTS],
    ).insert()

    await Tenant(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b387"),
        name="target",
        subdomain="target.fsrapp.com",
    ).insert()

    await Tenant(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b388"),
        name="holder",
        subdomain="holder.fsrapp.com",
        custom_domain="app.example.com",
    ).insert()

    response = await client.put(
        "/tenants/68c302ef6bf7a039b7e9b387",
        json={"custom_domain": "app.example.com"},
    )
    assert response.status_code == 409
    body = response.json()
    assert body["code"] == 409
    assert "Tenant with identifier app.example.com already exists." in body["error"]
    assert "refresh_token" not in response.headers.get("set-cookie", "")
    # The 409 must still carry the error-response headers: the
    # duplicate check raises before the handler creates any
    # response object, so on this path the no-store/Pragma headers
    # come from the central ApiBaseException handler, and a cached
    # 409 could otherwise be served to a different admin after an
    # account switch on a shared machine.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the other tenant tests in
    # this file: the pure-ASGI middleware stamps every HTTP
    # response with no path exclusions, so this authenticated
    # tenant 409 must carry the same headers as the other
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
    # Postconditions: the duplicate check fires before any
    # write, so the request is side-effect free - still
    # exactly one tenant on custom domain app.example.com
    # (the seeded holder), the target tenant still has no
    # custom domain, and the seeded role is still there
    # with HOST_MANAGE_TENANTS. Had the check been
    # dropped, the handler would have moved the target
    # tenant onto app.example.com, and the middleware's
    # find_by_custom_domain would then resolve that
    # domain to whichever of the two rows sorts first.
    holders = await Tenant.find(Tenant.custom_domain == "app.example.com").to_list()
    assert len(holders) == 1
    assert holders[0].name == "holder"
    target = await Tenant.find_one(
        Tenant.id == PydanticObjectId("68c302ef6bf7a039b7e9b387")
    )
    assert target is not None
    assert target.custom_domain is None
    stored_role = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored_role is not None
    assert stored_role.permissions == [Permission.HOST_MANAGE_TENANTS]


@pytest.mark.asyncio
async def test_update_dns_with_duplicate_custom_domain_returns_409_with_cache_and_security_headers(client: AsyncClient):
    """
        The update_dns duplicate-custom-domain error path:
        the tenant test file locked the PUT /tenants/{id}
        duplicate-custom-domain 409, but no test asserted a
        409 on POST /tenants/{tenant_id}/update_dns for a
        custom domain another tenant already holds -
        function-name grep count 0 for
        update_dns_with_duplicate_custom_domain, verified
        fresh this run. Dropping the duplicate check would
        previously have gone uncaught, and a second tenant
        would then sit on a domain another tenant already
        holds: update_dns writes custom_domain directly in
        the endpoint instead of going through
        TenantService.update_tenant, so the PUT guard never
        ran on this path. That matters because the
        middleware resolves the tenant for a request host
        via find_by_custom_domain
        (tenant_middleware.py:45), which is single_or_none
        - first match wins - so two tenants on one domain
        would route that domain's traffic to whichever row
        sorts first, serving the wrong tenant's data. The
        domain has no unique index to fall back on either:
        Tenant.custom_domain is a plain field (tenant.py)
        with only a plain "custom_domain" entry in
        Settings.indexes, no Indexed unique annotation, so
        the repository has no DuplicateKeyError catch to
        fire. The endpoint now checks first, mirroring the
        update_tenant service guard: the domain is looked
        up with find_by_custom_domain and raises
        ConflictException("Tenant", custom_domain) before
        any write or DNS-job enqueue when a different
        tenant holds it, which subclasses ApiBaseException
        with the message "Tenant with identifier <domain>
        already exists." (common/exceptions.py:26-38), and
        the central handler maps it to 409 with {"error":
        ..., "code": 409} plus the no-store/Pragma error
        headers (api/__init__.py:89-90, 121-133).
        Re-supplying the tenant's own domain is allowed
        (same id), so the check cannot false-positive on
        a re-submitted domain. The seeded role (id
        68c302ef6bf7a039b7e9b386) must carry the route's
        HOST_MANAGE_TENANTS permission, since the
        permission dependency runs before the handler, and
        the shared conftest mock is a host caller
        (tenant_id None), so the host scope guard passes
        too. The body is a valid UpdateTenantDto (only
        custom_domain set, all fields optional), so no 422
        can mask the 409, and "app.example.com" passes
        the CustomDomain validator (tenant.py
        validate_custom_domain: trimmed, urlparse
        hostname lowercased, matches CUSTOM_DOMAIN_REGEX,
        not the "fsrapp.com" main domain). The target
        tenant has no custom_domain_status set, so neither
        the activation-progress nor the active early
        return can mask the 409. The seeded holder tenant
        is inserted directly, so this test makes exactly
        one API call and enqueues no Celery job: the 409
        fires before any write or DNS job. A future change
        that drops the endpoint check would break this lock
        while leaving the PUT duplicate-custom-domain 409
        lock and the update_dns 404 lock green, so the
        paths are locked separately. Residual, not covered
        by this lock: concurrent duplicate DNS updates can
        still race past the check-then-write, and a true
        database guarantee needs a unique index on
        custom_domain, which needs a migration on existing
        databases - assess separately.
    """
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.entities.tenant import Tenant
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host tenant administrator",
        description="Role carrying HOST_MANAGE_TENANTS for the mocked caller",
        permissions=[Permission.HOST_MANAGE_TENANTS],
    ).insert()

    await Tenant(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b387"),
        name="target",
        subdomain="target.fsrapp.com",
    ).insert()

    await Tenant(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b388"),
        name="holder",
        subdomain="holder.fsrapp.com",
        custom_domain="app.example.com",
    ).insert()

    response = await client.post(
        "/tenants/68c302ef6bf7a039b7e9b387/update_dns",
        json={"custom_domain": "app.example.com"},
    )
    assert response.status_code == 409
    body = response.json()
    assert body["code"] == 409
    assert "Tenant with identifier app.example.com already exists." in body["error"]
    assert "refresh_token" not in response.headers.get("set-cookie", "")
    # The 409 must still carry the error-response headers: the
    # duplicate check raises before the handler creates any
    # response object, so on this path the no-store/Pragma headers
    # come from the central ApiBaseException handler, and a cached
    # 409 could otherwise be served to a different admin after an
    # account switch on a shared machine.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the other tenant tests in
    # this file: the pure-ASGI middleware stamps every HTTP
    # response with no path exclusions, so this authenticated
    # tenant 409 must carry the same headers as the other
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
    # Postconditions: the duplicate check fires before any
    # write, so the request is side-effect free - still
    # exactly one tenant on custom domain app.example.com
    # (the seeded holder), the target tenant still has no
    # custom domain and its status is untouched, and the
    # seeded role is still there with HOST_MANAGE_TENANTS.
    # Had the check been dropped, the handler would have
    # moved the target tenant onto app.example.com and
    # enqueued a DNS-update job for it, and the
    # middleware's find_by_custom_domain would then resolve
    # that domain to whichever of the two rows sorts first.
    holders = await Tenant.find(Tenant.custom_domain == "app.example.com").to_list()
    assert len(holders) == 1
    assert holders[0].name == "holder"
    target = await Tenant.find_one(
        Tenant.id == PydanticObjectId("68c302ef6bf7a039b7e9b387")
    )
    assert target is not None
    assert target.custom_domain is None
    assert target.custom_domain_status == "failed"
    stored_role = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored_role is not None
    assert stored_role.permissions == [Permission.HOST_MANAGE_TENANTS]
