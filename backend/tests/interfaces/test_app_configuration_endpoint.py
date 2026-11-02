from unittest.mock import AsyncMock, patch
import pytest
from httpx import AsyncClient
from api.common.enums.gender import Gender
from api.domain.dtos.app_configuration_dto import AppConfigurationDto
from api.domain.dtos.tenant_dto import CreateTenantDto, PublicTenantDto
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
# Mock Database for app-configuration tests
# ------------------------
@pytest.fixture
def mock_db():
    with patch("api.infrastructure.persistence.mongodb.Database", new_callable=AsyncMock) as mock_database:
        yield mock_database



async def create_tenant(client: AsyncClient, mock_post_tenant_service) -> CreateUserResponseDto:
    new_tenant = CreateTenantDto(
       name="test",
       admin_email="test@test.com",
       admin_password="Test1234!",
       first_name="Test",
       last_name="Admin",
       gender=Gender.MALE,
       subdomain="test.fsrapp.com",
    )
    response = await client.post("/tenants/", json=new_tenant.model_dump())
    assert response.status_code == 201
    # The security-headers middleware (security_headers_middleware.py)
    # stamps every HTTP response, not just GETs, and the tenant file's
    # own create_tenant helper already locks its headers in — but this
    # file's copy of the helper asserted only the 201, so deleting the
    # middleware registration would have gone uncaught on this
    # tenant-create response. The test client runs the real app over
    # ASGI transport, so the pure-ASGI middleware applies here exactly
    # as in production.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the seven most sensitive directives as disabled, mirroring the
    # app-config GET lock in this file and the nonexistent-role 404
    # lock (iteration 1893), using substring checks so later additions
    # to the list do not break this test. The full value lives in
    # _SECURITY_HEADERS. The fifth, clipboard-read, is safe to lock
    # here: the SPA never reads the clipboard (only writeText calls,
    # verified by grep in iteration 1914 and re-verified this run).
    # The sixth, display-capture, is safe to lock here: the SPA has
    # no screen-sharing flow (zero getDisplayMedia calls, verified
    # by grep this run). The seventh, fullscreen, is safe to lock
    # here: the SPA never calls requestFullscreen and has no
    # video/audio element (verified by grep this run), so no
    # fullscreen flow exists to break, and a compromised script
    # could otherwise fullscreen-spoof the app UI.
    permissions_policy = response.headers["permissions-policy"]
    assert "camera=()" in permissions_policy
    assert "microphone=()" in permissions_policy
    assert "geolocation=()" in permissions_policy
    assert "payment=()" in permissions_policy
    assert "clipboard-read=()" in permissions_policy
    assert "display-capture=()" in permissions_policy
    assert "fullscreen=()" in permissions_policy
    mock_post_tenant_service.assert_awaited()

    return CreateUserResponseDto.model_validate(response.json())



@pytest.mark.asyncio
async def test_app_configuration_as_logged_out_visitor(client: AsyncClient, mock_post_tenant_service, mock_db):
    """
        Get the app configuration as a logged-out visitor:
        the tenant resolved via X-Tenant-ID must come back in the
        public shape only, never with billing/entitlement fields.
    """
    new_tenant_response = await create_tenant(client, mock_post_tenant_service)
    # No Authorization header: current_user_optional resolves to None,
    # so this is the public login-page fetch (iteration 1781), while
    # X-Tenant-ID resolves the tenant exactly as the frontend sends it.
    response = await client.get("/app_configuration/", headers={"X-Tenant-ID": new_tenant_response.id})
    assert response.status_code == 200
    data = AppConfigurationDto.model_validate(response.json())
    assert data.is_user_logged_in == False
    assert data.current_tenant is not None
    # The app-config endpoint narrows to PublicTenantDto for logged-out
    # callers since iteration 1781, but only the search routes had
    # tests locking that narrowing in (iterations 1782-1783) — a
    # regression here (returning the full TenantDto with
    # subscription_id/features to anyone loading the login page)
    # would have gone uncaught. Asserting the absence of both withheld
    # fields closes that gap for this third public surface.
    current_tenant = response.json()["current_tenant"]
    assert "subscription_id" not in current_tenant
    assert "features" not in current_tenant
    public_tenant = PublicTenantDto.model_validate(current_tenant)
    assert public_tenant.name == "test"
    assert public_tenant.subdomain == "test.fsrapp.com"
    assert public_tenant.id == new_tenant_response.id
    # The endpoint comment requires this GET never to be served from a
    # browser or proxy cache (it carries per-user preferences and the
    # current tenant's branding), but no test locked the headers in —
    # deleting the two header lines would have gone uncaught.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"
    # The security-headers middleware (security_headers_middleware.py)
    # must stamp every response, but only the permissions, roles, and
    # users GETs locked its headers in (iterations 1820-1822) — deleting
    # the middleware registration would have gone uncaught on this
    # route too. The test client runs the real app over ASGI transport,
    # so the pure-ASGI middleware applies here exactly as in production.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the seven most sensitive directives as disabled, mirroring the
    # permissions GET lock (iteration 1865) and the user/role/tenant
    # create locks (iterations 1866-1868), using substring checks so
    # later additions to the list do not break this test. The full
    # value lives in _SECURITY_HEADERS. The fifth, clipboard-read,
    # is safe to lock here: the SPA never reads the clipboard
    # (only writeText calls, verified by grep in iteration 1914
    # and re-verified this run). The sixth, display-capture, is
    # safe to lock here: the SPA has no screen-sharing flow (zero
    # getDisplayMedia calls, verified by grep this run). The
    # seventh, fullscreen, is safe to lock here: the SPA never
    # calls requestFullscreen and has no video/audio element
    # (verified by grep this run), so no fullscreen flow exists
    # to break, and a compromised script could otherwise
    # fullscreen-spoof the app UI.
    permissions_policy = response.headers["permissions-policy"]
    assert "camera=()" in permissions_policy
    assert "microphone=()" in permissions_policy
    assert "geolocation=()" in permissions_policy
    assert "payment=()" in permissions_policy
    assert "clipboard-read=()" in permissions_policy
    assert "display-capture=()" in permissions_policy
    assert "fullscreen=()" in permissions_policy
