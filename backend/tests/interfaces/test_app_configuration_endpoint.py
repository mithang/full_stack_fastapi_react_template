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
    # the twelve most sensitive directives as disabled, mirroring the
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
    # could otherwise fullscreen-spoof the app UI. The eighth,
    # accelerometer, is safe to lock here: the SPA has no
    # motion-sensor flow (zero DeviceMotion/DeviceOrientation/
    # Accelerometer/Gyroscope/Magnetometer uses, verified by grep
    # this run), so no sensor flow exists to break. The ninth,
    # gyroscope, is safe to lock here: the SPA has no gyroscope
    # flow (zero Gyroscope/DeviceOrientation uses, verified by grep
    # this run), so no sensor flow exists to break. The tenth,
    # magnetometer, is safe to lock here: the SPA has no compass
    # flow (zero Magnetometer uses, verified by grep this run),
    # so no sensor flow exists to break. The eleventh,
    # xr-spatial-tracking, is safe to lock here: the SPA has no
    # XR flow (zero navigator.xr/XRSession/requestSession uses,
    # verified by grep this run, and no webxr/three dependency),
    # so no XR flow exists to break. The twelfth,
    # idle-detection, is safe to lock here: the SPA has no
    # idle-detection flow (zero IdleDetector matches, zero
    # case-insensitive idle matches, and zero requestIdleCallback
    # matches, verified by grep this run), so no idle-presence
    # flow exists to break, and a compromised script could
    # otherwise learn when the user is away from the keyboard.
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
    # the twelve most sensitive directives as disabled, mirroring the
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
    # fullscreen-spoof the app UI. The eighth, accelerometer, is
    # safe to lock here: the SPA has no motion-sensor flow (zero
    # DeviceMotion/DeviceOrientation/Accelerometer/Gyroscope/
    # Magnetometer matches, verified by grep this run). The ninth,
    # gyroscope, is safe to lock here: the SPA has no gyroscope
    # flow (zero Gyroscope/DeviceOrientation uses, verified by grep
    # this run), so no sensor flow exists to break. The tenth,
    # magnetometer, is safe to lock here: the SPA has no compass
    # flow (zero Magnetometer uses, verified by grep this run),
    # so no sensor flow exists to break. The eleventh,
    # xr-spatial-tracking, is safe to lock here: the SPA has no XR
    # flow (zero navigator.xr/XRSession/requestSession uses,
    # verified by grep this run), so no XR flow exists to break. The twelfth,
    # idle-detection, is safe to lock here: the SPA has no
    # idle-detection flow (zero IdleDetector matches, zero
    # case-insensitive idle matches, and zero requestIdleCallback
    # matches, verified by grep this run), so no idle-presence
    # flow exists to break, and a compromised script could
    # otherwise learn when the user is away from the keyboard.
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
async def test_get_app_configuration_with_branded_logo_and_unconfigured_s3_returns_502_with_cache_and_security_headers(client: AsyncClient):
    """
        The app-configuration GET S3 502 path for a stored logo
        with unconfigured S3 credentials:
    """
    # The app-configuration GET S3 502 branch for blank
    # credentials, not yet locked: function-name grep count 0
    # for get_app_configuration_with_branded_logo_and_
    # unconfigured_s3 (verified fresh this run), and grep count
    # 0 for "502" across test_app_configuration_endpoint.py.
    # The S3 502 mapping is locked for the profile-image GET
    # read path, the profile-picture upload path, and the
    # branding logo upload path, but GET /app_configuration/
    # reaches the same fail-closed constructor through a
    # different caller: BrandingService.get_branding()
    # (branding_service.py:46) resolves a stored logo_url
    # through file_service.get_file_url whenever a branding
    # record carries one, and the app-configuration handler
    # calls get_branding() on every page load (including the
    # public login page), so a branding with a logo plus a
    # misconfigured storage provider 502s the whole page load
    # instead of serving the config. Deleting the fail-closed
    # blank-key raise in S3Storage.__init__ would previously
    # have gone uncaught on this path - boto3 would silently
    # resolve ambient credentials (env vars, shared config,
    # IAM role) and presign the logo URL under the
    # deployment's credentials, hiding a misconfiguration
    # from the client fallbacks that only trigger on
    # rejection. The 502 here is deterministic with no network
    # and no live S3 call: the blank check runs before any
    # boto3 client construction or HTTP request
    # (s3_storage.py:12-23), so no credential resolution,
    # signing, or request happens. The handler chain is: no
    # Authorization header, so current_user_optional resolves
    # to None (current_user.py:47-60, exceptions swallowed to
    # None) and the user-preference/passkey lookups are
    # skipped; no X-Tenant-ID header, so get_tenant_id returns
    # None (tenant_middleware.py:138-139) and get_tenant
    # returns None without a service call; then
    # get_only_enabled_providers() runs before get_branding()
    # (app_configuration_endpoint.py:76-78) - SSOSettings is
    # outside the conftest model set, so the test initializes
    # it on the test DB alongside Branding and
    # StorageSettings, making the whole chain self-contained
    # regardless of which tests ran first in the session
    # (the empty collection returns no providers, and
    # re-initializing a model is a no-op per the branding
    # tests' beanie 2.2.0 verification); branding_service
    # .get_branding() finds the seeded record and, because
    # it carries a logo_url, calls file_service.get_file_url
    # -> FileRetrieval.generate_read_url, which finds the
    # enabled S3 row and constructs S3Storage, which raises;
    # the retrieval try catches only
    # StorageNotEnabledException, so the exception propagates,
    # and the central handler maps AwsException to 502
    # (api/__init__.py:110-117) with {"error": ..., "code":
    # 502} and the no-store/Pragma error headers. The seeded
    # branding carries an explicit tenant_id stamp: BrandingDto
    # .tenant_id is a required str, so a None-stamped record
    # would fail DTO validation inside get_branding() and 500
    # before ever reaching the file service - the stamp is
    # never scope-checked on this read path, so any value
    # keeps the DTO valid (mirroring the PATCH 406 lock's
    # foreign-stamp seed). StorageSettings is outside the
    # conftest model set (conftest.py:25), so the test
    # initializes it on the test DB first: init_beanie on the
    # same URI/db name the conftest fixture uses
    # (mongodb://localhost:27012/test_db, api_test_db), in the
    # same call as Branding, mirroring the branding tests'
    # second-init precedent and the S3/Azure 502 locks. The
    # 502 fires inside get_branding(), so no config is
    # returned and no file is written to storage. A future
    # change that drops the blank fail-closed raise, or that
    # lets blank S3 keys fall through to ambient boto3
    # credentials on this path, would break this lock while
    # leaving the profile-image S3 502 lock, the
    # profile-picture upload S3 502 lock, the branding PUT
    # /logo S3 502 lock, and the app-configuration 200 lock
    # green, so the paths are locked separately.
    from beanie import PydanticObjectId, init_beanie
    from pymongo import AsyncMongoClient

    from api.domain.entities.branding import Branding
    from api.domain.entities.sso_settings import SSOSettings
    from api.domain.entities.storage_settings import StorageProvider, StorageSettings

    mongo_client = AsyncMongoClient("mongodb://localhost:27012/test_db")
    await init_beanie(
        mongo_client["api_test_db"],
        document_models=[Branding, StorageSettings, SSOSettings],
    )

    await Branding(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b38a"),
        tenant_id=PydanticObjectId("68c302ef6bf7a039b7e9b389"),
        logo_url="logo.png",
        logo_type="image/png",
    ).insert()

    await StorageSettings(
        provider=StorageProvider.AWS_S3,
        is_enabled=True,
        region="eu-central-1",
        aws_access_key="",
        aws_secret_key="",
        aws_bucket_name="test-bucket",
    ).insert()

    # No Authorization header and no X-Tenant-ID header: the
    # public login-page fetch, exactly as the frontend sends it
    # on every page load.
    response = await client.get("/app_configuration/")
    assert response.status_code == 502
    body = response.json()
    assert body["code"] == 502
    # S3StorageException prefixes its message ("S3 Storage Error:
    # ..."), so assert on the fail-closed reason itself.
    assert "S3 storage credentials are not configured." in body["error"]
    assert "S3 Storage Error: " in body["error"]
    assert "refresh_token" not in response.headers.get("set-cookie", "")
    # The 502 must still carry the error-response headers: the
    # handler sets no-store only on the success path, so on this
    # path they come from the central ApiBaseException handler,
    # and a cached 502 could otherwise be served to a different
    # user after an account switch on a shared machine.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the app-configuration 200
    # test: the pure-ASGI middleware stamps every HTTP response
    # with no path exclusions, so the app-configuration 502
    # must carry the same headers as the authenticated calls,
    # including the exception-handler responses.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened:
    # lock the twelve most sensitive directives as disabled,
    # mirroring the app-configuration 200 lock, using substring
    # checks so later additions to the list do not break this
    # test. Each directive is safe to lock here for the same
    # reasons as on the other routes: the SPA has no camera,
    # microphone, geolocation, payment, clipboard-read,
    # display-capture, fullscreen, motion-sensor, compass, XR,
    # or idle-detection flow (verified by grep in the earlier
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
    # Postconditions: the 502 fires inside get_branding()
    # before any config is returned, so the request is
    # side-effect free - the seeded branding record is still
    # there with its logo_url (the constructor raises before
    # any read URL is minted), and the storage row is still
    # the enabled S3 row with blank keys and bucket
    # "test-bucket" (the constructor raises before any write
    # or upload).
    stored_branding = await Branding.find_one(
        Branding.id == PydanticObjectId("68c302ef6bf7a039b7e9b38a")
    )
    assert stored_branding is not None
    assert stored_branding.logo_url == "logo.png"
    assert stored_branding.tenant_id == PydanticObjectId("68c302ef6bf7a039b7e9b389")
    stored_settings = await StorageSettings.find_one(
        StorageSettings.is_enabled == True
    )
    assert stored_settings is not None
    assert stored_settings.provider == StorageProvider.AWS_S3
    assert stored_settings.aws_access_key == ""
    assert stored_settings.aws_secret_key == ""
    assert stored_settings.aws_bucket_name == "test-bucket"
    await mongo_client.close()


@pytest.mark.asyncio
async def test_get_app_configuration_with_branded_logo_and_unconfigured_azure_returns_502_with_cache_and_security_headers(client: AsyncClient):
    """
        The app-configuration GET Azure 502 path for a stored logo
        with an unconfigured Azure connection string:
    """
    # The app-configuration GET Azure 502 branch for a blank
    # connection string, not yet locked: function-name grep count
    # 0 for get_app_configuration_with_branded_logo_and_
    # unconfigured_azure (verified fresh this run), and grep count
    # 0 for "unconfigured_azure" across
    # test_app_configuration_endpoint.py. The S3 502 lock
    # (previous run) covers only the AWS_S3 branch, while the
    # central ApiBaseException handler maps AwsException/
    # AzureException to 502 (api/__init__.py:110-117) with no
    # lock on the Azure branch of this route. Before the
    # production fail-closed fix, a blank Azure connection
    # string raised a bare ValueError from
    # BlobServiceClient.from_connection_string, which is not an
    # ApiBaseException and so bypassed the central handler
    # entirely, surfacing as an unhandled 500 instead of a 502
    # and hiding an upstream failure from the client fallbacks
    # that only trigger on rejection. The 502 here is
    # deterministic with no network and no live Azure call: the
    # seeded StorageSettings row enables AZURE_BLOB with a blank
    # connection string, and AzureBlobStorage.__init__
    # (azure_storage.py) raises AzureBlobStorageException
    # ("Azure Blob Storage connection string is not
    # configured.") before constructing a BlobServiceClient, so
    # no credential resolution, signing, or HTTP request
    # happens. The handler chain is: no Authorization header,
    # so current_user_optional resolves to None
    # (current_user.py:47-60, exceptions swallowed to None) and
    # the user-preference/passkey lookups are skipped; no
    # X-Tenant-ID header, so get_tenant_id returns None
    # (tenant_middleware.py:138-139) and get_tenant returns None
    # without a service call; then get_only_enabled_providers()
    # runs before get_branding()
    # (app_configuration_endpoint.py:76-78) - SSOSettings is
    # outside the conftest model set, so the test initializes
    # it on the test DB alongside Branding and StorageSettings,
    # making the whole chain self-contained regardless of which
    # tests ran first in the session (the empty collection
    # returns no providers, and re-initializing a model is a
    # no-op per the branding tests' beanie 2.2.0 verification);
    # branding_service.get_branding() finds the seeded record
    # and, because it carries a logo_url, calls
    # file_service.get_file_url -> FileRetrieval.
    # generate_read_url, which finds the enabled Azure row and
    # constructs AzureBlobStorage, which raises; the retrieval
    # try catches only StorageNotEnabledException, so the
    # exception propagates, and the central handler maps
    # AzureException to 502 (api/__init__.py:110-117) with
    # {"error": ..., "code": 502} and the no-store/Pragma error
    # headers. The seeded branding carries an explicit tenant_id
    # stamp: BrandingDto.tenant_id is a required str, so a
    # None-stamped record would fail DTO validation inside
    # get_branding() and 500 before ever reaching the file
    # service - the stamp is never scope-checked on this read
    # path, so any value keeps the DTO valid (mirroring the
    # PATCH 406 lock's foreign-stamp seed and the S3 lock's
    # seed). StorageSettings is outside the conftest model set
    # (conftest.py:25), so the test initializes it on the test
    # DB first: init_beanie on the same URI/db name the
    # conftest fixture uses (mongodb://localhost:27012/test_db,
    # api_test_db), in the same call as Branding, mirroring the
    # branding tests' second-init precedent and the S3/Azure 502
    # locks; the conftest fixture drops the DB after each test,
    # so the S3 lock's identical seed ids cannot collide with
    # this test. The 502 fires inside get_branding(), so no
    # config is returned and no file is written to storage. A
    # future change that drops the blank fail-closed raise, or
    # that lets the Azure constructor fall through to the SDK's
    # bare ValueError on this path, would break this lock while
    # leaving the profile-image Azure 502 lock, the
    # profile-picture upload Azure 502 lock, the branding PUT
    # /logo Azure 502 lock, the app-configuration
    # S3 502 lock, and the app-configuration 200 lock green, so
    # the paths are locked separately.
    from beanie import PydanticObjectId, init_beanie
    from pymongo import AsyncMongoClient

    from api.domain.entities.branding import Branding
    from api.domain.entities.sso_settings import SSOSettings
    from api.domain.entities.storage_settings import StorageProvider, StorageSettings

    mongo_client = AsyncMongoClient("mongodb://localhost:27012/test_db")
    await init_beanie(
        mongo_client["api_test_db"],
        document_models=[Branding, StorageSettings, SSOSettings],
    )

    await Branding(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b38a"),
        tenant_id=PydanticObjectId("68c302ef6bf7a039b7e9b389"),
        logo_url="logo.png",
        logo_type="image/png",
    ).insert()

    await StorageSettings(
        provider=StorageProvider.AZURE_BLOB,
        is_enabled=True,
        region="eu-central-1",
        azure_connection_string="",
        azure_container_name="test-container",
    ).insert()

    # No Authorization header and no X-Tenant-ID header: the
    # public login-page fetch, exactly as the frontend sends it
    # on every page load.
    response = await client.get("/app_configuration/")
    assert response.status_code == 502
    body = response.json()
    assert body["code"] == 502
    # AzureBlobStorageException prefixes its message ("Azure Blob
    # Storage Error: ..."), so assert on the fail-closed reason
    # itself.
    assert "Azure Blob Storage connection string is not configured." in body["error"]
    assert "Azure Blob Storage Error: " in body["error"]
    assert "refresh_token" not in response.headers.get("set-cookie", "")
    # The 502 must still carry the error-response headers: the
    # handler sets no-store only on the success path, so on this
    # path they come from the central ApiBaseException handler,
    # and a cached 502 could otherwise be served to a different
    # user after an account switch on a shared machine.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the app-configuration 200
    # test: the pure-ASGI middleware stamps every HTTP response
    # with no path exclusions, so the app-configuration 502
    # must carry the same headers as the authenticated calls,
    # including the exception-handler responses.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened:
    # lock the twelve most sensitive directives as disabled,
    # mirroring the app-configuration 200 lock, using substring
    # checks so later additions to the list do not break this
    # test. Each directive is safe to lock here for the same
    # reasons as on the other routes: the SPA has no camera,
    # microphone, geolocation, payment, clipboard-read,
    # display-capture, fullscreen, motion-sensor, compass, XR,
    # or idle-detection flow (verified by grep in the earlier
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
    # Postconditions: the 502 fires inside get_branding()
    # before any config is returned, so the request is
    # side-effect free - the seeded branding record is still
    # there with its logo_url (the constructor raises before
    # any read URL is minted), and the storage row is still
    # the enabled Azure row with a blank connection string and
    # container "test-container" (the constructor raises before
    # any write or upload).
    stored_branding = await Branding.find_one(
        Branding.id == PydanticObjectId("68c302ef6bf7a039b7e9b38a")
    )
    assert stored_branding is not None
    assert stored_branding.logo_url == "logo.png"
    assert stored_branding.tenant_id == PydanticObjectId("68c302ef6bf7a039b7e9b389")
    stored_settings = await StorageSettings.find_one(
        StorageSettings.is_enabled == True
    )
    assert stored_settings is not None
    assert stored_settings.provider == StorageProvider.AZURE_BLOB
    assert stored_settings.azure_connection_string == ""
    assert stored_settings.azure_container_name == "test-container"
    await mongo_client.close()
