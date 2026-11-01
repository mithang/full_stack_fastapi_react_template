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



@pytest.mark.asyncio
async def test_get_nonexistent_tenant_by_name_as_host(client: AsyncClient,  mock_db):
    """
        Attempt to get a non-existent tenant by name:
    """
    response = await client.get("/tenants/search_by_name/nonexistent-tenant")
    assert response.status_code == 404
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
    # Create a single user and return the response

    # Verify the user was created by listing users again
    response = await client.get("/tenants/?skip=0&limit=1")
    assert response.status_code == 200
    data = TenantListDto.model_validate(response.json())
    assert data.total == 3
    assert len(data.tenants) == 1
    assert data.hasNext == True
    assert data.hasPrevious == False
    assert data.skip == 0
    assert data.limit == 1

    response = await client.get("/tenants/?skip=1&limit=1")
    assert response.status_code == 200
    data = TenantListDto.model_validate(response.json())
    assert data.total == 3
    assert len(data.tenants) == 1
    assert data.hasNext == True
    assert data.hasPrevious == True
    assert data.skip == 1
    assert data.limit == 1

    response = await client.get("/tenants/?skip=2&limit=1")
    assert response.status_code == 200
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
    assert response.json()["error"] == "Password must be at least 8 characters long, include uppercase and lowercase letters, a number, and a special character."
