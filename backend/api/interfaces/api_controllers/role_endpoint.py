from typing import Annotated, List
from beanie import PydanticObjectId
from fastapi import APIRouter, Depends, Query, Response, status
from api.common.exceptions import InvalidOperationException
from api.common.utils import get_logger
from api.domain.dtos.role_dto import CreateRoleDto, CreateRoleResponseDto, RoleDto, RoleListDto, UpdateRoleDto
from api.core.container import get_role_service, get_user_service
from api.domain.enum.permission import Permission
from api.infrastructure.security.current_user import CurrentUser
from api.interfaces.security.role_checker import check_permissions_for_current_role
from api.usecases.role_service import RoleService
from api.usecases.user_service import UserService


logger = get_logger(__name__)

router = APIRouter(prefix="/roles", tags=["Roles"])


@router.get("/", response_model=RoleListDto)
async def list_roles(
    response: Response,
    current_user: CurrentUser,
    # Same unbounded-pagination gap as GET /users/ (iteration 237):
    # a direct API call could pass limit=1000000 or negative values
    # straight into the DB query. Cap server-side; out-of-range
    # values now fail fast with a 422 instead.
    skip: int = Query(0, ge=0, le=10000),
    limit: int = Query(10, ge=1, le=100),
    service: RoleService = Depends(get_role_service),
    _bool: bool = Depends(check_permissions_for_current_role(required_permissions=[Permission.ROLE_VIEW_ONLY]))

):
    # This GET returns the tenant's role list (names and permissions), so
    # it must never be served from a browser or proxy cache: a cached
    # 200 could serve one tenant's roles to another admin after an
    # account switch on a shared machine, or hide freshly created,
    # updated, or deleted roles — the same no-store hardening as the
    # GET /users/ list in the same sweep.
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    logger.info(f"Listing roles with skip={skip}, limit={limit}")
    # Scope to the caller's tenant: tenant requests normally hit the
    # tenant database (TenantMiddleware), but a tenant user calling
    # without a tenant DB selected (no X-Tenant-ID/subdomain) would
    # otherwise read the host database's full role table — names and
    # permissions of every tenant's roles. Host callers (tenant_id None)
    # keep the global view, the same scope rule as the GET /users/
    # list and the dashboard metrics.
    return await service.list_roles(skip=skip, limit=limit, tenant_id=current_user.tenant_id)

@router.get("/search_by_name", response_model=List[RoleDto])
async def search_role_by_name(
    response: Response,
    name: str,
    current_user: CurrentUser,
    _bool: bool = Depends(check_permissions_for_current_role(required_permissions=[Permission.ROLE_VIEW_ONLY])),
    service: RoleService = Depends(get_role_service)
):
    # Same no-store hardening as the GET /roles/ list above: this GET
    # returns matching roles (names and permissions), so a cached 200
    # could serve one tenant's roles to another admin after an account
    # switch, or hide freshly created/updated roles.
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    # Scope to the caller's tenant, the same rule as the GET /roles/
    # list: tenant requests normally hit the tenant database
    # (TenantMiddleware), but a tenant user calling without a tenant DB
    # selected (no X-Tenant-ID/subdomain) would otherwise search the
    # host database's full role table. Host callers (tenant_id None)
    # keep the global view.
    roles = await service.search_role_by_name(name, tenant_id=current_user.tenant_id)
    return [RoleDto(**(await role.to_serializable_dict())) for role in roles]

@router.post("/", response_model=CreateRoleResponseDto, status_code=status.HTTP_201_CREATED)
async def create_role(
    data: CreateRoleDto,
    service: RoleService = Depends(get_role_service),
    _bool: bool = Depends(check_permissions_for_current_role(required_permissions=[Permission.ROLE_READ_AND_WRITE_ONLY]))
):  
    new_user_id = await service.create_role(data)
    return CreateRoleResponseDto(id=str(new_user_id))


@router.get("/{role_id}", response_model=RoleDto)
async def get_role(
    response: Response,
    role_id: str,
    service: RoleService = Depends(get_role_service),
    _bool: bool = Depends(check_permissions_for_current_role(required_permissions=[Permission.ROLE_VIEW_ONLY]))
):
    # Same no-store hardening as the GET /roles/ list above: this GET
    # returns a single role (name and permissions), so a cached 200
    # could serve one tenant's role to another admin after an account
    # switch, or hide a freshly updated role.
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    role = await service.get_role_by_id(role_id)
    role_doc = await role.to_serializable_dict()
    return RoleDto(**role_doc)


@router.put("/{role_id}", response_model=RoleDto, status_code=status.HTTP_200_OK)
async def update_role(
    role_id: str,
    data: UpdateRoleDto,
    service: RoleService = Depends(get_role_service),
    _bool: bool = Depends(check_permissions_for_current_role(required_permissions=[Permission.ROLE_READ_AND_WRITE_ONLY]))
):
    role_doc = await service.update_role(role_id=role_id, role_data=data)
    serialized_role = await role_doc.to_serializable_dict()
    return RoleDto(**serialized_role)


@router.delete("/{role_id:path}", status_code=status.HTTP_202_ACCEPTED, description="Deletes a role if it is not assigned to any users.")
async def delete_role(
    role_id: str,
    service: RoleService = Depends(get_role_service),
    user_service: UserService = Depends(get_user_service),
    _bool: bool = Depends(check_permissions_for_current_role(required_permissions=[Permission.ROLE_DELETE_ONLY]))
):
    users_role = await user_service.total_count(params={"role_id": role_id})
    logger.debug(f"Number of users with role {role_id}: {users_role}")
    if users_role > 0:
        logger.warning(f"Cannot delete role {role_id} as it is assigned to users.")
        raise InvalidOperationException(f"Cannot delete role {role_id} as it is assigned to users.")
    
    await service.delete_role(role_id)
    return status.HTTP_202_ACCEPTED


