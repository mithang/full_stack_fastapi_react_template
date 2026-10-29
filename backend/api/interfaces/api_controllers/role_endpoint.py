from typing import Annotated, List
from beanie import PydanticObjectId
from fastapi import APIRouter, Depends, Query, Response, status
from api.common.exceptions import ForbiddenException, InvalidOperationException
from api.common.utils import get_logger
from api.domain.dtos.role_dto import CreateRoleDto, CreateRoleResponseDto, RoleDto, RoleListDto, UpdateRoleDto
from api.core.container import get_role_service, get_user_service
from api.domain.enum.permission import Permission
from api.infrastructure.security.current_user import CurrentUser
from api.interfaces.middlewares.tenant_middleware import get_tenant_id
from api.interfaces.security.role_checker import check_permissions_for_current_role
from api.usecases.role_service import RoleService
from api.usecases.user_service import UserService


logger = get_logger(__name__)

router = APIRouter(prefix="/roles", tags=["Roles"])


def _assert_create_scope(current_user: CurrentUser, request_tenant_id) -> None:
    # Create-in-wrong-DB guard, mirroring the banner (iteration 869),
    # SSO, and branding guards: tenancy is per-database, so a tenant
    # caller creating on the host DB (no X-Tenant-ID/subdomain,
    # request scope None) would plant a role in the host DB that host
    # callers then see in their global list. Legitimate tenant role
    # creation happens in the caller's own tenant DB, where the
    # middleware scope equals their tenant id, and host callers
    # (tenant_id None) are unaffected. A mismatched scope fails closed
    # rather than stamping a record into the wrong DB.
    if current_user.tenant_id is not None and (
        request_tenant_id is None or str(request_tenant_id) != str(current_user.tenant_id)
    ):
        raise ForbiddenException("Role cannot be created outside your tenant's scope.")


def _assert_delete_scope(current_user: CurrentUser, request_tenant_id) -> None:
    # Delete-in-wrong-DB guard, mirroring the update guard above and
    # the notification-banner/SSO/storage delete guards (iterations
    # 902-904): the service already refuses a record stamped for
    # another tenant, but it does not check which database served
    # the request. So a tenant caller deleting on the host DB (no
    # X-Tenant-ID/subdomain, request scope None) could still delete
    # a tenant-stamped role sitting in the host DB (e.g. planted
    # before the create guard), removing a role that host callers
    # resolve by id with no tenant scope. Legitimate tenant role
    # deletes happen in the caller's own tenant DB, where the
    # middleware scope equals their tenant id, and host callers
    # (tenant_id None) are unaffected. A mismatched scope fails
    # closed before any delete.
    if current_user.tenant_id is not None and (
        request_tenant_id is None or str(request_tenant_id) != str(current_user.tenant_id)
    ):
        raise ForbiddenException("Role cannot be deleted outside your tenant's scope.")


def _assert_update_scope(current_user: CurrentUser, request_tenant_id) -> None:
    # Update-in-wrong-DB guard, mirroring the create guard above and
    # the notification-banner/SSO/storage update guards (iterations
    # 902-904): the service already refuses a record stamped for
    # another tenant, but it does not check which database served
    # the request. So a tenant caller updating on the host DB (no
    # X-Tenant-ID/subdomain, request scope None) could still edit a
    # tenant-stamped role sitting in the host DB (e.g. planted
    # before the create guard), changing its name or permissions
    # where host callers resolve roles by id with no tenant scope.
    # Legitimate tenant role edits happen in the caller's own tenant
    # DB, where the middleware scope equals their tenant id, and
    # host callers (tenant_id None) are unaffected. A mismatched
    # scope fails closed before any write.
    if current_user.tenant_id is not None and (
        request_tenant_id is None or str(request_tenant_id) != str(current_user.tenant_id)
    ):
        raise ForbiddenException("Role cannot be updated outside your tenant's scope.")


def _assert_list_scope(current_user: CurrentUser, request_tenant_id) -> None:
    # List-in-wrong-DB guard, mirroring the users list guard and the
    # update guard above: the service already scopes the list to the
    # caller's tenant stamp, but it does not check which database
    # served the request. So a tenant caller listing on the host DB
    # (no X-Tenant-ID/subdomain, request scope None) could still read
    # tenant-stamped roles sitting in the host DB (e.g. planted before
    # the create guard) — names and permissions of roles host callers
    # resolve by id with no tenant scope. Legitimate tenant role lists
    # happen in the caller's own tenant DB, where the middleware scope
    # equals their tenant id (the frontend ApiClient sends X-Tenant-ID),
    # and host callers (tenant_id None) are unaffected. A mismatched
    # scope fails closed before any read.
    if current_user.tenant_id is not None and (
        request_tenant_id is None or str(request_tenant_id) != str(current_user.tenant_id)
    ):
        raise ForbiddenException("Roles cannot be listed outside your tenant's scope.")


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
    _bool: bool = Depends(check_permissions_for_current_role(required_permissions=[Permission.ROLE_VIEW_ONLY])),
    request_tenant_id = Depends(get_tenant_id)
):
    _assert_list_scope(current_user, request_tenant_id)
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
    current_user: CurrentUser,
    service: RoleService = Depends(get_role_service),
    _bool: bool = Depends(check_permissions_for_current_role(required_permissions=[Permission.ROLE_READ_AND_WRITE_ONLY])),
    request_tenant_id = Depends(get_tenant_id)
):
    _assert_create_scope(current_user, request_tenant_id)
    # Stamp server-side from the authenticated caller, as the branding
    # routes do: the DTO's tenant_id is client-supplied, so trusting
    # it would let any caller stamp a role with another tenant's id
    # (or None). The legitimate frontend sends no tenant_id at all,
    # so tenant callers previously created unstamped roles that their
    # own tenant-filtered list then hid from them, while host callers
    # saw them in the global view. Host callers (tenant_id None) keep
    # the historic unstamped creation.
    data.tenant_id = current_user.tenant_id
    new_user_id = await service.create_role(data)
    return CreateRoleResponseDto(id=str(new_user_id))


@router.get("/{role_id}", response_model=RoleDto)
async def get_role(
    response: Response,
    role_id: str,
    current_user: CurrentUser,
    service: RoleService = Depends(get_role_service),
    _bool: bool = Depends(check_permissions_for_current_role(required_permissions=[Permission.ROLE_VIEW_ONLY]))
):
    # Same no-store hardening as the GET /roles/ list above: this GET
    # returns a single role (name and permissions), so a cached 200
    # could serve one tenant's role to another admin after an account
    # switch, or hide a freshly updated role.
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    # Tenant-scoped like the list: a tenant caller reading another
    # tenant's id gets the same 404 as an unknown id.
    role = await service.get_role_by_id(role_id, tenant_id=current_user.tenant_id)
    role_doc = await role.to_serializable_dict()
    return RoleDto(**role_doc)


@router.put("/{role_id}", response_model=RoleDto, status_code=status.HTTP_200_OK)
async def update_role(
    role_id: str,
    data: UpdateRoleDto,
    current_user: CurrentUser,
    service: RoleService = Depends(get_role_service),
    _bool: bool = Depends(check_permissions_for_current_role(required_permissions=[Permission.ROLE_READ_AND_WRITE_ONLY])),
    request_tenant_id = Depends(get_tenant_id),
):
    _assert_update_scope(current_user, request_tenant_id)
    role_doc = await service.update_role(role_id=role_id, role_data=data, tenant_id=current_user.tenant_id)
    serialized_role = await role_doc.to_serializable_dict()
    return RoleDto(**serialized_role)


@router.delete("/{role_id:path}", status_code=status.HTTP_202_ACCEPTED, description="Deletes a role if it is not assigned to any users.")
async def delete_role(
    role_id: str,
    current_user: CurrentUser,
    service: RoleService = Depends(get_role_service),
    user_service: UserService = Depends(get_user_service),
    _bool: bool = Depends(check_permissions_for_current_role(required_permissions=[Permission.ROLE_DELETE_ONLY])),
    request_tenant_id = Depends(get_tenant_id),
):
    _assert_delete_scope(current_user, request_tenant_id)
    # Scope check before the assigned-users check: the service raises
    # the same 404 for a cross-tenant id as for an unknown id, so the
    # "cannot delete" error below cannot confirm another tenant's role
    # exists. (delete_role re-checks scope internally as well.)
    await service.get_role_by_id(role_id, tenant_id=current_user.tenant_id)
    users_role = await user_service.total_count(params={"role_id": role_id})
    logger.debug(f"Number of users with role {role_id}: {users_role}")
    if users_role > 0:
        logger.warning(f"Cannot delete role {role_id} as it is assigned to users.")
        raise InvalidOperationException(f"Cannot delete role {role_id} as it is assigned to users.")

    await service.delete_role(role_id, tenant_id=current_user.tenant_id)
    return status.HTTP_202_ACCEPTED


