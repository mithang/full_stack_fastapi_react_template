from fastapi import APIRouter, Depends, File, Query, Response, UploadFile, status
from api.common.exceptions import ForbiddenException, InvalidOperationException
from api.common.utils import get_logger, is_tenancy_enabled
from api.domain.dtos.user_dto import CreateUserDto, CreateUserResponseDto, UpdateUserDto, UserDto, UserListDto, UserProfileImageUpdateDto, UserRoleUpdateRequestDto
from api.domain.enum.permission import Permission
from api.interfaces.security.role_checker import check_permissions_for_current_role
from api.usecases.file_service import FileService
from api.usecases.user_service import UserService
from api.core.container import get_file_service, get_role_service, get_user_service
from api.infrastructure.security.current_user import CurrentUser
from api.usecases.role_service import RoleService
from api.domain.enum.role import RoleType


logger = get_logger(__name__)

router = APIRouter(prefix="/users", tags=["Users"])


@router.get("/", response_model=UserListDto)
async def list_users(
    response: Response,
    current_user: CurrentUser,
    # The frontend only ever requests limit 10, but a direct API call
    # passed limit/skip straight into the DB query unbounded, so a
    # single request could dump the whole user table (limit=1000000)
    # or behave unpredictably on negative values. Cap server-side;
    # out-of-range values now fail fast with a 422 instead.
    skip: int = Query(0, ge=0, le=10000),
    limit: int = Query(10, ge=1, le=100),
    service: UserService = Depends(get_user_service),
    _bool: bool = Depends(check_permissions_for_current_role(required_permissions=[Permission.USER_VIEW_ONLY]))
):
    # This GET returns the tenant's user list (names, emails, roles), so
    # it must never be served from a browser or proxy cache: a cached
    # 200 could serve one tenant's list to another admin after an
    # account switch on a shared machine, or hide freshly created or
    # deleted users — the same no-store hardening as the single-user
    # GET below.
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    # Scope to the caller's tenant: tenant requests normally hit the
    # tenant database (TenantMiddleware), but a tenant user calling
    # without a tenant DB selected (no X-Tenant-ID/subdomain) would
    # otherwise read the host database's full user table — names and
    # emails of every tenant's users. Host callers (tenant_id None)
    # keep the global view, the same scope rule as the dashboard
    # metrics and the invoices/products lists.
    return await service.list_users(skip=skip, limit=limit, tenant_id=current_user.tenant_id)


@router.post("/", response_model=CreateUserResponseDto, status_code=status.HTTP_201_CREATED)
async def create_user(
    data: CreateUserDto,
    current_user: CurrentUser,
    service: UserService = Depends(get_user_service),
    role_service: RoleService = Depends(get_role_service),
    _bool: bool = Depends(check_permissions_for_current_role(required_permissions=[Permission.USER_READ_AND_WRITE_ONLY]))
):

    data.tenant_id = current_user.tenant_id
    role_guest = await role_service.find_by_name(name=RoleType.GUEST)
    data.role_id = role_guest.id
    new_user_id = await service.create_user(data)
    return CreateUserResponseDto(id=str(new_user_id))


@router.get("/{user_id}", response_model=UserDto)
async def get_user(
    response: Response,
    user_id: str,
    current_user: CurrentUser,
    service: UserService = Depends(get_user_service),
    _bool: bool = Depends(check_permissions_for_current_role(
        required_permissions=[Permission.USER_SELF_READ_AND_WRITE_ONLY],
        allow_self_access=True)
    )
):
    # This GET returns one user's personal data (name, email, role), so
    # it must never be served from a browser or proxy cache: a cached
    # 200 could serve a previous user's record after an account switch
    # on a shared machine, or stale data after a role/profile change —
    # the same no-store hardening as the profile-image GET above.
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    # Scope to the caller's tenant, mirroring list_users() and the
    # single-record role/SSO endpoints: the list was already scoped,
    # but this detail read was not, so a tenant admin with
    # USER_VIEW_ONLY could read any other tenant's user by id (name,
    # email, role). A cross-tenant id now answers with the same 404
    # as an unknown id; self-access is unaffected, since the caller's
    # tenant_id comes from their own record.
    user = await service.get_user_by_id(user_id, tenant_id=current_user.tenant_id)
    user_doc = await user.to_serializable_dict()
    return UserDto(**user_doc)


@router.put("/{user_id}", response_model=UserDto, status_code=status.HTTP_200_OK)
async def update_user(
    user_id: str,
    data: UpdateUserDto,
    current_user: CurrentUser,
    service: UserService = Depends(get_user_service),
    role_service: RoleService = Depends(get_role_service),
    _bool: bool = Depends(check_permissions_for_current_role(
        required_permissions=[Permission.USER_READ_AND_WRITE_ONLY, Permission.USER_SELF_READ_AND_WRITE_ONLY],
        allow_self_access=True)
    )

):
    # Role changes must go through the dedicated assign/remove endpoints'
    # permission (USER_ROLE_ASSIGN_OR_REMOVE_ONLY). UpdateUserDto carries
    # role_id and the service applies it, so without this check a caller
    # with only self or user-write access could escalate by PUTting their
    # own record (or another user's) with an admin role id, bypassing
    # the self-action guards on assign_role/remove_role. A no-op (the
    # role id already on the target) is allowed so full-DTO clients
    # echoing the current role are not broken.
    if data.role_id is not None:
        existing_user = await service.get_user_by_id(user_id, tenant_id=current_user.tenant_id)
        if str(existing_user.role_id) != data.role_id:
            # A real role change on one's own record is self-assignment
            # by another route, so it is barred exactly like assign_role
            # and remove_role are, even for callers who hold the role
            # assignment permission (a holder could otherwise promote
            # themselves to an admin role via PUT).
            if str(current_user.id) == user_id:
                raise ForbiddenException("Users cannot assign a role to themselves.")
            caller_permissions = []
            if current_user.role_id is not None:
                caller_role = await role_service.get_role_by_id(role_id=str(current_user.role_id))
                caller_permissions = caller_role.permissions or []
            can_assign_roles = (
                Permission.FULL_ACCESS in caller_permissions
                or Permission.USER_ROLE_ASSIGN_OR_REMOVE_ONLY in caller_permissions
                or (is_tenancy_enabled() and Permission.HOST_MANAGE_TENANTS in caller_permissions)
            )
            if not can_assign_roles:
                raise ForbiddenException("Only users with role assignment permission can change a user's role.")
            # The target user is scoped to the caller's tenant above, but
            # the role itself was not: the service stores any role_id
            # verbatim, and permission checks resolve a user's role by id
            # with no tenant scope, so a tenant admin could PUT another
            # tenant's ADMIN role (FULL_ACCESS) onto their own user — the
            # same escalation closed on assign_role in iteration 879.
            # Verify the role belongs to the caller's tenant; a foreign
            # or unknown id answers with the same 404 as an unknown role,
            # and host callers (tenant_id None) keep the global view.
            # The check runs after the permission check so an unauthorized
            # caller still sees Forbidden, not a role-existence signal,
            # and a no-op echo of the target's current role (already
            # tenant-scoped via get_user_by_id above) needs no check.
            await role_service.get_role_by_id(role_id=data.role_id, tenant_id=current_user.tenant_id)
    user_doc = await service.update_user(user_id=user_id, user_data=data, tenant_id=current_user.tenant_id)
    serialized_user = await user_doc.to_serializable_dict()
    return UserDto(**serialized_user)

@router.get("/profile/{image_key:path}", response_model=UserProfileImageUpdateDto)
async def get_profile_image(
    response: Response,
    image_key: str,
    _bool: bool = Depends(check_permissions_for_current_role(required_permissions=[Permission.USER_VIEW_ONLY])),
    file_service: FileService = Depends(get_file_service)
):
    # This GET returns a freshly minted presigned URL (1-hour expiry),
    # so it must never be served from a browser or proxy cache: a
    # cached 200 would hand back an expired URL after the hour instead
    # of minting a fresh one, breaking the avatar until the cache
    # expires — the same no-store hardening as the passkey GET (which
    # also returns credential-adjacent data). The server-side Redis
    # cache already bypasses this route via its /api/v1/users/
    # substring; this covers the browser/proxy cache it cannot reach.
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    try:
        image_url = await file_service.get_file_url(image_key)
        return UserProfileImageUpdateDto(image_url=image_url)
    except Exception as e:
        # Do not degrade to an empty URL: get_file_url never returns ""
        # on success (it returns a presigned URL or raises a mapped
        # storage exception), so a 200 with image_url="" made a storage
        # outage indistinguishable from "no image" and bypassed both
        # client fallbacks, which only trigger on rejection — the
        # auth-provider's raw-key fallback and the user-table's default
        # avatar. Re-raising lets the mapped handler answer with a
        # clean error and lets those fallbacks engage.
        logger.error(f"Error fetching profile image: {e}")
        raise
    
@router.delete("/{user_id}", status_code=status.HTTP_202_ACCEPTED)
async def delete_user(
    user_id: str,
    current_user: CurrentUser,
    service: UserService = Depends(get_user_service),
    _bool: bool = Depends(check_permissions_for_current_role(required_permissions=[Permission.USER_DELETE_ONLY]))
):
    if str(current_user.id) == user_id:
        raise ForbiddenException("Users cannot delete their own account.")
    # Scope the delete to the caller's tenant, mirroring get_user():
    # without this a tenant admin with USER_DELETE_ONLY could delete
    # any other tenant's user by id. Cross-tenant ids answer with the
    # same 404 as unknown ids (raised inside the service); host
    # callers (tenant_id None) keep the global view.
    await service.delete_user(user_id, tenant_id=current_user.tenant_id)
    return status.HTTP_202_ACCEPTED




@router.put("/{user_id}/update_profile_picture", response_model=UserProfileImageUpdateDto, status_code=status.HTTP_202_ACCEPTED)
async def update_profile_picture(
    user_id: str,
    current_user: CurrentUser,
    file: UploadFile = File(...),
    _bool: bool = Depends(check_permissions_for_current_role(
        required_permissions=[Permission.USER_READ_AND_WRITE_ONLY, Permission.USER_SELF_READ_AND_WRITE_ONLY],
        allow_self_access=True)),
    user_service: UserService = Depends(get_user_service),
    file_service: FileService = Depends(get_file_service),
):
    # The frontend checks for an image file, but a direct API call bypasses
    # it, so validate server-side (mirroring the branding logo upload):
    # anything stored as a profile picture is later served back via a
    # public-ish file URL, so a non-image upload (e.g. HTML) must not
    # reach storage. content_type comes from the multipart header, so
    # this check consumes nothing from the upload stream.
    if not file.content_type or not file.content_type.startswith("image/"):
        raise InvalidOperationException("Profile picture must be an image file.")
    # The frontend caps profile pictures at 5 MB, but a direct API call
    # bypasses it, so enforce the same cap server-side before the file
    # reaches storage. Chunks are counted, not retained, and the stream
    # is rewound afterwards: both storage backends read from the current
    # stream position (S3 via file.file, Azure via file.read()).
    max_size = 5 * 1024 * 1024
    size = 0
    while True:
        chunk = await file.read(1024 * 1024)
        if not chunk:
            break
        size += len(chunk)
        if size > max_size:
            raise InvalidOperationException("Profile picture must be less than 5MB.")
    await file.seek(0)
    # The branding logo upload rejects empty files; mirror it here, before
    # any user lookup or storage call, so an empty upload cannot replace
    # a working avatar with a zero-byte object.
    if size == 0:
        raise InvalidOperationException("Profile picture must not be empty.")
    await user_service.get_user_by_id(user_id, tenant_id=current_user.tenant_id)
    file_location = await file_service.upload_file(file)
    await user_service.update_user(user_id=user_id, user_data=UpdateUserDto(image_url=file_location), tenant_id=current_user.tenant_id)
    return UserProfileImageUpdateDto(image_url=file_location)


@router.patch("/{user_id}/assign_role", response_model=UserDto, status_code=status.HTTP_202_ACCEPTED)
async def patch_user(
    user_id: str, role_update: UserRoleUpdateRequestDto,
    current_user: CurrentUser,
    _: bool = Depends(check_permissions_for_current_role([Permission.USER_ROLE_ASSIGN_OR_REMOVE_ONLY])),
    user_service: UserService = Depends(get_user_service),
    role_service: RoleService = Depends(get_role_service)

):
    if str(current_user.id) == user_id:
        raise ForbiddenException("Users cannot assign a role to themselves.")

    exsisting_user = await user_service.get_user_by_id(user_id, tenant_id=current_user.tenant_id)
    if str(exsisting_user.role_id) == role_update.role_id:
        raise InvalidOperationException("User already has this role assigned")

    # The target user is scoped to the caller's tenant above, but the role
    # itself was not: update_user() stores any role_id verbatim, and
    # permission checks resolve a user's role by id with no tenant scope
    # (UserAccessManagement.get_role_detail), so a tenant admin could
    # assign another tenant's ADMIN role (FULL_ACCESS) to their own user
    # and gain those permissions in their own tenant. Verify the role
    # belongs to the caller's tenant first; a foreign or unknown id
    # answers with the same 404 as an unknown role, and host callers
    # (tenant_id None) keep the global view, matching get_role_by_id.
    await role_service.get_role_by_id(role_id=role_update.role_id, tenant_id=current_user.tenant_id)
    
    user = await user_service.update_user(user_id=user_id, user_data=UpdateUserDto(role_id=role_update.role_id), tenant_id=current_user.tenant_id)
    user_doc = await user.to_serializable_dict()
    return UserDto(**user_doc)
  


@router.patch("/{user_id}/remove_role", response_model=UserDto, status_code=status.HTTP_202_ACCEPTED)
async def remove_user_role(
     user_id: str, role_update: UserRoleUpdateRequestDto,
    current_user: CurrentUser,
    _: bool = Depends(check_permissions_for_current_role([Permission.USER_ROLE_ASSIGN_OR_REMOVE_ONLY])),
    user_service: UserService = Depends(get_user_service)
):
    if str(current_user.id) == user_id:
        raise ForbiddenException("Users cannot remove a role from themselves.")
    exsisting_user = await user_service.get_user_by_id(user_id, tenant_id=current_user.tenant_id)
    if str(exsisting_user.role_id) != role_update.role_id:
        raise InvalidOperationException("User does not have this role assigned")
    
    user = await user_service.update_user(user_id=user_id, user_data=UpdateUserDto(role_id=None), tenant_id=current_user.tenant_id)
    user_doc = await user.to_serializable_dict()
    return UserDto(**user_doc)
