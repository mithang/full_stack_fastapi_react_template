from fastapi import APIRouter, Depends, File, UploadFile, status
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
    skip: int = 0, limit: int = 10,
    service: UserService = Depends(get_user_service),
    _bool: bool = Depends(check_permissions_for_current_role(required_permissions=[Permission.USER_VIEW_ONLY]))
):
    return await service.list_users(skip=skip, limit=limit)


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
    user_id: str,
    service: UserService = Depends(get_user_service),
    _bool: bool = Depends(check_permissions_for_current_role(
        required_permissions=[Permission.USER_SELF_READ_AND_WRITE_ONLY],
        allow_self_access=True)
    )
):
    user = await service.get_user_by_id(user_id)
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
            existing_user = await service.get_user_by_id(user_id)
            if str(existing_user.role_id) != data.role_id:
                raise ForbiddenException("Only users with role assignment permission can change a user's role.")
    user_doc = await service.update_user(user_id=user_id, user_data=data)
    serialized_user = await user_doc.to_serializable_dict()
    return UserDto(**serialized_user)

@router.get("/profile/{image_key:path}", response_model=UserProfileImageUpdateDto)
async def get_profile_image(
    image_key: str,
    _bool: bool = Depends(check_permissions_for_current_role(required_permissions=[Permission.USER_VIEW_ONLY])),
    file_service: FileService = Depends(get_file_service)
):
    try:
        image_url = await file_service.get_file_url(image_key)
        return UserProfileImageUpdateDto(image_url=image_url)
    except Exception as e:
        logger.error(f"Error fetching profile image: {e}")
        return UserProfileImageUpdateDto(image_url="")
    
@router.delete("/{user_id}", status_code=status.HTTP_202_ACCEPTED)
async def delete_user(
    user_id: str,
    current_user: CurrentUser,
    service: UserService = Depends(get_user_service),
    _bool: bool = Depends(check_permissions_for_current_role(required_permissions=[Permission.USER_DELETE_ONLY]))
):
    if str(current_user.id) == user_id:
        raise ForbiddenException("Users cannot delete their own account.")
    await service.delete_user(user_id)
    return status.HTTP_202_ACCEPTED




@router.put("/{user_id}/update_profile_picture", response_model=UserProfileImageUpdateDto, status_code=status.HTTP_202_ACCEPTED)
async def update_profile_picture(
    user_id: str,
    file: UploadFile = File(...),
    _bool: bool = Depends(check_permissions_for_current_role(
        required_permissions=[Permission.USER_READ_AND_WRITE_ONLY, Permission.USER_SELF_READ_AND_WRITE_ONLY],
        allow_self_access=True)),
    user_service: UserService = Depends(get_user_service),
    file_service: FileService = Depends(get_file_service),
):
    await user_service.get_user_by_id(user_id)
    file_location = await file_service.upload_file(file)
    await user_service.update_user(user_id=user_id, user_data=UpdateUserDto(image_url=file_location))
    return UserProfileImageUpdateDto(image_url=file_location)


@router.patch("/{user_id}/assign_role", response_model=UserDto, status_code=status.HTTP_202_ACCEPTED)
async def patch_user(
    user_id: str, role_update: UserRoleUpdateRequestDto,
    current_user: CurrentUser,
    _: bool = Depends(check_permissions_for_current_role([Permission.USER_ROLE_ASSIGN_OR_REMOVE_ONLY])),
    user_service: UserService = Depends(get_user_service)

):
    if str(current_user.id) == user_id:
        raise ForbiddenException("Users cannot assign a role to themselves.")
    
    exsisting_user = await user_service.get_user_by_id(user_id)
    if str(exsisting_user.role_id) == role_update.role_id:
        raise InvalidOperationException("User already has this role assigned")
    
    user = await user_service.update_user(user_id=user_id, user_data=UpdateUserDto(role_id=role_update.role_id))
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
    exsisting_user = await user_service.get_user_by_id(user_id)
    if str(exsisting_user.role_id) != role_update.role_id:
        raise InvalidOperationException("User does not have this role assigned")
    
    user = await user_service.update_user(user_id=user_id, user_data=UpdateUserDto(role_id=None))
    user_doc = await user.to_serializable_dict()
    return UserDto(**user_doc)
