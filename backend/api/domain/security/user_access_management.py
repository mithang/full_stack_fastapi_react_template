from typing import List
from fastapi import Request
from api.common.exceptions import ForbiddenException
from api.common.utils import get_logger, is_tenancy_enabled
from api.core.container import get_role_service
from api.domain.dtos.user_dto import UserDto
from api.domain.enum.permission import Permission
from api.infrastructure.security.current_user import CurrentUser

logger = get_logger(__name__)


def _safe_log_value(value) -> str:
    """Flatten CR/LF in a logged value so it cannot forge extra log lines."""
    return str(value).replace("\r", " ").replace("\n", " ") if value is not None else "None"


class UserAccessManagement:
    def __init__(self,
        required_permissions: List[Permission],
        any_permission: bool = True,
        allow_self_access: bool = True
    ):
        """
        Initialize user access management
        
        Args:
            required_permissions: List of permissions required to access the resource
            any_permission: If True, user needs ANY of the permissions. If False, user needs ALL permissions
            allow_self_access: If True, allows self-access with USER_SELF_READ_AND_WRITE_ONLY permission
        """
        self.required_permissions = required_permissions
        self.any_permission = any_permission
        self.allow_self_access = allow_self_access

    async def get_role_detail(self, role_id: str):
    
        role_service = get_role_service()
        role = await role_service.get_role_by_id(role_id=role_id)
        return role

    async def check_self_access(self, current_user: UserDto, resource_id: str = None) -> bool:
        """Check if user is accessing their own resource"""
        if not resource_id or not self.allow_self_access:
            return False
        return str(current_user.id) == str(resource_id)
    
    async def has_permission(self, user_permissions: List[Permission], required_permissions: List[Permission]) -> bool:
        """Check if user has required permissions"""
        if self.any_permission:
            # User needs ANY of the required permissions
            return any(perm in user_permissions for perm in required_permissions)
        else:
            # User needs ALL of the required permissions
            return all(perm in user_permissions for perm in required_permissions)
    
    def __call__(self):

        async def check_permission(current_user: CurrentUser, request: Request) -> bool:

            # The resource being accessed is the id in the request path
            # (e.g. /users/{user_id}), NOT the caller's own id: the old
            # code set resource_id = current_user.id, so the self-access
            # check below compared the caller to themselves and was
            # always true — any holder of USER_SELF_READ_AND_WRITE_ONLY
            # passed it for any user's record. Only the user endpoints
            # use allow_self_access, and all of them name the path
            # parameter user_id; routes without one get None here and
            # fail the self-access check, which is fail-closed.
            resource_id = request.path_params.get("user_id")
            logger.info(f"Resource ID for self-access checking: {_safe_log_value(resource_id)}")

            if current_user.role_id is None:
                logger.info("User has no role assigned")
                raise ForbiddenException(f"No role assigned. Required. Please contact support.")
            
            role = await self.get_role_detail(current_user.role_id)
            user_permissions = role.permissions
            
            logger.info(f"User permissions: {[p.value if hasattr(p, 'value') else str(p) for p in user_permissions]}")
            logger.info(f"Required permissions: {[p.value if hasattr(p, 'value') else str(p) for p in self.required_permissions]}")

            if is_tenancy_enabled():
                if Permission.HOST_MANAGE_TENANTS in user_permissions:
                    logger.info("Host Permission detected - Granting all permissions")
                    return True


            # Check for full access (admin override)
            if Permission.FULL_ACCESS in user_permissions:
                logger.info("Full access granted - User has admin privileges")
                return True
            
            # Check for self-access permissions
            if (Permission.USER_SELF_READ_AND_WRITE_ONLY in user_permissions and 
                self.allow_self_access and resource_id):
                if await self.check_self_access(current_user, resource_id):
                    logger.info("Self access granted - User accessing own resource")
                    return True
            
            # Check required permissions. USER_SELF_READ_AND_WRITE_ONLY
            # is a self-only permission: it is honoured by the
            # self-access branch above and must not satisfy the general
            # check, or a self-only holder would pass a route whose
            # required list is just that permission (GET /users/{id})
            # for any user's record. The empty-list guard matters when
            # any_permission is False, since all([]) is True.
            general_permissions = self.required_permissions
            if self.allow_self_access:
                general_permissions = [p for p in general_permissions if p != Permission.USER_SELF_READ_AND_WRITE_ONLY]
            if general_permissions and await self.has_permission(user_permissions, general_permissions):
                permission_type = "any" if self.any_permission else "all"
                logger.info(f"Access granted - User has {permission_type} required permissions")
                return True

            # The required-permission list stays server-side only: the
            # ApiBaseException handler returns ex.message verbatim to
            # the client, so listing it here told a denied user exactly
            # which permissions an endpoint requires, aiding RBAC
            # mapping for privilege escalation. The client gets a
            # generic denial; the detail remains in the server log.
            logger.error(f"Access denied - Insufficient permissions. Required: {[p.value if hasattr(p, 'value') else str(p) for p in self.required_permissions]}")
            raise ForbiddenException("Insufficient permissions.")
        
        return check_permission
   
     
