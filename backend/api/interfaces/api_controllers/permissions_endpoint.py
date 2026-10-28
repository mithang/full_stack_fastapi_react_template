
from fastapi import APIRouter, Response

from api.common.utils import get_logger
from api.domain.dtos.permission_dto import PermissionDto
from api.domain.enum.permission import Permission
from api.infrastructure.security.current_user import CurrentUser

logger = get_logger(__name__)

router = APIRouter(prefix="/permissions")
router.tags = ["Permissions"]


@router.get("/", response_model=list[PermissionDto])
async def get_permissions(
    response: Response,
    current_user: CurrentUser
):
    # The list is scope-dependent (host-level permissions are filtered
    # out for tenant users), so it must not be served from a browser
    # or proxy cache: a cached 200 could show a host user's full list
    # to a tenant user after an account switch on a shared machine —
    # the same no-store hardening as the billing plan list GET.
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    permissions = [{"name": perm.value} for perm in Permission]
    if current_user.tenant_id:
        logger.debug("Filtering out host-level permissions for tenant user")
        permissions = filter(
            lambda p: not p["name"].startswith("host:"),
            permissions
        )
        permissions = list(permissions)

    return permissions
