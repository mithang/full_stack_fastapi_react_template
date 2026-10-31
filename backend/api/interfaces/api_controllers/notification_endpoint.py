from fastapi import APIRouter, Depends, Response, status

from api.common.exceptions import ForbiddenException
from api.core.container import get_notification_banner_service
from api.domain.dtos.notification_settings_dto import CreateNotificationBannerSettingDto, NotificationBannerSettingDto
from api.domain.enum.permission import Permission
from api.infrastructure.security.current_user import CurrentUser
from api.interfaces.middlewares.tenant_middleware import get_tenant_id
from api.interfaces.security.role_checker import check_permissions_for_current_role
from api.usecases.notification_banner_service import NotificationBannerService


router = APIRouter(prefix="/notifications")

router.tags = ["Notifications"]


def _assert_create_scope(current_user: CurrentUser, request_tenant_id) -> None:
    # Create-in-wrong-DB guard, mirroring the SSO (iteration 868) and
    # branding (iteration 867) guards: the banner GET serves the first
    # record in the current DB (repository get_banner_setting, no
    # tenant filter), so a tenant caller creating on the host DB (no
    # X-Tenant-ID/subdomain, request scope None) would plant a
    # tenant-stamped record in the host DB that host banner GETs could
    # then serve as the application-wide banner. Legitimate tenant
    # banner creation happens in the caller's own tenant DB, where the
    # middleware scope equals their tenant id, and host callers
    # (tenant_id None) are unaffected. A mismatched scope fails closed
    # rather than stamping a record into the wrong DB.
    if current_user.tenant_id is not None and (
        request_tenant_id is None or str(request_tenant_id) != str(current_user.tenant_id)
    ):
        raise ForbiddenException("Notification banner cannot be created outside your tenant's scope.")


@router.get("/banner", description="Get the current notification banner information.", response_model=NotificationBannerSettingDto, status_code=status.HTTP_200_OK)
async def get_notification_banner(
    response: Response,
    notification_banner_service: NotificationBannerService = Depends(get_notification_banner_service)
):
    # The banner is tenant settings data that admins edit, so it must
    # not be served from a browser or proxy cache: a cached 200 could
    # keep showing a disabled/old banner after an update, or show one
    # tenant's banner to another user after an account switch on a
    # shared machine — the same no-store hardening as the tenant list
    # and Stripe settings GETs.
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return await notification_banner_service.get_banner_setting()

@router.post("/banner", description="Create a new notification banner setting.", response_model=None, status_code=status.HTTP_201_CREATED)
async def create_notification_banner(
    created_banner: CreateNotificationBannerSettingDto,
    current_user: CurrentUser,
    _bool: bool = Depends(check_permissions_for_current_role(required_permissions=[Permission.FULL_ACCESS])),
    notification_banner_service: NotificationBannerService = Depends(get_notification_banner_service),
    request_tenant_id = Depends(get_tenant_id)
):
    _assert_create_scope(current_user, request_tenant_id)
    await notification_banner_service.create_banner_setting(created_banner.is_enabled, created_banner.message, current_user.tenant_id)

def _assert_update_scope(current_user: CurrentUser, request_tenant_id) -> None:
    # Update-in-wrong-DB guard, mirroring the create guard above:
    # the service already refuses a banner stamped for another
    # tenant, but it does not check which database served the
    # request — and the banner GET serves the first record in the
    # current DB with no tenant filter. So a tenant caller updating
    # on the host DB (no X-Tenant-ID/subdomain, request scope None)
    # could still overwrite a tenant-stamped banner record sitting
    # in the host DB (e.g. planted before the create guard), and
    # the host banner GET would then serve the edited message
    # app-wide. Legitimate tenant banner edits happen in the
    # caller's own tenant DB, where the middleware scope equals
    # their tenant id, and host callers (tenant_id None) are
    # unaffected. A mismatched scope fails closed before any write,
    # rather than editing a record in the wrong DB.
    if current_user.tenant_id is not None and (
        request_tenant_id is None or str(request_tenant_id) != str(current_user.tenant_id)
    ):
        raise ForbiddenException("Notification banner cannot be updated outside your tenant's scope.")


@router.put("/banner/{id}", description="Update an existing notification banner setting.", response_model=None, status_code=status.HTTP_204_NO_CONTENT)
async def update_notification_banner(
    id: str,
    updated_banner: CreateNotificationBannerSettingDto,
    current_user: CurrentUser,
    _bool: bool = Depends(check_permissions_for_current_role(required_permissions=[Permission.FULL_ACCESS])),
    notification_banner_service: NotificationBannerService = Depends(get_notification_banner_service),
    request_tenant_id = Depends(get_tenant_id)
):
    _assert_update_scope(current_user, request_tenant_id)
    await notification_banner_service.update_banner_setting(id, updated_banner.is_enabled, updated_banner.message, tenant_id=current_user.tenant_id)
