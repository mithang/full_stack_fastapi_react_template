from typing import List
from fastapi import APIRouter, Depends, Response, status
from api.common.utils import get_logger
from api.common.exceptions import ForbiddenException
from api.core.container import get_sso_settings_service
from api.domain.dtos.sso_settings_dto import CreateSSOSettingsDto, ReadSSOSettingsDto, SSOSettingsListDto, SSOSettingsResponseDto, UpdateSSOSettingsDto
from api.domain.enum.permission import Permission
from api.infrastructure.security.current_user import CurrentUser
from api.interfaces.middlewares.tenant_middleware import get_tenant_id
from api.interfaces.security.role_checker import check_permissions_for_current_role
from api.usecases.sso_settings_service import SSOSettingsService


logger = get_logger(__name__)

router = APIRouter(prefix="/ssos", tags=["SSO Settings"], dependencies=[Depends(check_permissions_for_current_role(required_permissions=[Permission.FULL_ACCESS]))])


def _assert_create_scope(current_user: CurrentUser, request_tenant_id) -> None:
    # Create-in-wrong-DB guard, mirroring the branding singleton guard
    # (iteration 867): SSO login resolves a provider by first match in
    # the current DB (sso_settings_service.get_provider, no tenant
    # filter), so a tenant caller creating on the host DB (no
    # X-Tenant-ID/subdomain, request scope None) would plant an SSO
    # configuration — attacker-chosen client id/secret and redirect
    # URI — that host SSO logins could then pick up for that provider
    # if the host has no setting for it yet. Legitimate tenant SSO
    # creation happens in the caller's own tenant DB, where the
    # middleware scope equals their tenant id, and host callers
    # (tenant_id None) are unaffected. A mismatched scope fails closed
    # rather than stamping a record into the wrong DB.
    if current_user.tenant_id is not None and (
        request_tenant_id is None or str(request_tenant_id) != str(current_user.tenant_id)
    ):
        raise ForbiddenException("SSO settings cannot be created outside your tenant's scope.")


def _assert_read_scope(current_user: CurrentUser, request_tenant_id) -> None:
    # Read-in-wrong-DB guard, mirroring the create/update guards
    # above and the roles get guard (iteration 929): list() and
    # get_sso_settings_by_id() already scope results to the
    # caller's tenant stamp, but nothing checks which database
    # served the request. So a tenant caller reading on the host
    # DB (no X-Tenant-ID/subdomain, request scope None) could
    # still read tenant-stamped SSO settings sitting in the host
    # DB (e.g. planted before the create guard) — masked client
    # ids, redirect URIs, and scopes. Legitimate tenant SSO reads
    # happen in the caller's own tenant DB, where the middleware
    # scope equals their tenant id, and host callers (tenant_id
    # None) are unaffected. A mismatched scope fails closed
    # before any read, so it also leaks no existence signal via
    # the 404. The static /available-providers catalogue carries
    # no tenant data and is left unguarded.
    if current_user.tenant_id is not None and (
        request_tenant_id is None or str(request_tenant_id) != str(current_user.tenant_id)
    ):
        raise ForbiddenException("SSO settings cannot be read outside your tenant's scope.")


def _assert_update_scope(current_user: CurrentUser, request_tenant_id) -> None:
    # Update/delete-in-wrong-DB guard, mirroring the create guard
    # above and the notification-banner update guard (iteration
    # 902): the service already refuses a record stamped for
    # another tenant, but it does not check which database served
    # the request — and SSO login resolves a provider by first
    # match in the current DB with no tenant filter. So a tenant
    # caller updating/deleting on the host DB (no
    # X-Tenant-ID/subdomain, request scope None) could still
    # overwrite or delete a tenant-stamped SSO configuration
    # sitting in the host DB (e.g. planted before the create
    # guard), and host SSO logins could then pick up the edited
    # credentials or lose the provider. Legitimate tenant SSO
    # edits happen in the caller's own tenant DB, where the
    # middleware scope equals their tenant id, and host callers
    # (tenant_id None) are unaffected. A mismatched scope fails
    # closed before any write, rather than editing a record in
    # the wrong DB.
    if current_user.tenant_id is not None and (
        request_tenant_id is None or str(request_tenant_id) != str(current_user.tenant_id)
    ):
        raise ForbiddenException("SSO settings cannot be modified outside your tenant's scope.")

@router.get("/", response_model=SSOSettingsListDto, response_model_exclude_none=True)
async def list(
    response: Response,
    current_user: CurrentUser,
    sso_settings_service: SSOSettingsService = Depends(get_sso_settings_service),
    request_tenant_id = Depends(get_tenant_id)
):
    _assert_read_scope(current_user, request_tenant_id)
    # SSO configuration (masked client secrets included): a
    # browser/proxy-cached 200 could serve one tenant's SSO settings
    # to another admin after an account switch, or hide freshly
    # updated settings — same class as the /invoices fix in the
    # previous iteration.
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    # Scope to the caller's tenant: settings are stamped with the
    # creator's tenant_id on create, but this list previously returned
    # every tenant's SSO configuration to any FULL_ACCESS admin calling
    # without a tenant DB selected (no X-Tenant-ID/subdomain) — masked
    # client ids, redirect URIs and scopes of other tenants. Host
    # callers (tenant_id None) keep the global view.
    return await sso_settings_service.list(tenant_id=current_user.tenant_id)

@router.get("/available-providers", response_model=List)
async def get_available_sso_providers(
    response: Response,
    sso_settings_service: SSOSettingsService = Depends(get_sso_settings_service)
):
    # Static provider catalogue, but completing the no-store
    # coverage of this file: a browser/proxy-cached 200 could
    # otherwise hide a newly added provider from the SSO
    # configuration UI after a deploy, unlike the list/detail
    # endpoints above which already send no-store.
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return await sso_settings_service.get_available_sso_providers()

@router.get("/{sso_id}", response_model=ReadSSOSettingsDto, response_model_exclude_none=True)
async def get_sso_settings_by_id(
    response: Response,
    sso_id: str,
    current_user: CurrentUser,
    sso_settings_service: SSOSettingsService = Depends(get_sso_settings_service),
    request_tenant_id = Depends(get_tenant_id)
):
    _assert_read_scope(current_user, request_tenant_id)
    # Single SSO record, same sensitivity as the list endpoint
    # above: a browser/proxy-cached 200 could serve one tenant's
    # SSO settings to another admin after an account switch, or
    # hide freshly updated settings.
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    # Tenant-scoped like the list: a tenant caller reading another
    # tenant's id gets the same 404 as an unknown id.
    return await sso_settings_service.get_sso_settings_by_id(sso_id, tenant_id=current_user.tenant_id)

@router.post("/", response_model=SSOSettingsResponseDto, status_code=status.HTTP_201_CREATED)
async def create_sso_settings(
    current_user: CurrentUser,
    sso_settings: CreateSSOSettingsDto,
    sso_settings_service: SSOSettingsService = Depends(get_sso_settings_service),
    request_tenant_id = Depends(get_tenant_id)
):
    _assert_create_scope(current_user, request_tenant_id)
    sso_settings.tenant_id = current_user.tenant_id if current_user.tenant_id else None
    await sso_settings_service.create_sso_settings(sso_settings)
    return SSOSettingsResponseDto(message="SSO settings created successfully")

@router.delete("/{sso_id}", response_model=bool)
async def delete_sso_settings(
    sso_id: str,
    current_user: CurrentUser,
    sso_settings_service: SSOSettingsService = Depends(get_sso_settings_service),
    request_tenant_id = Depends(get_tenant_id)
):
    _assert_update_scope(current_user, request_tenant_id)
    return await sso_settings_service.delete_sso_settings(sso_id, tenant_id=current_user.tenant_id)


@router.patch("/{sso_id}", response_model=None, status_code=status.HTTP_204_NO_CONTENT)
async def update_sso_settings(
    sso_id: str,
    sso_settings: UpdateSSOSettingsDto,
    current_user: CurrentUser,
    sso_settings_service: SSOSettingsService = Depends(get_sso_settings_service),
    request_tenant_id = Depends(get_tenant_id)
):
    _assert_update_scope(current_user, request_tenant_id)
    await sso_settings_service.update_sso_settings(sso_id, sso_settings, tenant_id=current_user.tenant_id)
    return None
