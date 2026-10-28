from typing import List
from beanie import PydanticObjectId
from fastapi import APIRouter, Depends, HTTPException, Response, status
from api.common.exceptions import NotFoundException
from api.common.utils import get_logger
from api.core.container import get_storage_settings_service
from api.domain.dtos.storage_settings_dto import AvailableStorageProviderDto, StorageSettingsDto
from api.domain.entities.storage_settings import StorageProvider
from api.domain.enum.permission import Permission
from api.infrastructure.security.current_user import CurrentUser
from api.interfaces.security.role_checker import check_permissions_for_current_role
from api.usecases.storage_settings_service import StorageSettingsService


logger = get_logger(__name__)

router = APIRouter(
    prefix="/storage",
    dependencies=[
        Depends(check_permissions_for_current_role(required_permissions=[Permission.MANAGE_STORAGE_SETTINGS]))
    ]
)
router.tags = ["Storage Settings"]

@router.get("/", response_model=List[AvailableStorageProviderDto], response_model_exclude_none=True)
async def get_storage_settings(
    response: Response,
    setting_service: StorageSettingsService = Depends(get_storage_settings_service)
):
    # Tenant storage configuration (masked secrets included): a
    # browser/proxy-cached 200 could serve one tenant's storage
    # settings to another admin after an account switch, or hide
    # freshly updated settings — same class as the SSO list fix.
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    res = await setting_service.get_storages()
    return [s.model_dump(exclude_none=True) for s in res]

@router.get("/available", response_model=List[dict[str, str]])
async def get_available_providers(response: Response):
    # Static provider catalogue, but completing the no-store
    # coverage of this file: a browser/proxy-cached 200 could
    # otherwise hide a newly added provider from the storage
    # settings UI after a deploy — same class as the
    # /ssos/available-providers fix.
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    providers = [{"name": p.value} for p in StorageProvider]
    return providers

@router.post("/configure", status_code=status.HTTP_201_CREATED)
async def configure_storage(
    configuration: StorageSettingsDto,
    current_user: CurrentUser,
    setting_service: StorageSettingsService = Depends(get_storage_settings_service)
):

    # Log only the provider, not the configuration itself: StorageSettingsDto
    # carries aws_secret_key / aws_access_key / azure_connection_string,
    # and the api logger runs at DEBUG in all environments, so logging the
    # whole DTO would leak live storage credentials into server logs.
    logger.debug(f"Received storage configuration for provider: {configuration.provider} (enabled: {configuration.is_enabled})")
    try:
        # We don't expect storage settings to be configured with host context as they are global settings. Only tenants with proper permissions can configure them.
        if current_user.tenant_id is None or current_user.tenant_id.strip() == "":
            logger.error("Tenant ID is missing in the current user context.")
            # Raise, don't return the status code as the body: returning
            # status.HTTP_400_BAD_REQUEST only sets the response body to
            # 400 while the declared 201 status still goes out, so the
            # generated client (which throws only on non-2xx) treated a
            # failed configuration as success and settings-provider
            # toasted "updated successfully" for a save that never
            # happened. A real 400 makes the client throw instead.
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Tenant ID is missing in the current user context.")
        
        configuration.updated_by_user_id = current_user.id
        await setting_service.configure_storage(setting=configuration, tenant_id=current_user.tenant_id)
        return status.HTTP_201_CREATED
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to configure storage: {e}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Failed to configure storage.")



@router.patch("/{storage_id}/reset", status_code=status.HTTP_204_NO_CONTENT)
async def reset_storage(
    storage_id: str,
    current_user: CurrentUser,
    setting_service: StorageSettingsService = Depends(get_storage_settings_service)
):
    logger.debug(f"Received request to reset storage settings for ID: {storage_id}")

    try:
        # We don't expect storage settings to be configured with host context as they are global settings. Only tenants with proper permissions can configure them.
        if current_user.tenant_id is None or current_user.tenant_id.strip() == "":
            logger.error("Tenant ID is missing in the current user context.")
            # Raise, don't return the status code as the body: the route
            # declares 204, which cannot carry a body at all, so the
            # returned 400 was discarded and the client saw a successful
            # 204 for a reset that never happened (same shape as the
            # configure_storage fix). A real 400 makes the client throw.
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Tenant ID is missing in the current user context.")

        await setting_service.reset_storage(storage_id=storage_id, updated_by_user_id=current_user.id, tenant_id=PydanticObjectId(current_user.tenant_id))
        # The route declares 204 No Content, so return that code: the
        # previous 201 return value mismatched the decorator (the only
        # such mismatch in the controllers) and was misleading to
        # readers, even though the wire status was already 204.
        return status.HTTP_204_NO_CONTENT
    except HTTPException:
        raise
    except (NotFoundException, Exception) as e:
        logger.error(f"Failed to reset storage settings: {e}")
        raise e
