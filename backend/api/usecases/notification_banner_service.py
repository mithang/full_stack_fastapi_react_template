from typing import Optional

from beanie import PydanticObjectId
from api.common.exceptions import NotFoundException
from api.domain.dtos.notification_settings_dto import NotificationBannerSettingDto
from api.infrastructure.persistence.repositories.notification_banner_repository_impl import NotificationBannerRepository


def _caller_may_access(record_tenant_id: PydanticObjectId | None, caller_tenant_id: str | PydanticObjectId | None) -> bool:
    # Single-record scope rule, mirroring the SSO settings service:
    # host callers (tenant_id None) may access any record; a tenant
    # caller may access only records stamped with their own tenant_id.
    # A malformed caller id cannot match any record, so it fails closed.
    if caller_tenant_id is None:
        return True
    try:
        caller_oid = PydanticObjectId(caller_tenant_id)
    except Exception:
        return False
    return record_tenant_id == caller_oid


class NotificationBannerService:
    def __init__(self, repository: NotificationBannerRepository):
        self.repository: NotificationBannerRepository = repository

    async def get_banner_setting(self) -> NotificationBannerSettingDto:
        result = await self.repository.get_banner_setting()
        if result:
            return NotificationBannerSettingDto(**result.model_dump())
        return NotificationBannerSettingDto(is_enabled=False, message=None)

    async def create_banner_setting(self, is_enabled: bool, message: Optional[str] = None, tenant_id: Optional[PydanticObjectId] = None):
        await self.repository.create_banner_setting(is_enabled, message, tenant_id)

    async def update_banner_setting(self, id: str, is_enabled: bool, message: Optional[str] = None, tenant_id: str | PydanticObjectId | None = None):
        # Scope to the caller's tenant, mirroring the SSO single-record
        # scoping: the PUT endpoint is FULL_ACCESS-gated with no tenant
        # check, so a tenant caller without a tenant DB selected (no
        # X-Tenant-ID/subdomain, hitting the host DB) could otherwise
        # overwrite the host banner — or any banner id they guessed —
        # since the repository updates by id alone. Host callers
        # (tenant_id None) keep the global view; a host-stamped record
        # (tenant_id None) is not visible to a tenant caller, matching
        # the create path which stamps each banner with its creator's
        # tenant_id. A cross-tenant id raises the same 404 as an
        # unknown id, so a probe cannot distinguish the two, and the
        # check runs before any write. When the record does not exist
        # the repository's own NotFound (with its audit log) applies,
        # unchanged.
        existing = await self.repository.get(id)
        if existing is not None and not _caller_may_access(existing.tenant_id, tenant_id):
            raise NotFoundException("NotificationBannerSetting", id)
        await self.repository.update_banner_setting(id, is_enabled, message)
        
