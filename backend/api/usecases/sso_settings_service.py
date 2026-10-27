from typing import List
from typing_extensions import get_args
from api.common.exceptions import NotFoundException
from api.common.utils import get_logger, get_sso_redirect_uri
from api.domain.dtos.sso_settings_dto import CreateSSOSettingsDto, ReadSSOSettingsDto, SSOSettingsListDto, UpdateSSOSettingsDto
from api.domain.entities.sso_settings import SSOProvider, SSOSettings
from api.infrastructure.persistence.repositories.sso_settings_provider_respository_impl import SSOSettingsProviderRepository
from api.usecases.tenant_service import TenantService

logger = get_logger(__name__)

class SSOSettingsService:
    def __init__(self, sso_settings_provider_repository: SSOSettingsProviderRepository, tenant_service: TenantService):
        self.sso_settings_provider_repository: SSOSettingsProviderRepository = sso_settings_provider_repository
        self.tenant_service: TenantService = tenant_service

    async def get_sso_settings_by_id(self, id: str) -> ReadSSOSettingsDto:
        res = await self.sso_settings_provider_repository.get_by_id(id)
        if res is None:
            # BaseRepository.get returns None for a malformed id (iteration 328)
            # instead of raising, so dereferencing res here would raise
            # AttributeError and surface as a 500 for a tampered SSO id —
            # or for a well-formed but unknown id, which previously also
            # reached this line. Map both to the clean 404 instead.
            raise NotFoundException("SSOSettings", id)
        return ReadSSOSettingsDto(**res.model_dump(exclude={"client_secret": True}))

    async def update_redirect_uri(self, id: str, redirect_uri: str) -> None:
        # Same silent-success class as update_sso_settings() above:
        # repository.update() returns None when no document matches, so
        # updating an unknown id previously returned as if it had
        # succeeded. Surface the mapped 404 instead, matching
        # get_sso_settings_by_id() in this file. (No live caller today;
        # this restores the method's contract for any future caller.)
        updated = await self.sso_settings_provider_repository.update_sso_settings(id, SSOSettings(redirect_uris=[redirect_uri]))
        if updated is None:
            raise NotFoundException("SSOSettings", id)

    async def update_sso_settings(self, id: str, sso_settings: UpdateSSOSettingsDto) -> None:
        # Repository.update() returns None when no document matches (and
        # BaseRepository.get returns None for a malformed id), so an
        # update of an unknown SSO settings id previously returned 204
        # as if it had succeeded — the silent-success class fixed for
        # tenant delete in iteration 364. Surface the mapped 404 instead,
        # matching get_sso_settings_by_id() in this file.
        updated = await self.sso_settings_provider_repository.update_sso_settings(id, SSOSettings(**sso_settings.model_dump(exclude_none=True, exclude_unset=True)))
        if updated is None:
            raise NotFoundException("SSOSettings", id)

    async def create_sso_settings(self, sso_settings: CreateSSOSettingsDto) -> str:
        redirect_uri = get_sso_redirect_uri(sso_settings.provider)
        if sso_settings.tenant_id:
            tenant = await self.tenant_service.get_tenant_by_id(tenant_id=sso_settings.tenant_id)
            redirect_uri = get_sso_redirect_uri(sso_settings.provider, tenant.custom_domain if tenant.custom_domain else tenant.subdomain)

        sso_settings.redirect_uris = [redirect_uri]    
        res = await self.sso_settings_provider_repository.create_sso_settings(SSOSettings(**sso_settings.model_dump()))
        return str(res)
    
    async def delete_sso_settings(self, id: str) -> bool:
        return await self.sso_settings_provider_repository.delete_sso_settings(id)
    
    async def list(self) -> SSOSettingsListDto:
        ssos: List[SSOSettings] = await self.sso_settings_provider_repository.list_sso_settings()
        logger.info(f"Retrieved {len(ssos)} SSO settings from repository")
        # Do not log the full SSOSettings list: it carries client_secret
        # (the API response deliberately excludes it, see below), so log
        # provider names only.
        logger.debug(f"SSO Settings providers: {[s.provider for s in ssos]}")
        items = [ReadSSOSettingsDto(**sso.model_dump(exclude={"client_secret": True})) for sso in ssos]
        return SSOSettingsListDto(items=items)
    
    async def get_provider(self, provider_name: SSOProvider) -> SSOSettings:
        ssos: List[SSOSettings] = await self.sso_settings_provider_repository.list_sso_settings()
        for sso in ssos:
            if sso.provider == provider_name:
                return sso
        # ValueError is not an ApiBaseException, so it escaped the central
        # handler as a raw 500 when a user clicked an SSO provider that
        # has no settings row; NotFoundException (already imported) maps
        # to 404 via the handler, matching get_sso_settings_by_id above.
        raise NotFoundException("SSOSettings", provider_name)
    
    async def get_only_enabled_providers(self) -> SSOSettingsListDto:
        ssos: List[SSOSettings] = await self.sso_settings_provider_repository.list_sso_settings()
        enabled_ssos = [sso for sso in ssos if sso.enabled]
        items = [ReadSSOSettingsDto(**sso.model_dump(exclude={"client_secret": True})) for sso in enabled_ssos]
        return SSOSettingsListDto(items=items)
    
    async def get_available_sso_providers(self) -> List[str]:
        return list(get_args(SSOProvider))