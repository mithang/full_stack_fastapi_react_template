from typing import List
from beanie import PydanticObjectId
from typing_extensions import get_args
from api.common.exceptions import NotFoundException
from api.common.utils import get_logger, get_sso_redirect_uri
from api.domain.dtos.sso_settings_dto import CreateSSOSettingsDto, ReadSSOSettingsDto, SSOSettingsListDto, UpdateSSOSettingsDto
from api.domain.entities.sso_settings import SSOProvider, SSOSettings
from api.infrastructure.persistence.repositories.sso_settings_provider_respository_impl import SSOSettingsProviderRepository
from api.usecases.tenant_service import TenantService

logger = get_logger(__name__)


def _caller_may_access(record_tenant_id: PydanticObjectId | None, caller_tenant_id: str | PydanticObjectId | None) -> bool:
    # Single-record scope rule, mirroring list(): host callers
    # (tenant_id None) may access any record; a tenant caller may
    # access only records stamped with their own tenant_id. A
    # malformed caller id cannot match any record, so it fails closed.
    if caller_tenant_id is None:
        return True
    try:
        caller_oid = PydanticObjectId(caller_tenant_id)
    except Exception:
        return False
    return record_tenant_id == caller_oid


class SSOSettingsService:
    def __init__(self, sso_settings_provider_repository: SSOSettingsProviderRepository, tenant_service: TenantService):
        self.sso_settings_provider_repository: SSOSettingsProviderRepository = sso_settings_provider_repository
        self.tenant_service: TenantService = tenant_service

    async def get_sso_settings_by_id(self, id: str, tenant_id: str | PydanticObjectId | None = None) -> ReadSSOSettingsDto:
        res = await self.sso_settings_provider_repository.get_by_id(id)
        if res is None:
            # BaseRepository.get returns None for a malformed id (iteration 328)
            # instead of raising, so dereferencing res here would raise
            # AttributeError and surface as a 500 for a tampered SSO id —
            # or for a well-formed but unknown id, which previously also
            # reached this line. Map both to the clean 404 instead.
            raise NotFoundException("SSOSettings", id)
        if not _caller_may_access(res.tenant_id, tenant_id):
            # Cross-tenant read: same 404 as an unknown id, so probing
            # another tenant's id reveals neither its existence nor its
            # masked client id / redirect URIs. Host callers
            # (tenant_id None) keep the global view, the same scope
            # rule as list() — and a host-stamped record (tenant_id
            # None) is not visible to a tenant caller, matching the
            # list filter which only returns the caller's own rows.
            raise NotFoundException("SSOSettings", id)
        return ReadSSOSettingsDto(**res.model_dump(exclude={"client_secret": True}))

    async def update_redirect_uri(self, id: str, redirect_uri: str) -> None:
        # Same silent-success class as update_sso_settings() above:
        # repository.update() returns None when no document matches, so
        # updating an unknown id previously returned as if it had
        # succeeded. Surface the mapped 404 instead, matching
        # get_sso_settings_by_id() in this file. (No live caller today;
        # this restores the method's contract for any future caller.)
        # Strip before persisting, mirroring the SSO DTO normalizer for
        # client_id/client_secret/scopes: OAuth providers match a
        # redirect URI exactly, so a pasted URI with surrounding
        # whitespace would otherwise persist verbatim and only fail
        # later at provider login time with a generic OAuth error.
        # A URI cannot legitimately carry surrounding whitespace.
        updated = await self.sso_settings_provider_repository.update_sso_settings(id, SSOSettings(redirect_uris=[redirect_uri.strip()]))
        if updated is None:
            raise NotFoundException("SSOSettings", id)

    async def update_sso_settings(self, id: str, sso_settings: UpdateSSOSettingsDto, tenant_id: str | PydanticObjectId | None = None) -> None:
        # Repository.update() returns None when no document matches (and
        # BaseRepository.get returns None for a malformed id), so an
        # update of an unknown SSO settings id previously returned 204
        # as if it had succeeded — the silent-success class fixed for
        # tenant delete in iteration 364. Surface the mapped 404 instead,
        # matching get_sso_settings_by_id() in this file.
        # Masked-credential round-trip: GET serializes client_id (and
        # client_secret, where present) as first-2 + stars + last-2, and
        # the SSO edit form pre-fills from that response, so a save
        # that changes only e.g. enabled/scopes resubmits the masked
        # value. Treat a submission exactly equal to the stored
        # value's masked form as "unchanged" (dropped via exclude_none
        # below) instead of overwriting the live credential with the
        # masked string, which would silently break SSO login. A
        # genuinely new credential differs from its own masked form.
        existing = await self.sso_settings_provider_repository.get_by_id(id)
        if existing is not None and not _caller_may_access(existing.tenant_id, tenant_id):
            # Cross-tenant write: same 404 as an unknown id (and raised
            # before any write), so probing another tenant's id reveals
            # nothing and cannot overwrite its live credentials.
            raise NotFoundException("SSOSettings", id)
        if existing is not None:
            for field in ("client_id", "client_secret"):
                submitted = getattr(sso_settings, field)
                stored = getattr(existing, field)
                if submitted is not None and stored is not None:
                    masked = ("*" * len(stored)) if len(stored) <= 4 else stored[:2] + "*" * (len(stored) - 4) + stored[-2:]
                    if submitted == masked:
                        setattr(sso_settings, field, None)
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
    
    async def delete_sso_settings(self, id: str, tenant_id: str | PydanticObjectId | None = None) -> bool:
        # Cross-tenant delete must be indistinguishable from deleting an
        # unknown id: BaseRepository.delete returns False for unknown
        # ids, so return False here too (without deleting) rather than
        # a 404, which would confirm the record exists to the prober.
        existing = await self.sso_settings_provider_repository.get_by_id(id)
        if existing is None or not _caller_may_access(existing.tenant_id, tenant_id):
            return False
        return await self.sso_settings_provider_repository.delete_sso_settings(id)
    
    async def list(self, tenant_id: str | None = None) -> SSOSettingsListDto:
        # Tenant callers see only their tenant's SSO settings; host
        # callers (tenant_id None) keep the global view, the same scope
        # rule as the GET /users/ list. A malformed tenant id cannot
        # match any record, so fail closed with an empty list rather
        # than falling back to the unscoped list. The login flows
        # (get_provider / get_only_enabled_providers) do not pass a
        # tenant and keep their global provider resolution.
        tenant_oid = None
        if tenant_id:
            try:
                tenant_oid = PydanticObjectId(tenant_id)
            except Exception:
                return SSOSettingsListDto(items=[])
        ssos: List[SSOSettings] = await self.sso_settings_provider_repository.list_sso_settings(tenant_id=tenant_oid)
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
