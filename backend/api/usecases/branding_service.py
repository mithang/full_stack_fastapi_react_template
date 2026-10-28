from beanie import PydanticObjectId
from api.common.utils import get_logger
from api.core.exceptions import BrandingException
from api.domain.dtos.branding_dto import BrandingDto, UpdateBrandingDto
from api.domain.entities.branding import Branding, ThemeConfig
from api.infrastructure.persistence.repositories.branding_repository_impl import BrandingRepository
from api.usecases.file_service import FileService

logger = get_logger(__name__)


def _caller_may_access(record_tenant_id: PydanticObjectId | None, caller_tenant_id: str | PydanticObjectId | None) -> bool:
    # Single-record scope rule, mirroring the notification-banner
    # service: host callers (tenant_id None) may access any record; a
    # tenant caller may access only records stamped with their own
    # tenant_id. A malformed caller id cannot match any record, so it
    # fails closed.
    if caller_tenant_id is None:
        return True
    try:
        caller_oid = PydanticObjectId(caller_tenant_id)
    except Exception:
        return False
    return record_tenant_id == caller_oid


class BrandingService:
    def __init__(self, branding_repository: BrandingRepository, file_service: FileService):
        self.branding_repository = branding_repository
        self.file_service = file_service
    
    async def default_theme_config(self) -> ThemeConfig:
        config = await self.branding_repository.default_theme_config()
        return config

    async def get_branding(self) -> BrandingDto | None:
        res = await self.branding_repository.get_branding()
        # Log presence only: the api logger runs at DEBUG in all
        # environments (iteration 432), and the full document carries
        # contact_info PII.
        logger.debug(f"Fetched branding: {'found' if res is not None else 'not found'}")
        if res is None:
            return None
        branding =  BrandingDto(**res.model_dump())
        if branding.logo_url:
            branding.logo_url = await self.file_service.get_file_url(file_key=branding.logo_url)
        return branding
    
    async def update_branding(self, id: str, data: UpdateBrandingDto, tenant_id: str | PydanticObjectId | None = None, request_tenant_id: str | PydanticObjectId | None = None) -> None:
        # Scope to the caller's tenant, mirroring the banner PUT fix:
        # the branding routes are FULL_ACCESS-gated with no tenant
        # check, and branding is a singleton in the current DB, so a
        # tenant caller without a tenant DB selected (no X-Tenant-ID /
        # subdomain, hitting the host DB) could otherwise overwrite
        # the host branding — or, via another tenant's X-Tenant-ID,
        # that tenant's branding — since the repository updates by id
        # alone. Host callers (tenant_id None) keep the global view; a
        # host-stamped record (tenant_id None) is not visible to a
        # tenant caller, matching the POST create path which stamps
        # each branding with its creator's tenant_id (and the logo
        # create path, stamped in the same change). A cross-tenant id
        # raises the same "Branding not found." as an unknown id, so a
        # probe cannot distinguish the two, and the check runs before
        # any write. The stamp is read straight from the repository
        # document, not via get_branding(), which would also resolve
        # the logo URL through the file service for no benefit here.
        existing = await self.branding_repository.get_branding()
        # Legacy-claim case: a branding created via the old logo path
        # was stamped tenant_id None, so the scope check below refuses
        # its tenant caller any update — while create refuses a second
        # record, leaving the tenant permanently locked out of editing
        # their own branding. A None-stamped singleton is only claimed
        # when the request was actually routed to the caller's own
        # tenant DB (request scope equals caller tenant): on the host
        # DB the same None stamp is the host branding and stays
        # blocked for tenant callers, and a mismatched request scope
        # (e.g. another tenant's X-Tenant-ID) stays blocked too. The
        # claim restamps the record with the caller's tenant, so the
        # deadlock heals on the first update instead of persisting.
        claim_legacy = (
            existing is not None
            and existing.tenant_id is None
            and tenant_id is not None
            and request_tenant_id is not None
            and str(request_tenant_id) == str(tenant_id)
        )
        if existing is not None and not claim_legacy and not _caller_may_access(existing.tenant_id, tenant_id):
            raise BrandingException("Branding not found.")
        try:
            # Log the id only: the full DTO carries contact_info PII.
            logger.debug(f"Updating branding with ID {id}")
            payload = data.model_dump(exclude_unset=True, exclude_none=True)
            if claim_legacy:
                payload["tenant_id"] = tenant_id
            elif existing is not None:
                # Pin the stamp: UpdateBrandingDto carries a tenant_id
                # field and the payload above is its exclude_unset dump,
                # so a client-supplied tenant_id otherwise reaches the
                # repository verbatim — and the scope check above only
                # verifies the EXISTING record is accessible to the
                # caller. The POST / route (which doubles as update
                # when a branding already exists) passes the client DTO
                # straight through, unlike PATCH which pins
                # data.tenant_id to the caller, so a tenant caller
                # updating their own branding could re-stamp it to
                # another tenant's id (or to None, making it
                # host-visible). Overwrite with the existing stamp in
                # all non-claim cases: a caller-stamped update writes
                # the same stamp back (a no-op), a host update of a
                # host record writes None which the repository's
                # exclude_none dump drops, and a foreign stamp is
                # discarded. Mirrors the role-update pin from
                # iteration 871.
                payload["tenant_id"] = existing.tenant_id
            # identity is optional on UpdateBrandingDto: PUT /logo (and
            # a PATCH without an identity block) pass no identity, so
            # reading data.identity.app_name unconditionally raised
            # AttributeError and every such update surfaced as
            # "Failed to update branding." Only override app_name when
            # an identity was actually supplied; otherwise the
            # repository's exclude_unset dump leaves the stored
            # app_name untouched (Branding's default is not in
            # fields_set, so it is excluded too).
            branding_kwargs = {}
            if data.identity is not None:
                branding_kwargs["app_name"] = data.identity.app_name
            updated = await self.branding_repository.update_branding(id, Branding(**payload, **branding_kwargs))
        except Exception as e:
            # Log the detail server-side only: the ApiBaseException
            # handler returns the message verbatim, so str(e) here would
            # leak repository internals to the client (same class as
            # iterations 467-471 for tenant/product/plan/invoice/price).
            logger.error(f"Failed to update branding {id}: {e}")
            raise BrandingException("Failed to update branding.")
        # The not-found check sits outside the try on purpose: raising
        # inside it would be re-wrapped by the except above and double
        # the "Branding Error:" prefix. A None return means no branding
        # matched the id, so fail instead of silently succeeding — the
        # same silent-success class fixed for SSO settings in
        # iterations 365-366. The PATCH endpoint's id-match guard
        # (iteration 367) already covers its own route; this restores
        # the contract for every caller, including the POST / and logo
        # routes that pass the singleton id they just fetched.
        if updated is None:
            raise BrandingException("Branding not found.")
        
    async def create_branding(self, data: UpdateBrandingDto) -> BrandingDto:
        if await self.branding_repository.count() > 0:
            raise BrandingException("Branding already exists. Only one branding allowed.")

        # identity is optional on UpdateBrandingDto: PUT /logo's
        # logo-first creation (and a POST without an identity block)
        # pass no identity, so reading data.identity.app_name
        # unconditionally raised AttributeError and every such
        # creation failed — the same crash class fixed for updates
        # in iteration 875. Only override app_name when an identity
        # was actually supplied; otherwise Branding's own default
        # ("SaaS Org") applies, and a later PATCH/POST with an
        # identity block can still set it.
        branding_kwargs = {}
        if data.identity is not None:
            branding_kwargs["app_name"] = data.identity.app_name
        branding_data = Branding(**data.model_dump(), **branding_kwargs)
        
        created_branding = await self.branding_repository.create_branding(data=branding_data)
        # Log the tenant id only: the full document carries contact_info PII.
        logger.debug(f"Created default branding for tenant {created_branding.tenant_id}")
        return BrandingDto(**created_branding.model_dump())