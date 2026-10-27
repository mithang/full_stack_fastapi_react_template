from api.common.utils import get_logger
from api.core.exceptions import BrandingException
from api.domain.dtos.branding_dto import BrandingDto, UpdateBrandingDto
from api.domain.entities.branding import Branding, ThemeConfig
from api.infrastructure.persistence.repositories.branding_repository_impl import BrandingRepository
from api.usecases.file_service import FileService

logger = get_logger(__name__)

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
    
    async def update_branding(self, id: str, data: UpdateBrandingDto) -> None:
        try:
            # Log the id only: the full DTO carries contact_info PII.
            logger.debug(f"Updating branding with ID {id}")
            updated = await self.branding_repository.update_branding(id, Branding(**data.model_dump(exclude_unset=True, exclude_none=True), app_name=data.identity.app_name))
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
        
        branding_data = Branding(**data.model_dump(), app_name=data.identity.app_name)
        
        created_branding = await self.branding_repository.create_branding(data=branding_data)
        # Log the tenant id only: the full document carries contact_info PII.
        logger.debug(f"Created default branding for tenant {created_branding.tenant_id}")
        return BrandingDto(**created_branding.model_dump())