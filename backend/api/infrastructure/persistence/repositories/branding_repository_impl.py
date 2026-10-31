from api.common.base_repository import BaseRepository
from api.common.utils import get_logger, get_utc_now
from api.domain.entities.branding import Branding, ThemeConfig

logger = get_logger(__name__)

class BrandingRepository(BaseRepository[Branding]):
    def __init__(self):
        super().__init__(Branding)
    
    async def default_theme_config(self) -> ThemeConfig:
        return ThemeConfig()

    async def get_branding(self) -> Branding | None:
        return await super().single_or_none()
    
    async def update_branding(self, id: str, data: Branding) -> Branding | None:
        data.updated_at = get_utc_now()
        # BaseRepository.update() returns None when no document matches,
        # so return it instead of discarding it: callers otherwise
        # cannot tell a successful update from an unknown id.
        return await super().update(id, data.model_dump(exclude_unset=True, exclude_none=True))

    async def create_branding(self, data: Branding) -> Branding:
        # Do not log the full payload: Branding carries contact_info (PII)
        # and the api logger runs at DEBUG in all environments, so log
        # only the tenant it belongs to, as with the other log trims.
        logger.debug(f"Creating branding for tenant: {data.tenant_id}")
        try:
            return await super().create(data.model_dump())
        except Exception as e:
            logger.error(f"Error creating branding: {e}")
            raise e
