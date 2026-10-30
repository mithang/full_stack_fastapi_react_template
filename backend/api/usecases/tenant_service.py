from typing import List
from beanie import PydanticObjectId

from api.common.utils import get_logger, get_utc_now, validate_password
from api.core.exceptions import TenantNotFoundException
from api.domain.dtos.tenant_dto import CreateTenantDto, FeatureDto, TenantListDto, UpdateTenantDto
from api.domain.entities.tenant import Feature, Tenant
from api.infrastructure.persistence.repositories.tenant_repository_impl import TenantRepository
from api.domain.enum.feature import Feature as FeatureEnum

logger = get_logger(__name__)


def _safe_log_value(value: object) -> str:
    # The ApiBaseException handler logs ex.message verbatim, so an
    # identifier embedded in a TenantNotFoundException message reaches
    # the log lines unescaped (same shape as the billing plan/product/
    # price fixes in iterations 971-973). Flatten CR/LF so a
    # newline-bearing path-param value cannot forge extra log lines;
    # the raw value still drives the lookup, and normal ids/names
    # render identically.
    return str(value).replace("\r", " ").replace("\n", " ")


class TenantService:
    def __init__(self, tenant_repository: TenantRepository):
        self.tenant_repository = tenant_repository
        logger.info("Initialized.")


    async def list_tenants(self, skip: int = 0, limit: int = 10) -> TenantListDto:
        """List tenants with pagination."""
        return await self.tenant_repository.list(skip=skip, limit=limit)

    async def find_by_name(self, name: str) -> Tenant | None:
        """Get tenant by name. Raises TenantNotFoundException if not found."""
        # Trim before lookup: stored tenant names are always trimmed
        # (CreateTenantDto validator), so a padded name from a direct
        # API client — the frontend search already trims, but a mobile
        # or scripted caller bypasses the form — can never match by its
        # spaces and 404s for a tenant that exists, the same
        # deferred-failure class as the role search trim. A
        # whitespace-only name still finds nothing and raises exactly
        # as before, and clean names are unchanged.
        if isinstance(name, str):
            name = name.strip()
        exisiting = await self.tenant_repository.single_or_none(name=name)
        if exisiting is None:
            raise TenantNotFoundException(_safe_log_value(name))
        return exisiting

    async def find_by_custom_domain(self, custom_domain: str) -> Tenant | None:
        """Get tenant by custom domain. Raises TenantNotFoundException if not found."""
        existing = await self.tenant_repository.single_or_none(custom_domain=custom_domain)
        if existing is None:
            # Same _safe_log_value hardening as find_by_name /
            # get_tenant_by_id above: the ApiBaseException handler logs
            # ex.message verbatim, and the middleware's warning log
            # embeds this exception, so a newline-bearing host would
            # otherwise forge extra log lines. The raw value still
            # drives the lookup; normal domains render identically.
            raise TenantNotFoundException(_safe_log_value(custom_domain))
        return existing

    async def find_by_subdomain(self, subdomain: str) -> Tenant | None:
        """Get tenant by subdomain. Raises TenantNotFoundException if not found."""
        existing = await self.tenant_repository.single_or_none(subdomain=subdomain)
        if existing is None:
            # Same hardening as find_by_custom_domain above: unlike
            # the endpoint's Subdomain-typed path param, the register
            # flow passes the free-form UserDto.sub_domain string here,
            # so a newline-bearing value would otherwise reach the
            # handler's verbatim log via this exception. The raw value
            # still drives the lookup.
            raise TenantNotFoundException(_safe_log_value(subdomain))
        return existing

    async def get_tenant_by_id(self, tenant_id: str) -> Tenant:
        """Get tenant by ID. Raises TenantNotFoundException if not found."""
        existing = await self.tenant_repository.get(id=tenant_id)
        if existing is None:
            raise TenantNotFoundException(_safe_log_value(tenant_id))
        return existing

    async def create_tenant(self, tenant_data: CreateTenantDto) -> PydanticObjectId | None:
        """Create a new tenant. Raises InvalidOperationException if admin password is weak."""
        validate_password(tenant_data.admin_password)
        response = await self.tenant_repository.create(tenant_data)
        return response


    async def delete_tenant(self, tenant_id: str) -> None:
        """Delete tenant by ID. Raises TenantNotFoundException if not found."""
        # BaseRepository.delete() returns a bool (False when no document
        # matches), never None, so `is None` could never fire and a
        # delete of a nonexistent tenant silently succeeded instead of
        # raising, breaking this method's own contract. Check `is
        # False`, as RoleService.delete_role and UserService.delete_user
        # already do for the same repository method. The tenant delete
        # endpoint pre-checks with get_tenant_by_id, so its behaviour
        # today is unchanged; this fixes the service contract for any
        # direct caller.
        if await self.tenant_repository.delete(id=tenant_id) is False:
            raise TenantNotFoundException(_safe_log_value(tenant_id))

    async def total_count(self) -> int:
        """Get total count of tenants. Returns an integer."""
        return await self.tenant_repository.count()
    
    async def update_feature(self, tenant_id: str, feature: FeatureDto):
        """
            Update a feature for a tenant. If the feature does not exist, it will be added to the tenant's features.
            Raises TenantNotFoundException if tenant not found.
        """
        tenant = await self.get_tenant_by_id(tenant_id)
        feature_found = False
        for existing_feature in tenant.features:
            if existing_feature.name == feature.name:
                existing_feature.enabled = feature.enabled
                feature_found = True
                break
        if not feature_found:
            tenant.features.append(Feature(name=feature.name, enabled=feature.enabled))
        
        # Direct .save() bypasses BaseRepository.update()'s central
        # updated_at stamp, so stamp it here to move it off creation time.
        tenant.updated_at = get_utc_now()
        # Save the updated tenant..
        await tenant.save()
        logger.debug(f"Feature '{feature.name}' updated to '{feature.enabled}' for tenant '{tenant_id}'")


    async def update_tenant(self, tenant_id: str, data: UpdateTenantDto) -> None:
        """Update tenant details. Raises TenantNotFoundException if tenant not found."""
        tenant = await self.get_tenant_by_id(tenant_id)
        tenant.is_active = data.is_active
        tenant.custom_domain = data.custom_domain
        tenant.subscription_id = data.subscription_id
        await self.tenant_repository.update(tenant_id, tenant.model_dump(exclude_none=True))


    async def get_features_by_tenant_id(self, tenant_id: str) -> List[FeatureDto]:
        """
            Get features for a tenant by ID.
            Raises 
                TenantNotFoundException if tenant not found.
        """
        tenant = await self.get_tenant_by_id(tenant_id)
        all_features = [FeatureDto(name=name, enabled=False) for name in FeatureEnum]
        if len(tenant.features) == 0:
            return all_features

        tenant_features = [FeatureDto(name=feature.name, enabled=feature.enabled) for feature in tenant.features]
        logger.debug(f"Tenant features for tenant {tenant_id}: {tenant_features}")
        
        # Check if any features are added in the enum that are not present in tenant features
        if len(all_features) > len(tenant_features):
            logger.debug(f"Some features are not set for tenant {tenant_id}, adding missing features as disabled.")
            available_features: List[FeatureDto] = []
            for all_feature in all_features:
                for tenant_feature in tenant_features:
                    if all_feature.name == tenant_feature.name:
                        # Feature exists in tenant, add it as is
                        available_features.append(tenant_feature)
                        break
                else:
                    # Feature not found in tenant, add it as enabled=False by default
                    available_features.append(FeatureDto(name=all_feature.name, enabled=False))
            return available_features
        
        # Return tenant features if all features are already set
        return tenant_features