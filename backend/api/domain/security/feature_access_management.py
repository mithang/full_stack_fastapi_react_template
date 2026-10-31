from fastapi import Request
from api.core.container import get_tenant_service
from api.common.utils import get_logger
from api.core.exceptions import  FeatureNotEnabledException
from api.domain.dtos.role_dto import RoleDto
from api.domain.enum.feature import Feature as FeatureEnum
from api.domain.enum.permission import Permission
from api.infrastructure.security.current_user import CurrentUser

logger = get_logger(__name__)

def check_feature_access(feature_name: FeatureEnum) -> callable:
    async def dependency(request: Request, currentUser: CurrentUser) -> bool:
        role: RoleDto = currentUser.role
        if not currentUser.tenant_id:
            if Permission.HOST_MANAGE_TENANTS in role.permissions:
                return True  # Host users with tenant management permissions have access to all features.
        
        if not currentUser.tenant_id:
            logger.info(f"User {currentUser.id} does not belong to any tenant and lacks host permissions.")
            raise FeatureNotEnabledException(feature_name.value)
        
        tenant_service = get_tenant_service()
        tenant = await tenant_service.get_tenant_by_id(tenant_id=request.state.tenant_id)

        # Tenant names are free-form (CreateTenantDto.name is a plain str),
        # so strip CR/LF before logging: a name containing a newline could
        # otherwise forge extra log lines.
        safe_tenant_name = tenant.name.replace("\r", " ").replace("\n", " ")

        for f in tenant.features:
            if f.name == feature_name:
                if f.enabled is False:
                    logger.info(f"Feature {feature_name.value} is disabled for tenant {safe_tenant_name}")
                    raise FeatureNotEnabledException(feature_name.value)
                break
                    
                
        logger.info(f"Feature {feature_name.value} is enabled for tenant {safe_tenant_name}")
        return True
    return dependency
