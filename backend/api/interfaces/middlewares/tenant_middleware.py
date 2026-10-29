from typing import Annotated, Optional
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi import  Depends, Request
from beanie import PydanticObjectId
from api.common.utils import get_host_main_domain_name, get_logger, is_subdomain
from api.core.config import settings

from api.core.container import get_tenant_service
from api.core.exceptions import TenantNotFoundException
from api.domain.entities.tenant import Tenant
from api.infrastructure.persistence.mongodb import mongo_client as db

logger = get_logger(__name__)


def _safe_log_value(value) -> str:
    # tenant_id below can arrive as a query param (request.query_params
    # percent-decodes it), unlike the X-Tenant-ID header value, so a
    # newline-bearing value would otherwise forge extra log lines on
    # every request carrying it — unauthenticated, before any handler
    # runs (same class as the endpoint/service fixes in iterations
    # 951-969). The tenant host is logged on the same unauthenticated
    # path, so it goes through the same flattening. Only the logged
    # copy is flattened; the raw value still drives the
    # PydanticObjectId conversion and its fallback.
    return str(value).replace("\r", " ").replace("\n", " ")


class TenantMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        tenant_id: Optional[str] = None
        tenant_host = get_tenant_host(request)
        logger.debug(f"Tenant host found: {_safe_log_value(tenant_host)}")
        tenant_service = get_tenant_service()

        if tenant_host:
            try:
                tenant: Tenant
                if is_subdomain(tenant_host):
                    logger.debug(f"Host '{_safe_log_value(tenant_host)}' identified as subdomain.")
                    tenant = await tenant_service.find_by_subdomain(tenant_host)
                else:
                    logger.debug(f"Host '{_safe_log_value(tenant_host)}' identified as custom domain.")
                    tenant = await tenant_service.find_by_custom_domain(tenant_host)
                
                tenant_id = str(tenant.id)
                logger.debug(f"Tenant ID resolved from custom domain '{_safe_log_value(tenant_host)}': {tenant_id}")
                request.state.frontend_host = tenant_host
            except TenantNotFoundException as e:
                logger.warning(f"Error resolving tenant from custom domain '{_safe_log_value(tenant_host)}': {e}")
                
        
        if tenant_id is None:
            tenant_id = request.headers.get("X-Tenant-ID") or request.query_params.get('tenant_id') or None

 
        if tenant_id is not None:
            logger.debug(f"Tenant ID found: {_safe_log_value(tenant_id)}")
            try:
                request.state.tenant_id = PydanticObjectId(tenant_id)
                # Initialize the database for the tenant and initialize
                # Beanie with tenant-specific models. This stays inside
                # the try so a conversion failure skips the tenant-DB
                # init and the return, instead of falling through to
                # them with tenant_id=None.
                await db.init_db(f"tenant_{tenant_id}", is_tenant=True)
                logger.debug(f"Database initialized for tenant: tenant_{_safe_log_value(tenant_id)}")
                return await call_next(request)
            except Exception:
                # Guard a malformed X-Tenant-ID / tenant_id query value
                # (e.g. a corrupted frontend localStorage entry) the
                # same way the subdomain branch above guards an unknown
                # tenant: PydanticObjectId() raises on a non-ObjectId
                # string, and uncaught that turned every API call
                # carrying the bad header into a 500 before any handler
                # ran. Fall through to the host/default-database path
                # below instead, as for a missing tenant id; tenant-
                # scoped handlers still fail closed on their own auth
                # checks, and a valid id behaves as before.
                logger.warning(
                    f"Invalid tenant id '{_safe_log_value(tenant_id)}', falling back to host scope"
                )
                tenant_id = None
        # A malformed id falls through here to the host/default-
        # database path below, which sets request.state.tenant_id
        # = None explicitly; the valid-id path returned above.
        # If no tenant ID is provided, ensure we are using the default database
        if db.is_tenant_active():
            # Reset to default DB if no tenant ID is provided
            await db.init_db(settings.mongo_db_name, is_tenant=False)
        request.state.tenant_id = None
        logger.debug("No tenant ID provided, using default database.")

        return await call_next(request)
        


def get_tenant_host(request: Request) -> Optional[str]:
    """
    Extracts the tenant-specific host (subdomain) from the incoming request.
    Returns None if the host matches the main domain.
    """
    # Try HTTP/2 ':authority' → fall back to 'host' → finally use parsed URL
    host = (
        request.headers.get(":authority")
        or request.headers.get("host")
        or request.url.hostname
    )
    if not host:
        return None

    host = host.split(':')[0].lower()  # Remove port if present and convert to lowercase

    # Compare against main domain
    main_domain = get_host_main_domain_name().lower()
    if host == main_domain:
        # If the host is exactly the main domain, return None (no tenant)
        return None

    if host.startswith("localhost") or host.startswith("127.0.0.1"):
        # Handle localhost with optional
        return None
    
    logger.debug(f"Extracted host: {_safe_log_value(host)}")
    return host

def get_tenant_id(request: Request) -> PydanticObjectId | None:
    return getattr(request.state, "tenant_id", None)

def frontend_dynamic_host(request: Request) -> str:
   return getattr(request.state, "frontend_host", get_host_main_domain_name())


FrontendHost = Annotated[str, Depends(frontend_dynamic_host)]