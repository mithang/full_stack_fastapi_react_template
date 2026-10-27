import os
from fastapi import FastAPI, APIRouter, Request, status
from contextlib import asynccontextmanager

from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from api.common.exceptions import ApiBaseException, AuthenticationFailedException, AwsException, AzureException, ConflictException, ForbiddenException, InvalidOperationException, NotFoundException, UnauthorizedException
from api.common.utils import get_logger, is_production_environment, is_tenancy_enabled
from api.core.container import container
from api.core.exceptions import InvalidSubdomainException, TenantNotFoundException
from api.infrastructure.persistence.mongodb import Database
from api.interfaces.middlewares.audit_logs_read_middleware import AuditLogsReadMiddleware
from api.interfaces.middlewares.redis_cache_middleware import RedisCacheMiddleware
from api.interfaces.middlewares.security_headers_middleware import SecurityHeadersMiddleware
from api.interfaces.middlewares.tenant_middleware import TenantMiddleware
from api.interfaces.api_controllers.account_endpoint import router as account_router
from api.interfaces.api_controllers.user_endpoint import router as user_router
from api.interfaces.api_controllers.tenant_endpoint import router as tenant_router
from api.interfaces.api_controllers.role_endpoint import router as role_router
from api.interfaces.api_controllers.app_configuration_endpoint import router as app_configuration_router
from api.interfaces.api_controllers.storage_endpoint import router as storage_router
from api.interfaces.api_controllers.permissions_endpoint import router as permissions_router
from api.interfaces.api_controllers.dashboard_endpoint import router as dashboard_router
from api.interfaces.api_controllers.ai_endpoint import router as ai_router
from api.interfaces.api_controllers.health_endpoint import router as health_router
from api.interfaces.api_controllers.manage_security_endpoint import router as manage_security_router
from api.interfaces.api_controllers.features_endpoint import router as features_router
from api.interfaces.api_controllers.product_endpoint import router as product_router
from api.interfaces.api_controllers.prices_endpoint import router as prices_router
from api.interfaces.api_controllers.billing_endpoint import router as billing_router
from api.interfaces.api_controllers.stripe_endpoint import router as stripe_router
from api.interfaces.api_controllers.stripe_endpoint import webhook_router as stripe_webhook_router
from api.interfaces.api_controllers.invoice_endpoint import router as invoice_router
from api.interfaces.api_controllers.checkout_endpoint import router as checkout_router
from api.interfaces.api_controllers.notification_endpoint import router as notification_router
from api.interfaces.api_controllers.audit_logs_endpoint import router as audit_logs_router
from api.interfaces.api_controllers.sso_settings_endpoint import router as sso_router
from api.interfaces.api_controllers.branding_endpoint import router as branding_router

from api.common.logging import configure_logging
from api.core.config import settings
from api.infrastructure.persistence.seeder import seed_initial_data

build_path = os.path.join(os.path.dirname(__file__), "ui")


db: Database = container.resolve(Database)

logger = get_logger(__name__)
@asynccontextmanager
async def lifespan(app: FastAPI):
    configure_logging()
    # initialization database with application-wide models Typically the host database
    await db.init_db(settings.mongo_db_name, is_tenant=False)
    await seed_initial_data()
    yield
    # Shutdown code
    await db.close()

app = FastAPI(
    lifespan=lifespan,
    title="FastAPI React & MongoDb Template",
    description="A template for building full-stack applications with FastAPI, React and MongoDB. Optional multi-tenancy support.",
    version="1.0.0",
    # Interactive docs and the raw schema expose every route, request
    # shape and auth endpoint: useful in development, but an
    # unnecessary information disclosure on a production deployment
    # (and the generated frontend client never fetches the schema at
    # runtime). Disabled only in production; dev keeps /docs, /redoc
    # and /openapi.json exactly as before. is_production_environment
    # lowercases the env value, unlike the raw == "production" checks
    # elsewhere, so "Production" is treated as production too.
    docs_url=None if is_production_environment() else "/docs",
    redoc_url=None if is_production_environment() else "/redoc",
    openapi_url=None if is_production_environment() else "/openapi.json",
)



@app.exception_handler(ApiBaseException)
async def api_exception_handler(req: Request, ex: ApiBaseException) -> JSONResponse:
    status_code = status.HTTP_400_BAD_REQUEST
    if isinstance(ex, NotFoundException) or isinstance(ex, TenantNotFoundException):
        status_code = status.HTTP_404_NOT_FOUND
    elif isinstance(ex, ConflictException):
        status_code = status.HTTP_409_CONFLICT
    elif isinstance(ex, UnauthorizedException):
        status_code = status.HTTP_401_UNAUTHORIZED
    elif isinstance(ex, AuthenticationFailedException):
        # The only named auth exception still falling through to the
        # default 400: an authentication failure is a 401, the status
        # the frontend treats as an auth signal, not a bad request.
        status_code = status.HTTP_401_UNAUTHORIZED
    elif isinstance(ex, ForbiddenException):
        # ForbiddenException previously fell through to the default 400,
        # so permission denials, self-action guards, and the refresh
        # endpoint's missing-cookie error all surfaced as "bad request"
        # instead of 403 — including FeatureNotEnabledException, which
        # subclasses ForbiddenException. 403 is the status the frontend
        # already expects for these cases (e.g. tenant-provider).
        status_code = status.HTTP_403_FORBIDDEN
    elif isinstance(ex, InvalidSubdomainException):
        status_code = status.HTTP_400_BAD_REQUEST
    elif isinstance(ex, InvalidOperationException):
        status_code = status.HTTP_406_NOT_ACCEPTABLE
    elif isinstance(ex, AwsException) or isinstance(ex, AzureException):
        # S3/Azure storage failures (S3StorageException, AzureBlobStorageException)
        # previously fell through to the default 400, so a storage-provider
        # outage looked like a bad client request. An upstream failure is a
        # 502, the status the frontend already treats as a server error
        # (its fallbacks trigger on any non-2xx rejection, as in the
        # profile-image path), so no client change is needed.
        status_code = status.HTTP_502_BAD_GATEWAY

    
    logger.error(f"API Exception: {ex.message}")
    return JSONResponse(
        status_code=status_code,
        content={"error": ex.message, "code": status_code}
    )

# Audit logging must run before the Redis cache: Starlette runs
# last-added middleware first, so the previous add order (audit
# before cache) made the cache run first, and a cache hit returned
# before the audit middleware ever ran, leaving cached reads of
# users/roles/tenants unlogged while uncached reads were logged.
# With this order the audit entry is written for every GET, cached
# or not, and the cache still sits between audit and the handler.
app.add_middleware(RedisCacheMiddleware)
app.add_middleware(AuditLogsReadMiddleware)

if is_tenancy_enabled(): 
    app.add_middleware(TenantMiddleware)
    logger.info("Multi-tenancy is enabled.")

# CORS must run before the other middlewares for preflight OPTIONS
# requests, so it is added last (Starlette runs last-added first).
# Only enabled when CORS_ALLOW_ORIGINS is explicitly configured, and
# only for those exact origins, so cookie auth is not opened up.
_cors_origins = [o.strip() for o in settings.cors_allow_origins.split(",") if o.strip()]
if _cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_cors_origins,
        allow_credentials=True,
        # Only the methods the API actually exposes and the generated
        # client actually uses (GET/POST/PUT/PATCH/DELETE, verified
        # against both the router decorators and the client services):
        # with allow_credentials=True, "*" would preflight-approve any
        # method (e.g. TRACE) from a configured origin. OPTIONS
        # preflights are handled by CORSMiddleware itself and need no
        # entry here.
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        allow_headers=["Authorization", "Content-Type", "X-Tenant-ID"],
    )
    logger.info(f"CORS enabled for origins: {_cors_origins}")

# Security headers are added last so they run outermost (Starlette runs
# last-added first) and cover every response: API, error, cached, and
# SPA-shell alike, including when CORS is disabled. The middleware is
# pure ASGI, so it does not buffer streaming responses (ai-chat SSE).
app.add_middleware(SecurityHeadersMiddleware)


# Mount static files only if they exist (for production Docker deployment)
if os.path.exists(build_path) and os.path.exists(os.path.join(build_path, "assets")):
    app.mount("/assets", StaticFiles(directory=os.path.join(build_path, "assets")), name="assets")
    logger.info("Static files mounted successfully")
else:
    logger.warning(f"Static files directory not found - running in {settings.fastapi_env} mode")




router = APIRouter(prefix="/api/v1")


router.include_router(health_router)

if is_tenancy_enabled():
    router.include_router(tenant_router)
    router.include_router(features_router)
    router.include_router(branding_router)



router.include_router(app_configuration_router)
router.include_router(account_router)
router.include_router(manage_security_router)
router.include_router(dashboard_router)

router.include_router(user_router)
router.include_router(role_router)
router.include_router(permissions_router)
router.include_router(storage_router)
router.include_router(ai_router)
router.include_router(product_router)
router.include_router(prices_router)
router.include_router(billing_router)
router.include_router(stripe_router)
router.include_router(stripe_webhook_router)
router.include_router(invoice_router)
router.include_router(checkout_router)
router.include_router(notification_router)
router.include_router(audit_logs_router)
router.include_router(sso_router)


app.include_router(router)



# Catch-all route for React Router (only in production with static files)
@app.get("/{full_path:path}", include_in_schema=False)
async def react_router(full_path: str):
    # API paths must never serve the SPA shell: a web/mobile client
    # calling a mistyped or removed /api/v1 route previously got a 200
    # index.html (or a 200 "not found" message below), so the client
    # could not tell the route did not exist and failed opaquely on
    # the HTML body. Unmatched API paths are a 404 JSON instead, in
    # the same {"detail": ...} shape FastAPI returns for unknown routes.
    # SPA routes are unaffected: only the api/ prefix is intercepted.
    if full_path == "api" or full_path.startswith("api/"):
        return JSONResponse(
            status_code=404, content={"detail": "API route not found"}
        )
    if os.path.exists(os.path.join(build_path, "index.html")):
        # Never cache the SPA shell: asset filenames are content-hashed
        # per build, so a cached index.html from before a deploy can
        # reference asset files the new build no longer ships, leaving
        # the client broken until its cache expires. The hashed assets
        # themselves are cacheable; only the shell must stay fresh.
        return FileResponse(
            os.path.join(build_path, "index.html"),
            headers={"Cache-Control": "no-store"},
        )
    else:
        # No UI build exists, so there is no SPA shell to serve: return
        # a 404 JSON (same {"detail": ...} shape as the API guard
        # above) instead of a 200 body claiming an endpoint was not
        # found, which a client could mistake for a successful
        # response. API paths never reach here (intercepted above),
        # so this branch only serves SPA routes with no build.
        return JSONResponse(
            status_code=404, content={"detail": "UI build not found"}
        )

