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
# Browser Origin headers never carry a path or trailing slash, and
# Starlette matches allow_origins exactly, so a configured origin like
# "https://app.example.com/" would silently never match and the
# frontend's calls would fail with CORS errors. Normalize trailing
# slashes away (same class of fix as the frontend base-URL trim).
# Scheme and host are case-insensitive, and browsers send them
# lowercased, so also lowercase each entry: an uppercase typo like
# "HTTPS://App.Example.com" would otherwise silently never match.
# Browsers also omit the default port from the Origin header, so a
# configured "https://app.example.com:443" (or http :80) would
# likewise silently never match under exact matching; strip those
# default ports. Non-default ports (e.g. :3000, :8443) are kept.
# Finally, an Origin header never carries a path, so a configured
# "https://app.example.com/spa" would likewise never match; strip any
# path after scheme://host[:port] (the default-port strip below then
# still applies to e.g. "https://app.example.com:443/spa").
# Likewise a scheme-less entry like "app.example.com" would never
# match a browser Origin, which always carries a scheme; assume https
# (the production default) so the rest of the pipeline applies to it.
def _normalize_cors_origin(origin: str) -> str:
    o = origin.strip().rstrip("/").lower()
    if not o:
        return ""
    # Leave "*" untouched: the wildcard filter below drops it with a
    # warning, and prepending a scheme here would turn it into a dead
    # "https://*" entry that escapes that filter.
    if o == "*":
        return "*"
    # A browser Origin always carries a scheme, so a scheme-less entry
    # like "app.example.com" (or protocol-relative "//app.example.com")
    # would likewise never match; assume https, the production default,
    # except for loopback hosts, which in development are served over
    # plain http — a scheme-less "localhost:3000" previously became
    # https://localhost:3000 and never matched the dev Origin.
    if o.startswith("//"):
        bare = o[2:]
    elif "://" not in o:
        bare = o
    else:
        bare = None
    if bare is not None:
        host_part = bare.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
        host_part = host_part.rsplit("@", 1)[-1]
        # Bracketed IPv6 loopback: a naive rsplit(":", 1) mangles "[::1]"
        # (no port) into "[:" and never matches, so extract up to "]".
        # An unbracketed "::1" is likewise loopback, but browsers send it
        # bracketed, so it is re-bracketed below when it leads the entry.
        if host_part.startswith("["):
            host = host_part.split("]", 1)[0] + "]" if "]" in host_part else host_part
        elif host_part == "::1":
            host = "::1"
        else:
            host = host_part.rsplit(":", 1)[0]
        if bare.startswith("::1"):
            bare = "[::1]" + bare[3:]
            host = "[::1]"
        # A trailing dot must not hide a loopback host from the http
        # assumption above (e.g. "localhost.:3000"); the dot itself is
        # stripped from the rebuilt origin by the scheme branch below.
        if host.endswith("."):
            host = host[:-1]
        scheme = "http" if host in ("localhost", "127.0.0.1", "[::1]") else "https"
        o = scheme + "://" + bare if not o.startswith("//") else scheme + ":" + o
    scheme_end = o.find("://")
    if scheme_end != -1:
        path_start = o.find("/", scheme_end + 3)
        if path_start != -1:
            o = o[:path_start]
        # Browsers send Origin as scheme://host[:port] only, never with a
        # query or fragment, so strip those too (before the default-port
        # strip below, so "https://app.example.com:443?ref=docs" still
        # normalizes to "https://app.example.com").
        for sep in ("?", "#"):
            sep_pos = o.find(sep, scheme_end + 3)
            if sep_pos != -1:
                o = o[:sep_pos]
        # Browsers send Origin as scheme://host[:port] only, never with
        # userinfo, so a configured "https://user@app.example.com"
        # would likewise never match; strip everything up to the last
        # "@" in the host part (before the default-port strip below,
        # so "https://user@app.example.com:443" still normalizes to
        # "https://app.example.com").
        at_pos = o.rfind("@", scheme_end + 3)
        if at_pos != -1:
            o = o[: scheme_end + 3] + o[at_pos + 1 :]
        # A trailing dot is a valid DNS root label, so a configured
        # "https://app.example.com." names the same host — but browsers
        # send Origin without it, so it would never match. Strip one
        # trailing dot from the host (before the default-port strip
        # below, so "https://app.example.com.:443" still normalizes to
        # "https://app.example.com"); bracketed IPv6 hosts never carry
        # a trailing dot and are left alone.
        rest = o[scheme_end + 3 :]
        if not rest.startswith("[") and ":" in rest:
            host, port = rest.rsplit(":", 1)
            if host.endswith(".") and len(host) > 1:
                o = o[: scheme_end + 3] + host[:-1] + ":" + port
        elif rest.endswith(".") and len(rest) > 1:
            o = o[:-1]
    if o.startswith("https://") and o.endswith(":443"):
        return o[:-4]
    if o.startswith("http://") and o.endswith(":80"):
        return o[:-3]
    return o
_cors_origins = [o for o in (_normalize_cors_origin(o) for o in settings.cors_allow_origins.split(",")) if o]
# A "*" entry would defeat the exact-origins promise above: with
# allow_credentials=True, a wildcard origin is reflected back to the
# requester, so any site could make credentialed (cookie) calls; and
# a literal "*" is in any case ignored by browsers for credentialed
# requests. Drop it with a warning instead of opening up cookie auth;
# exact origins are unaffected, and if "*" was the only entry CORS
# simply stays disabled (the guard below).
if "*" in _cors_origins:
    logger.warning("CORS_ALLOW_ORIGINS contains '*', which is not allowed with credentialed cookie auth; ignoring the wildcard entry.")
    _cors_origins = [o for o in _cors_origins if o != "*"]
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

