import json
from redis.asyncio import Redis, from_url
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response
from fastapi import Request
from api.common.utils import get_logger
from api.core.config import settings

from api.core.container import get_jwt_token_service, get_role_service, get_user_service, get_subscription_plan_service
from api.infrastructure.security.current_user import  current_user_optional

logger = get_logger(__name__)

redis_cache_expiry = 300  # Cache expiry time in seconds (5 minutes)
redis: Redis =  from_url(url=settings.redis_uri, decode_responses=True)

not_allowed_cache_paths = [
    "/api/v1/account/login",
    "/api/v1/account/logout",
    "/api/v1/account/register",
    # Single-use token flow that returns a TokenSetDto (and sets the
    # refresh cookie): a cached 200 would let a consumed magic link
    # be replayed within the TTL without re-validating it, and would
    # return the token set without the handler's Set-Cookie. The
    # repo frontend calls this without an Authorization header (so
    # it already bypassed via token is None), but a mobile or other
    # non-browser client sending a bearer token must not be cached.
    "/api/v1/account/email_magic_link_validate",
    # Fresh-random-value GET: create_new_session returns a new
    # PydanticObjectId on every call, and the frontend asks for one
    # whenever starting a chat without a session_id. A cached 200
    # would hand the same session_id to every new chat within the
    # TTL, merging distinct conversations into one history.
    "/api/v1/ai/new_session",
    # Side-effect GET: check_dns dispatches a DNS-update task when the
    # custom-domain status is "activation-progress" or "failed", and its
    # message reports the live status. The path carries a tenant id, so
    # only the "/check_dns" suffix can be matched (matching is endswith).
    # A cached 200 would suppress the re-dispatch when a user re-checks
    # after fixing their DNS records — the user would see the stale
    # "previously failed" message while no new task runs — and would hide
    # a completed activation behind a stale "still in progress" message
    # for the rest of the TTL.
    "/check_dns",
    "/api/v1/app_configuration/",
    # Global tenant banner, fetched once at app load by the
    # app-config provider alongside the app configuration above.
    # A banner create/update is a mutation, but the middleware only
    # clears the acting admin's cache keys, so every other user in
    # the tenant would otherwise keep the previous banner for the
    # rest of the TTL — a withdrawn banner lingering, or a newly
    # published (possibly urgent) banner not appearing until their
    # cached entry expires.
    "/api/v1/notifications/banner",
    "/api/v1/security/passkeys",
    "/api/v1/configurations/stripe/webhooks",
]


class RedisCacheMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, expiry: int = redis_cache_expiry):
        super().__init__(app)
        self.expiry = expiry

    async def _clear_cache(self, user_id: str, tenant_id: str):
        # Fail open: a cache outage must not block the mutation itself.
        # Stale entries expire on their own (self.expiry); the request
        # proceeds and the handler runs either way.
        try:
            async for key in redis.scan_iter(f"cache:cu{user_id}:ct{tenant_id}:*"):
                await redis.delete(key)
        except Exception as e:
            logger.warning(f"Cache clear failed, continuing without it: {e}")

    async def dispatch(self, request: Request, call_next):
        token = None
        if "authorization" in request.headers:
            # The auth scheme is case-insensitive (RFC 7235), and
            # replace() would strip every "Bearer " occurrence, so
            # strip only a leading scheme: a "bearer <token>" header
            # from a non-browser client previously reached user
            # resolution as "bearer <token>", failed, and the request
            # bypassed the cache as an unresolvable token — mirroring
            # the audit middleware's misattribution fix.
            auth_header = request.headers["authorization"]
            token = auth_header[7:] if auth_header.lower().startswith("bearer ") else auth_header

        if any(request.url.path.endswith(path) for path in not_allowed_cache_paths) or token is None:
            logger.debug(f"Bypassing cache for path: {request.url.path}")
            return await call_next(request)
            
        try:
            
            user_service = get_user_service()
            jwt_service = get_jwt_token_service()
            role_service = get_role_service()
            subscription_service = get_subscription_plan_service()

            current_user = await current_user_optional(
                token,
                user_service=user_service,
                token_service=jwt_service,
                role_service=role_service,
                subscription_service=subscription_service
            )
        except Exception as e:
            logger.debug(f"Could not resolve current_user in middleware: {e}")
            current_user = None

        # A token was supplied but its user could not be resolved
        # (invalid/expired token, or a transient lookup failure).
        # Do not serve or store anything under the shared
        # "anonymous" key below: a handler that still succeeds
        # (e.g. after a transient failure clears) would otherwise
        # cache one user's 200 response under a key shared by every
        # unresolvable token, and later such requests would be
        # served that cached response. Bypass, as for no token.
        if current_user is None:
            logger.debug("Bypassing cache for unresolvable token.")
            return await call_next(request)

        user_id = getattr(current_user, "id", "anonymous")
        # Key on the effective request tenant, not the token user's
        # tenant: TenantMiddleware runs before this middleware and
        # sets request.state.tenant_id from the subdomain/custom
        # domain or the X-Tenant-ID header, and handlers read data
        # from that tenant's database. Keying on the user's tenant
        # alone let one tenant's cached GET be served for another
        # tenant's request (and left the other tenant's entries
        # uncleared on mutation) whenever the two differed.
        # request.state.tenant_id is None on the host scope (or when
        # tenancy is disabled), where the user's tenant is the
        # previous behaviour and is kept as the fallback.
        request_tenant_id = getattr(request.state, "tenant_id", None)
        tenant_id = str(request_tenant_id) if request_tenant_id is not None else getattr(current_user, "tenant_id", "default")
        cache_base = f"cu{user_id}:ct{tenant_id}:{request.url.path}?{request.url.query}"
        logger.debug(f"Cache base string: {cache_base}")
        cache_key = f"cache:{cache_base}"

        logger.debug(request.method + " " + request.url.path + "?" + request.url.query)
        # Only cache GET requests
        if request.method != "GET":
            logger.debug(f"Clearing cache for key: {cache_key}")
            await self._clear_cache(user_id, tenant_id)
            logger.debug("Cache cleared for non-GET request.")
            return await call_next(request)
           

        # --- Try reading from cache; fail open on any cache failure
        # (Redis down, corrupted entry) so the handler still runs.
        cached_value = None
        try:
            cached_value = await redis.get(cache_key)
        except Exception as e:
            logger.warning(f"Cache read failed, treating as miss: {e}")
        if cached_value:
            logger.debug(f"Cache hit for key: {cache_key}")
            try:
                cached = json.loads(cached_value)
                return Response(
                    content=cached["body"],
                    status_code=cached["status"],
                    media_type=cached["media_type"],
                    headers=cached.get("headers", {}),
                )
            except Exception as e:
                # Corrupt or wrong-shape entry: fall through to the
                # handler (which will re-cache a fresh response).
                logger.warning(f"Corrupt cache entry, treating as miss: {e}")

        # --- Cache miss → execute route handler
        response = await call_next(request)

        # Read and rebuild response body
        body = b"".join([chunk async for chunk in response.body_iterator])
        content_type = response.headers.get("content-type", "")
        try:
            body_text = body.decode()
        except UnicodeDecodeError as e:
            # Fail open: a non-UTF-8 body (a binary download, or a
            # non-UTF-8 upstream error page) must not turn into a 500
            # raised by this middleware itself, masking the handler's
            # own response — the same fail-open class as the cache
            # read/write guards above. Return the raw bytes uncached;
            # today's JSON GETs decode as before and are unaffected.
            logger.warning(f"Non-UTF-8 response body, returning raw: {e}")
            return Response(
                content=body,
                status_code=response.status_code,
                headers=dict(response.headers),
                media_type=content_type,
            )

        # Cache only 200 OK + JSON responses
        if response.status_code == 200  and "application/json" in content_type:
            to_cache = json.dumps({
                "body": body_text,
                "status": response.status_code,
                "media_type": content_type,
            })
            # Fail open: a cache-write failure must not turn a
            # successful handler response into a 500 for the client.
            try:
                await redis.set(cache_key, to_cache, ex=self.expiry)
            except Exception as e:
                logger.warning(f"Cache set failed, returning response anyway: {e}")
            else:
                logger.debug(f"Cache set for key: {cache_key}")

        if response.status_code == 401 and "application/json" in content_type and request.url.path not in not_allowed_cache_paths:
            logger.debug(f"Response status {response.status_code} not cached.")
            await self._clear_cache(user_id, tenant_id)
            logger.debug(f"Cleared cache for user: {user_id}, tenant: {tenant_id}")
            # Return the already-consumed 401 response instead of
            # calling call_next() again: a second call would re-run
            # the route handler and the audit-log middleware, doubling
            # handler work and audit entries for a single client GET.
            return Response(
                content=body_text,
                status_code=response.status_code,
                headers=dict(response.headers),
                media_type=content_type,
            )


        # Return new Response (since body_iterator is consumed)
        return Response(
            content=body_text,
            status_code=response.status_code,
            headers=dict(response.headers),
            media_type=content_type,
        )