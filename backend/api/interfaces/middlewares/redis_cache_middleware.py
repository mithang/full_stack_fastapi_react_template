import json
from urllib.parse import parse_qsl, urlencode
from redis.asyncio import Redis, from_url
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response
from fastapi import Request
from api.common.utils import get_logger
from api.core.config import settings

from api.core.container import get_jwt_token_service, get_role_service, get_user_service, get_subscription_plan_service
from api.infrastructure.security.current_user import  current_user_optional

logger = get_logger(__name__)

# Query keys whose values must never reach the logs: single-use auth
# tokens travel in the query string (e.g. POST
# /api/v1/account/password_reset_confirmation?token=...), and the api
# logger runs at DEBUG in all environments. Only the log strings are
# redacted — the real cache key below is untouched, so cache
# lookups, writes and clears behave exactly as before.
_REDACTED_QUERY_KEYS = {"token"}


def _redacted_query(query: str) -> str:
    if not query:
        return query
    pairs = parse_qsl(query, keep_blank_values=True)
    return urlencode(
        [
            (key, "[redacted]" if key.lower() in _REDACTED_QUERY_KEYS else value)
            for key, value in pairs
        ],
        doseq=True,
    )

redis_cache_expiry = 300  # Cache expiry time in seconds (5 minutes)
redis: Redis =  from_url(url=settings.redis_uri, decode_responses=True)

not_allowed_cache_paths = [
    "/api/v1/account/login",
    "/api/v1/account/logout",
    "/api/v1/account/register",
    # Identity endpoint: read_users_me returns the user, role and
    # subscription read fresh from the database on every call
    # (get_current_user), and the frontend's auth provider uses it
    # as its source for the displayed profile, role and plan. A
    # cached 200 would hide a role change, profile edit, deactivation
    # or subscription change made by another admin (or a billing
    # event) for the rest of the TTL, because a mutation clears only
    # the acting user's cache keys. Same stale-viewer class as the
    # users/roles/plans list bypasses below, not an enforcement fix:
    # permission checks read the user fresh on each request.
    "/api/v1/account/me",
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
    # Append-only chat history: get_history reads the user's sessions
    # fresh on every call, and the frontend refetches it when a stream
    # ends (ai-chat.tsx, new_session case). But the exchange itself is
    # saved by a post-response background task (OllamaChat.
    # generate_response adds save_user_query after the stream), and
    # the middleware's non-GET cache clear for POST /ask runs before
    # that save lands — so a history GET landing between stream end
    # and the background save would cache the pre-save list for the
    # rest of the TTL, hiding the just-finished exchange from the
    # history panel. Same stale-viewer class as the audit-log/
    # checkout bypasses above, not an enforcement fix: ask/delete
    # handlers read/write fresh.
    "/api/v1/ai/history",
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
    # Tenant feature toggles, fetched by the manage-features dialog.
    # A feature update is a PATCH, and the middleware only clears the
    # acting admin's cache keys, so every other admin would otherwise
    # keep the previous toggle list for the rest of the TTL — a
    # just-disabled feature still shown as enabled (or vice versa)
    # when they open the dialog. Features gate access server-side
    # (check_feature_access reads the tenant fresh), so this is a
    # stale-admin-UI fix, not an enforcement fix. Matching is
    # endswith, and the tenant path ends in "/features" while the
    # static feature-enum list is "/api/v1/features/" (trailing
    # slash), so that list stays cached.
    "/features",
    "/api/v1/security/passkeys",
    "/api/v1/configurations/stripe/webhooks",
    # Tenant Stripe settings, fetched by the Stripe provider on load
    # and on tenant change. A configure POST by another admin with
    # MANAGE_PAYMENTS_SETTINGS clears only that admin's cache keys,
    # so a viewing admin would otherwise keep the previous settings
    # for the rest of the TTL — a just-configured key not shown, or
    # removed settings still offered in the billing UI. Same
    # stale-admin-UI class as the SSO-list bypass above, not an
    # enforcement fix: checkout handlers read settings fresh.
    # Endswith matching is exact here: no other GET path ends in
    # "/stripe" (the webhook path has its own entry above, and
    # webhook POSTs are never cached anyway).
    "/api/v1/configurations/stripe",
    # Live computed metrics: get_dashboard_metrics aggregates user
    # counts and a registration timeseries fresh on every call, and
    # the dashboard page fetches it on load (and on filter change).
    # A cached 200 would show a viewing admin numbers up to the TTL
    # old even as other users register, because a registration POST
    # clears only the registering user's cache keys, not the viewing
    # admin's. The query string (filter) is part of the cache key, so
    # this bypass is the only way to keep the metrics live.
    "/api/v1/dashboard/",
    # Append-only security list: list_audit_logs reads the tenant's
    # audit entries fresh on every call, and the audit-log page
    # fetches it on load (and on page/filter change). Audit entries
    # are created by other users' actions, and a mutation clears only
    # the acting user's cache keys, so a viewing admin would
    # otherwise keep a list up to the TTL old — newest security
    # events (logins, permission changes) hidden while they review
    # it. The query string (limit/skip/action) is part of the cache
    # key, so this bypass is the only way to keep the list live.
    "/api/v1/audit-logs/",
    # Tenant SSO settings list, fetched by the SSO-configuration
    # provider on load and on tenant change (and after the viewing
    # admin's own CRUD, which clears only their own cache keys). A
    # create/delete by another FULL_ACCESS admin would otherwise
    # leave the viewing admin's list up to the TTL old — a just-
    # deleted provider still offered in the configuration UI, or a
    # newly enabled provider missing from it. Same stale-admin-UI
    # class as the feature-toggle bypass above, not an enforcement
    # fix: the SSO login/callback handlers read settings fresh.
    # Endswith matching keeps the detail route (/ssos/{sso_id})
    # and the static available-providers list cached, since neither
    # path ends in "/api/v1/ssos/".
    "/api/v1/ssos/",
    # Append-only billing list: list_checkout_records reads the tenant's
    # billing records fresh on every call, and the billing overview page
    # fetches it on load and on page change. Records are created by other
    # users' payment-success handlers (and Stripe webhooks), not by the
    # viewing admin's mutations, and a mutation clears only the acting
    # user's cache keys, so a viewing billing admin would otherwise keep
    # a list up to the TTL old — newest payments hidden while they
    # review billing. Same stale-viewer class as the audit-log bypass,
    # not an enforcement fix: payment handlers read/write fresh. The
    # query string (skip/limit) is part of the cache key, so this bypass
    # is the only way to keep the list live. Endswith matching is exact
    # here: no other GET path ends in "/checkouts/all".
    "/api/v1/checkouts/all",
    # Live Stripe list: list_invoices reads the tenant's invoices
    # fresh from Stripe on every call, and the invoices page fetches
    # it on load. Invoices are created/paid by other users' payments
    # and Stripe events, not by the viewing billing admin's mutations,
    # and a mutation clears only the acting user's cache keys, so a
    # viewing billing admin would otherwise keep a list up to the TTL
    # old — a just-paid invoice still shown as open while they review
    # billing. Same stale-viewer class as the audit-log/checkout
    # bypasses, not an enforcement fix: payment handlers read/write
    # fresh. Full path confirmed as /api/v1 + router prefix /invoices
    # + GET "/" (api/__init__.py:130,157; invoice_endpoint.py:14,22).
    "/api/v1/invoices/",
    # Tenant user list, fetched by the UsersProvider on load and on
    # page change. Users are created, updated, deleted, and assigned
    # roles by other admins, and a mutation clears only the acting
    # admin's cache keys, so a viewing admin would otherwise keep a
    # list up to the TTL old — a just-created user missing from the
    # list, or a just-deactivated user still shown as active while
    # they review it. Same stale-viewer class as the audit-log/
    # checkout/invoices bypasses, not an enforcement fix: user
    # mutations read/write fresh. The query string (skip/limit) is
    # part of the cache key, so this bypass is the only way to keep
    # the list live. Endswith matching keeps the detail route
    # (/users/{user_id}) and the profile-image route cached, since
    # neither path ends in "/api/v1/users/".
    "/api/v1/users/",
    # Tenant role list, fetched by the RolesProvider on load and on
    # page change. Roles are created, updated, deleted, and assigned
    # permissions by other admins, and a mutation clears only the
    # acting admin's cache keys, so a viewing admin would otherwise
    # keep a list up to the TTL old — a just-created role missing
    # from the list, or a just-deleted role still offered for
    # assignment while they review it. Same stale-viewer class as
    # the audit-log/checkout/invoices/users bypasses, not an
    # enforcement fix: role mutations read/write fresh. The query
    # string (skip/limit) is part of the cache key, so this bypass
    # is the only way to keep the list live. Endswith matching keeps
    # the detail route (/roles/{role_id}) and the search route
    # (/roles/search_by_name) cached, since neither path ends in
    # "/api/v1/roles/". Full path confirmed as /api/v1 + router
    # prefix /roles + GET "/" (api/__init__.py:130,148;
    # role_endpoint.py:16,19).
    "/api/v1/roles/",
    # Tenant storage settings list, fetched by the SettingsProvider
    # on load and on tenant change (and after the viewing admin's own
    # configure/reset, which clears only their own cache keys). A
    # configure POST or reset PATCH by another
    # MANAGE_STORAGE_SETTINGS admin would otherwise leave the viewing
    # admin's list up to the TTL old — a just-configured provider
    # still shown as unconfigured, or reset settings still shown as
    # active. Same stale-admin-UI class as the SSO-list bypass above,
    # not an enforcement fix: upload handlers read settings fresh.
    # Endswith matching keeps the static available-providers list
    # cached, since /api/v1/storage/available does not end in
    # "/api/v1/storage/".
    "/api/v1/storage/",
    # Live Stripe list: list_products reads the tenant's products
    # fresh from Stripe on every call, and the products page fetches
    # it on load. Products are created, updated, and deleted by
    # other admins (or in the Stripe dashboard), and a mutation
    # clears only the acting admin's cache keys, so a viewing admin
    # would otherwise keep a list up to the TTL old — a
    # just-created product missing from the pricing UI, or a
    # just-deactivated product still offered while they review it.
    # Same stale-viewer class as the audit-log/checkout/invoices/
    # users/roles bypasses, not an enforcement fix: product
    # mutations read/write fresh. The query string (active filter)
    # is part of the cache key, so this bypass is the only way to
    # keep the list live. Endswith matching keeps the detail route
    # (/products/{product_id}) cached, since it does not end in
    # "/api/v1/products/". Full path confirmed as /api/v1 + router
    # prefix /products + GET "/" (api/__init__.py:130,152;
    # product_endpoint.py:15,23).
    "/api/v1/products/",
    # Live Stripe list: list_prices reads the tenant's prices fresh
    # from Stripe on every call (prices.list_async), and prices are
    # created and updated by other admins or in the Stripe dashboard,
    # while a mutation clears only the acting admin's cache keys, so
    # a viewing admin would otherwise keep a list up to the TTL old
    # — a just-created price missing, or a just-deactivated price
    # still offered while they review pricing. Same stale-viewer
    # class as the products bypass above, not an enforcement fix:
    # price mutations read/write fresh. Endswith matching keeps the
    # detail route (/prices/{price_id}) cached, since it does not
    # end in "/api/v1/prices/". Full path confirmed as /api/v1 +
    # router prefix /prices + GET "/" (api/__init__.py:130,153;
    # prices_endpoint.py:15,23).
    "/api/v1/prices/",
    # Live Stripe list: list_plans reads the tenant's (or host's)
    # plans fresh from Stripe on every call (plans.list_async), and
    # the billing overview page fetches it on load. Plans are
    # created, updated, and deleted by other admins (or in the
    # Stripe dashboard), and a mutation clears only the acting
    # admin's cache keys, so a viewing billing admin would
    # otherwise keep a list up to the TTL old — a just-created
    # plan missing from the billing overview, or a just-deleted
    # plan still offered while they review it. Same stale-viewer
    # class as the products/prices bypasses above, not an
    # enforcement fix: plan mutations read/write fresh. Endswith
    # matching keeps the detail route (/plans/{plan_id}) cached,
    # since it does not end in "/api/v1/billing/plans". Full path
    # confirmed as /api/v1 + router prefix /billing + GET "/plans"
    # (api/__init__.py:130,154; billing_endpoint.py:13,16).
    "/api/v1/billing/plans",
    # Tenant list: list_tenants reads all tenants fresh on every call,
    # and the tenant provider fetches it on load and on page change.
    # Tenants are created and deleted by other HOST_MANAGE_TENANTS
    # admins, and a mutation clears only the acting admin's cache
    # keys, so a viewing host admin would otherwise keep a list up
    # to the TTL old — a just-created tenant missing, or a
    # just-deleted tenant still offered while they review tenants.
    # Same stale-viewer class as the users/roles bypasses above, not
    # an enforcement fix: tenant mutations read/write fresh. The
    # query string (skip/limit) is part of the cache key, so this
    # bypass is the only way to keep the list live. Endswith
    # matching keeps the detail route (/tenants/{id}) and the
    # search/check routes cached, since none ends in
    # "/api/v1/tenants/". Full path confirmed as /api/v1 + router
    # prefix /tenants + GET "/" (api/__init__.py:130,136;
    # tenant_endpoint.py:24,26).
    "/api/v1/tenants/",
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

        # Live-availability GET: /api/v1/tenants/check_subdomain/{subdomain}
        # returns whether a subdomain is free right now, and the frontend
        # (TenantsService, via ApiClient with a bearer token when logged
        # in) calls it while the user types. A cached verdict would lie
        # for the rest of the TTL — a just-freed name still shown as
        # taken, or a just-taken name still shown as free, with the
        # submission then failing server-side. It cannot go in
        # not_allowed_cache_paths: matching there is endswith, and the
        # variable subdomain is the trailing segment, so no list entry
        # can match — the same reason "/check_dns" is a suffix entry
        # (there the tenant id leads, here the variable trails).
        # Tenant-resolution GET: /api/v1/tenants/search_by_subdomain/{subdomain}
        # resolves a tenant from its subdomain, so the same trailing-variable
        # shape applies: a cached TenantDto would keep resolving a freed or
        # reassigned subdomain to its previous tenant for the rest of the
        # TTL, where a stable record fetch (e.g. /tenants/{id}) has no such
        # mapping-change risk. It is bypassed the same way.
        # Tenant-resolution GET: /api/v1/tenants/search_by_name/{name}
        # has the identical shape and risk: the name is the lookup key, so
        # a cached TenantDto would keep resolving a freed or recreated name
        # to its previous tenant (including a stale is_active/custom-domain
        # state) for the rest of the TTL. The trailing-slash segment keeps
        # this from matching /roles/search_by_name, which takes no variable.
        # Single-session history: /api/v1/ai/sessions/{session_id}
        # has the same post-response-background-save staleness as
        # /api/v1/ai/history above (a GET landing before the save
        # caches pre-save histories for the TTL), but it cannot go in
        # not_allowed_cache_paths: matching there is endswith, and
        # the variable session id is the trailing segment — the same
        # reason "/check_subdomain/" is matched this way.
        # Live Stripe detail: /api/v1/products/{product_id} reads
        # the product fresh from Stripe on every call (retrieve_async),
        # and the billing overview fetches it per plan on load. The
        # list bypass above keeps only the list live; the detail route
        # cannot go in not_allowed_cache_paths for the same trailing-
        # variable reason, so it is bypassed here. A product edited or
        # deactivated by another admin (or in the Stripe dashboard)
        # would otherwise stay stale in the viewing admin's overview
        # for the rest of the TTL, since a mutation clears only the
        # acting admin's cache keys. No other GET lives under
        # /api/v1/products/, so the substring also re-matches the
        # already-bypassed list harmlessly. Same stale-viewer class
        # as the products-list bypass, not an enforcement fix:
        # product mutations read/write fresh.
        # Live Stripe detail: /api/v1/billing/plans/{plan_id} reads
        # the plan fresh from Stripe on every call (retrieve_async),
        # and the list bypass above keeps only the list live; the
        # detail route cannot go in not_allowed_cache_paths for the
        # same trailing-variable reason, so it is bypassed here. A
        # plan edited or deleted by another admin (or in the Stripe
        # dashboard) would otherwise stay stale in the viewing
        # admin's billing view for the rest of the TTL, since a
        # mutation clears only the acting admin's cache keys. The
        # list path has no trailing slash, so this substring matches
        # only the detail route. Same stale-viewer class as the
        # products-detail bypass, not an enforcement fix: plan
        # mutations read/write fresh.
        # Live user detail: /api/v1/users/{user_id} reads the user
        # fresh from the database on every call (get_user_by_id), and
        # the list bypass above keeps only the list live; the detail
        # route cannot go in not_allowed_cache_paths for the same
        # trailing-variable reason, so it is bypassed here. A user
        # edited, deactivated, or role-changed by another admin would
        # otherwise stay stale in the viewing admin's detail/edit
        # view for the rest of the TTL, since a mutation clears only
        # the acting admin's cache keys. No other GET lives under
        # /api/v1/users/ except the profile-image route, whose
        # presigned URL is freshly minted on every call, so the
        # substring also re-matches the already-bypassed list and
        # the profile route harmlessly. Same stale-viewer class as
        # the products/plan detail bypasses, not an enforcement fix:
        # user mutations read/write fresh.
        if any(request.url.path.endswith(path) for path in not_allowed_cache_paths) or "/check_subdomain/" in request.url.path or "/search_by_subdomain/" in request.url.path or "/search_by_name/" in request.url.path or "/ai/sessions/" in request.url.path or "/api/v1/products/" in request.url.path or "/api/v1/billing/plans/" in request.url.path or "/api/v1/users/" in request.url.path or token is None:
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
        # Log only the redacted form: the raw query can carry a
        # single-use token (see _REDACTED_QUERY_KEYS).
        log_cache_base = f"cu{user_id}:ct{tenant_id}:{request.url.path}?{_redacted_query(request.url.query)}"
        log_cache_key = f"cache:{log_cache_base}"
        logger.debug(f"Cache base string: {log_cache_base}")
        cache_key = f"cache:{cache_base}"

        logger.debug(request.method + " " + request.url.path + "?" + _redacted_query(request.url.query))
        # Only cache GET requests
        if request.method != "GET":
            logger.debug(f"Clearing cache for key: {log_cache_key}")
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
            logger.debug(f"Cache hit for key: {log_cache_key}")
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
                logger.debug(f"Cache set for key: {log_cache_key}")

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