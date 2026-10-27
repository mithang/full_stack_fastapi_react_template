from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware

from api.common.utils import capture_audit_log, get_logger
from api.core.container import get_jwt_token_service, get_role_service, get_subscription_plan_service, get_user_service
from api.domain.dtos.audit_logs_dto import AuditLogDto
from api.infrastructure.security.current_user import current_user_optional

logger = get_logger(__name__)

class AuditLogsReadMiddleware(BaseHTTPMiddleware):
    def _get_entity_name(self, path: str) -> str:
        if "/api/v1/users" in path:
            return "User"
        elif "/api/v1/roles" in path:
            return "Role"
        elif "/api/v1/tenants" in path:
            return "Tenant"
        elif "/api/v1/audit-logs" in path:
            return "AuditLog"

        return "Unknown"
    async def dispatch(self, request: Request, call_next):
        if request.method == "GET":
            # Only audited entities are logged: previously every GET
            # (dashboard, products, health, the SPA catch-all route)
            # fell through to "AuditLog" here, flooding the jsonl file
            # and pushing genuine user/role/tenant reads out of the
            # newest-first pagination window in list_audit_logs.
            # Reading the audit log itself stays logged as AuditLog.
            # Check the entity before resolving the user: the
            # resolution hits the user/token services, and paying
            # that cost for every unlogged GET (dashboard, health,
            # SPA catch-all) wasted a lookup per request even though
            # the request was then passed through unlogged.
            entity = self._get_entity_name(request.url.path)
            if entity == "Unknown":
                return await call_next(request)
            token = None
            if "authorization" in request.headers:
                # The auth scheme is case-insensitive (RFC 7235), and
                # replace() would strip every "Bearer " occurrence, so
                # strip only a leading scheme: a "bearer <token>" header
                # from a non-browser client previously reached user
                # resolution as "bearer <token>", failed, and had its
                # reads misattributed to "Anonymous".
                auth_header = request.headers["authorization"]
                token = auth_header[7:] if auth_header.lower().startswith("bearer ") else auth_header
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
            # Fail open: the audit write is a plain file append with no
            # error handling of its own, so a failure here (disk full,
            # read-only temp dir) must not turn the read itself into
            # a 500 — the handler runs either way, mirroring the
            # Redis cache middleware's fail-open behaviour.
            # Attribute the entry to the effective request tenant set by
            # TenantMiddleware (subdomain/custom domain/X-Tenant-ID),
            # falling back to the user's home tenant on the host scope —
            # mirroring the Redis cache middleware's effective-tenant
            # key. Attributing to the user's tenant alone put reads
            # performed under another tenant's scope into the wrong
            # tenant's audit file.
            effective_tenant_id = getattr(request.state, "tenant_id", None)
            tenant_id = str(effective_tenant_id) if effective_tenant_id else (str(current_user.tenant_id) if current_user and current_user.tenant_id else None)
            # Run the handler first and only then record the read: the
            # entry was previously written before call_next, so a denied
            # or failed read (401/403/404/500) was still recorded as a
            # successful "read" — misleading for an audit trail — and a
            # listing read logged itself into the page it just returned.
            # A handler exception still propagates as before; it simply
            # leaves no "read" entry behind.
            response = await call_next(request)
            if 200 <= response.status_code < 300:
                try:
                    await capture_audit_log(AuditLogDto(
                        action="read",
                        entity=entity,
                        user_id=str(current_user.id) if current_user else "Anonymous",
                        changes={"info": f"Read access to {request.url.path}"},
                        tenant_id=tenant_id
                    ))
                except Exception as e:
                    logger.warning(f"Audit log write failed, continuing without it: {e}")
            return response

        return await call_next(request)
        