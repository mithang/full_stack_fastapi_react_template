from fastapi import APIRouter, Depends, Response

from api.common.exceptions import ForbiddenException
from api.core.container import get_audit_logs_service, get_passkey_service
from api.domain.dtos.audit_logs_dto import AuditLogDto
from api.domain.dtos.passkey_dto import RegisteredPasskeyCredentialsDto
from api.infrastructure.security.current_user import CurrentUser
from api.infrastructure.security.passkey_service import PasskeyService
from api.interfaces.middlewares.tenant_middleware import get_tenant_id
from api.usecases.audit_logs_service import AuditLogsService


router = APIRouter(prefix="/security")
router.tags = ["Manage Security"]


def _assert_passkey_scope(current_user: CurrentUser, request_tenant_id) -> None:
    # Read/delete-in-wrong-DB guard, mirroring the AI history guard:
    # passkey reads and deletes are keyed by email only
    # (PasskeyService.get_registered_passkeys /
    # delete_registered_passkey look up UserPasskey by user_email)
    # in the current DB, with no tenant filter, and UserPasskey
    # carries no tenant_id. So a tenant caller without a tenant DB
    # selected (no X-Tenant-ID/subdomain, hitting the host DB)
    # would read — and could delete — host-DB passkey records
    # matching their email (normally empty, but an email collision
    # across DBs would expose another user's credentials and let
    # the caller delete them), instead of their own tenant
    # passkeys. Legitimate tenant calls go through ApiClient,
    # which sends X-Tenant-ID whenever a tenant is selected, so
    # the middleware scope equals their tenant id; host callers
    # (tenant_id None) are unaffected. The delete endpoint reuses
    # this guard: the failure mode (acting on the wrong DB's
    # email-keyed record) is identical to the read.
    if current_user.tenant_id is not None and (
        request_tenant_id is None or str(request_tenant_id) != str(current_user.tenant_id)
    ):
        raise ForbiddenException("Passkeys cannot be accessed outside your tenant's scope.")

@router.get("/passkeys", response_model=list[RegisteredPasskeyCredentialsDto], status_code=200)
async def get_registered_passkeys(
    response: Response,
    current_user: CurrentUser,
    passkey_service: PasskeyService = Depends(get_passkey_service),
    audit_log_service: AuditLogsService = Depends(get_audit_logs_service),
    request_tenant_id = Depends(get_tenant_id),

):
    """
    Endpoint to retrieve registered passkeys for the current user.
    """
    # This GET writes a read audit log and returns the user's passkey
    # credentials, so it must never be served from a browser or proxy
    # cache: a cached 200 would replay without running the handler,
    # silently skipping the audit entry for a credential read — the
    # same no-store hardening as the state-changing GETs in the
    # account controller (logout, magic-link validation) and the
    # tenant check_dns GET. Payload and audit content unchanged.
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"

    _assert_passkey_scope(current_user, request_tenant_id)
    passkeys = await passkey_service.get_registered_passkeys(email=current_user.email)
    res = [RegisteredPasskeyCredentialsDto(**pk.model_dump()) for pk in passkeys]
    await audit_log_service.create_audit_log(
        audit_log=AuditLogDto(
            entity="Passkey",
            action="read",
            changes={"Info": f"Retrieved {len(res)} passkeys for user {current_user.email}."},
            user_id=current_user.id,
            tenant_id=current_user.tenant_id
        )   
    )
    return res


@router.delete("/passkeys/{credential_id}", status_code=204)
async def delete_registered_passkey(
    credential_id: str,
    current_user: CurrentUser,
    passkey_service: PasskeyService = Depends(get_passkey_service),
    audit_log_service: AuditLogsService = Depends(get_audit_logs_service),
    request_tenant_id = Depends(get_tenant_id)
):
    """
    Endpoint to delete a registered passkey for the current user.
    """
    _assert_passkey_scope(current_user, request_tenant_id)
    # Strip before the lookup: delete_registered_passkey filters the
    # stored credentials by exact credential_id match, so a padded id
    # (copied/pasted, %20-encoded in the path) passed the scope check
    # yet raised "Credential ID not found" for a credential that
    # exists, leaving the user unable to delete it. Credential ids
    # are base64url values that never legitimately carry surrounding
    # whitespace, so stripping here covers both the lookup and the
    # audit-log text below; clean ids are unchanged and a
    # whitespace-only id still fails with the same error.
    credential_id = credential_id.strip()
    try:
        await passkey_service.delete_registered_passkey(
            email=current_user.email,
            credential_id=credential_id
        )
        await audit_log_service.create_audit_log(
            audit_log=AuditLogDto(
                entity="Passkey",
                action="delete",
                changes={"Info": f"Deleted passkey {credential_id} for user {current_user.email}."},
                user_id=current_user.id,
                tenant_id=current_user.tenant_id
            )   
        )
    except Exception as e:
        await audit_log_service.create_audit_log(
           audit_log=AuditLogDto(
               entity="Passkey",
               action="error",
               changes={"Info": f"Failed to delete passkey {credential_id} for user {current_user.email}."},
               user_id=current_user.id,
               tenant_id=current_user.tenant_id
           )   
        )
        raise e
    return None
