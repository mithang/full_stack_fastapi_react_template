from typing import Dict, Optional
from fastapi import APIRouter, Depends, Query, Response, status

from api.common.dtos.download_dto import DownloadResponseDto
from api.common.dtos.worker_dto import WorkerPayloadDto
from api.common.exceptions import ForbiddenException, InvalidOperationException
from api.core.container import get_audit_logs_service
from api.domain.dtos.audit_logs_dto import AuditActionType, AuditLogListDto, DownloadAuditRequestDto
from api.domain.enum.permission import Permission
from api.infrastructure.security.current_user import CurrentUser
from api.interfaces.middlewares.tenant_middleware import get_tenant_id
from api.interfaces.security.role_checker import check_permissions_for_current_role
from api.usecases.audit_logs_service import AuditLogsService
from api.infrastructure.messaging.celery_worker import trigger_download_report


router = APIRouter(prefix="/audit-logs",  dependencies=[
        Depends(check_permissions_for_current_role(
            required_permissions=[
                Permission.AUDIT_LOGS_VIEW_ONLY

            ]
        )
    )]
   )


router.tags = ["Audit Logs"]


def _assert_audit_logs_scope(current_user: CurrentUser, request_tenant_id) -> None:
    # Read-in-wrong-DB guard, mirroring the dashboard metrics guard:
    # the list below is already filtered to the caller's tenant stamp,
    # but nothing checks which database served the request. So a
    # tenant caller hitting the host DB (no X-Tenant-ID/subdomain,
    # request scope None) would still read tenant-stamped audit
    # entries sitting in the host DB (e.g. written before the
    # audit-write path was tenant-scoped) — another tenant's audit
    # trail presented as their own. Legitimate tenant audit-log calls
    # go through ApiClient, which sends X-Tenant-ID whenever a tenant
    # is selected, so the middleware scope equals their tenant id;
    # host callers (tenant_id None) are unaffected. A mismatched
    # scope fails closed before any read runs.
    if current_user.tenant_id is not None and (
        request_tenant_id is None or str(request_tenant_id) != str(current_user.tenant_id)
    ):
        raise ForbiddenException("Audit logs cannot be read outside your tenant's scope.")


@router.get("/", response_model=AuditLogListDto, status_code=status.HTTP_200_OK)
async def list_audit_logs(
    response: Response,
    current_user: CurrentUser,
    limit: int = Query(10, ge=1, le=100),
    # Bound skip as well as limit: the repository keeps a deque of
    # skip + limit DTOs while scanning, so an unbounded skip let one
    # request force the server to hold an arbitrary number of entries
    # in memory. 10000 still covers 1000 pages at the default limit
    # (100 at the max limit); bulk export goes through /download.
    skip: int = Query(0, ge=0, le=10000),
    action: Optional[AuditActionType] = None,
    log_service: AuditLogsService = Depends(get_audit_logs_service),
    request_tenant_id = Depends(get_tenant_id)
):
    _assert_audit_logs_scope(current_user, request_tenant_id)
    # Audit entries are tenant-scoped admin data: a browser/proxy-cached
    # 200 could serve one tenant's audit trail to another admin after an
    # account switch, or hide freshly written entries. Never cache it.
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    tenant_id = str(current_user.tenant_id) if current_user.tenant_id else None
    return await log_service.read_audit_logs(tenant_id=tenant_id, limit=limit, skip=skip, action=action)

@router.post("/download", status_code=status.HTTP_202_ACCEPTED, response_model=DownloadResponseDto)
async def download_audit_logs(
    download_request: DownloadAuditRequestDto,
    current_user: CurrentUser,
    _bool: bool = Depends(check_permissions_for_current_role(required_permissions=[Permission.AUDIT_LOGS_DOWNLOAD]))
):
    if download_request.total_records <= 0:
        raise InvalidOperationException("Audit log download request must have at least one record.")

    payload = WorkerPayloadDto[Dict[str, str | None]](
        data={
            "action": download_request.action if download_request.action else None,
            "requested_by": str(current_user.id)
        },
        label="email-sending",
        tenant_id=str(current_user.tenant_id) if current_user.tenant_id else None
    )

    trigger_download_report.delay(payload.model_dump_json())
    return DownloadResponseDto(message="Download request has been received. You will receive an email once the report is ready.")


