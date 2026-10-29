from fastapi import APIRouter, Depends, Response

from api.common.exceptions import ForbiddenException
from api.core.container import get_billing_record_service
from api.domain.dtos.billing_dto import InvoiceListDto
from api.domain.enum.feature import Feature
from api.domain.enum.permission import Permission
from api.domain.security.feature_access_management import check_feature_access
from api.infrastructure.security.current_user import CurrentUser
from api.interfaces.middlewares.tenant_middleware import get_tenant_id
from api.interfaces.security.role_checker import check_permissions_for_current_role
from api.usecases.billing_record_service import BillingRecordService


def _assert_read_scope(current_user: CurrentUser, request_tenant_id) -> None:
    # Read-in-wrong-scope guard, mirroring the product/plan write
    # guards (iterations 886-888): invoice listing is a Stripe-object
    # read, not a DB record, but its scope still comes from the
    # current DB — the tenant Stripe resolver reads the singleton
    # settings record in the current DB with no tenant filter. So a
    # tenant caller without a tenant DB selected (no X-Tenant-ID /
    # subdomain, hitting the host DB) would list invoices from the
    # HOST Stripe account (scope "tenant" from the caller's
    # tenant_id, keys from the host singleton) — a financial-records
    # leak to a tenant admin, not just a wrong catalog. Legitimate
    # tenant invoice listing happens with the middleware scope equal
    # to the caller's tenant id, and host callers (tenant_id None)
    # are unaffected. A mismatched scope fails closed rather than
    # serving another account's invoices.
    if current_user.tenant_id is not None and (
        request_tenant_id is None or str(request_tenant_id) != str(current_user.tenant_id)
    ):
        raise ForbiddenException("Invoices cannot be listed outside your tenant's scope.")


router = APIRouter(
    prefix="/invoices", 
    dependencies=[
        Depends(check_feature_access(feature_name=Feature.STRIPE)),
        Depends(check_permissions_for_current_role(required_permissions=[Permission.MANAGE_BILLING]))
    ]
)
router.tags = ["Stripe - Invoices"]

@router.get("/", summary="List invoices", response_model=InvoiceListDto)
async def list_invoices(
    response: Response,
    current_user: CurrentUser,
    billing_service: BillingRecordService = Depends(get_billing_record_service),
    request_tenant_id = Depends(get_tenant_id)
):
    _assert_read_scope(current_user, request_tenant_id)
    # Financial records: a browser/proxy-cached 200 could serve one
    # tenant's invoices to another admin after an account switch, or
    # hide freshly written invoices — same class as the /checkouts/all
    # fix in the previous iteration.
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    scope = "host"
    if current_user.tenant_id:
        scope = "tenant"

    return await billing_service.list_invoices(scope=scope)
    
    