from fastapi import APIRouter, Depends, Response, status

from api.common.exceptions import ForbiddenException
from api.common.utils import get_logger
from api.core.container import get_billing_record_service
from api.domain.dtos.billing_dto import CreatePlanDto,  PlanDto, PlanListDto, UpdatePlanDto
from api.domain.enum.feature import Feature
from api.domain.enum.permission import Permission
from api.domain.security.feature_access_management import check_feature_access
from api.infrastructure.security.current_user import CurrentUser, CurrentUserOptional
from api.interfaces.middlewares.tenant_middleware import get_tenant_id
from api.interfaces.security.role_checker import check_permissions_for_current_role
from api.usecases.billing_record_service import BillingRecordService

logger = get_logger(__name__)


def _assert_create_scope(current_user: CurrentUser, request_tenant_id) -> None:
    # Write-in-wrong-scope guard, mirroring the product/price guards
    # (iterations 886-887): plan writes are Stripe-object writes, not
    # DB records, but their scope still comes from the current DB —
    # the tenant Stripe resolver reads the singleton settings record
    # in the current DB with no tenant filter. So a tenant caller
    # without a tenant DB selected (no X-Tenant-ID/subdomain, hitting
    # the host DB) would create, update or delete plans in the HOST
    # Stripe account (scope "tenant" from the caller's tenant_id,
    # keys from the host singleton), polluting the host catalog and
    # hiding the objects from the caller's own tenant Stripe account.
    # Legitimate tenant plan management happens with the middleware
    # scope equal to the caller's tenant id, and host callers
    # (tenant_id None) are unaffected. A mismatched scope fails closed
    # rather than writing into the wrong Stripe account.
    if current_user.tenant_id is not None and (
        request_tenant_id is None or str(request_tenant_id) != str(current_user.tenant_id)
    ):
        raise ForbiddenException("Plans cannot be managed outside your tenant's scope.")

router = APIRouter(prefix="/billing", dependencies=[Depends(check_feature_access(feature_name=Feature.STRIPE))])
router.tags = ["Stripe - Billing"]

@router.get("/plans", summary="List available plans", response_model=PlanListDto)
async def list_plans(
    response: Response,
    current_user_optional: CurrentUserOptional,
    billing_service: BillingRecordService = Depends(get_billing_record_service)
):
    scope = "host"
    if current_user_optional and current_user_optional.tenant_id:
        scope = "tenant"

    # The list is scope-dependent (host vs tenant), so it must not
    # be served from a browser or proxy cache: a cached 200 could
    # show one scope's plans to another user after an account switch
    # on a shared machine, or hide freshly created/updated plans —
    # the same no-store hardening as the tenant list GET.
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    logger.debug(f"Listing plans for scope: {scope}")
    return await billing_service.list_plans(scope=scope)

@router.get("/plans/{plan_id:path}", summary="Retrieve a plan details", response_model=PlanDto)
async def get_plan(
    response: Response,
    plan_id: str,
    current_user_optional: CurrentUserOptional,
    billing_service: BillingRecordService = Depends(get_billing_record_service)
):
    scope = "host"
    if current_user_optional and current_user_optional.tenant_id:
        scope = "tenant"

    # The detail is scope-dependent (host vs tenant), like the plan
    # list hardened in the previous iteration, so it must not be
    # served from a browser or proxy cache: a cached 200 could show
    # one scope's plan to another user after an account switch on a
    # shared machine, or hide a freshly updated plan.
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return await billing_service.get_plan(plan_id=plan_id, scope=scope)


@router.delete("/plans/{plan_id:path}", summary="Delete existing plan", status_code=status.HTTP_202_ACCEPTED)
async def delete_plan(
    plan_id: str,
    current_user: CurrentUser,
    # Mutating plan endpoints require manage:billing, mirroring the
    # /checkouts/all list and invoice endpoints: products/prices
    # require manage:products_and_pricing at router level, but plans
    # had no permission check at all, so any authenticated user could
    # create, update or delete a Stripe plan. The read endpoints
    # above stay open on purpose (the pricing page lists plans for
    # visitors), and the frontend billing UI is already gated on
    # manage:billing, so legitimate plan managers are unaffected.
    _bool: bool = Depends(check_permissions_for_current_role(required_permissions=[Permission.MANAGE_BILLING])),
    billing_service: BillingRecordService = Depends(get_billing_record_service),
    request_tenant_id = Depends(get_tenant_id)
):
    _assert_create_scope(current_user, request_tenant_id)
    scope = "host"
    if current_user.tenant_id:
        scope = "tenant"

    return await billing_service.delete_plan(plan_id=plan_id, scope=scope)


@router.post("/plans", summary="Create a new plan", status_code=status.HTTP_201_CREATED)
async def create_plan(
    new_plan: CreatePlanDto,
    current_user: CurrentUser,
    _bool: bool = Depends(check_permissions_for_current_role(required_permissions=[Permission.MANAGE_BILLING])),
    billing_service: BillingRecordService = Depends(get_billing_record_service),
    request_tenant_id = Depends(get_tenant_id)
):
    _assert_create_scope(current_user, request_tenant_id)
    scope = "host"
    if current_user.tenant_id:
        scope = "tenant"

    await billing_service.create_plan(new_plan=new_plan, scope=scope)


@router.patch("/plans/{plan_id:path}", summary="Update a existing plan", status_code=status.HTTP_204_NO_CONTENT)
async def update_plan(
    plan_id: str,
    updated_plan: UpdatePlanDto,
    current_user: CurrentUser,
    _bool: bool = Depends(check_permissions_for_current_role(required_permissions=[Permission.MANAGE_BILLING])),
    billing_service: BillingRecordService = Depends(get_billing_record_service),
    request_tenant_id = Depends(get_tenant_id)
):
    _assert_create_scope(current_user, request_tenant_id)
    scope = "host"
    if current_user.tenant_id:
        scope = "tenant"

    await billing_service.update_plan(plan_id=plan_id, update_plan=updated_plan, scope=scope)



