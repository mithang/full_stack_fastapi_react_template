from fastapi import APIRouter, Response, status
from fastapi.params import Depends

from api.common.exceptions import ForbiddenException
from api.core.container import get_pricing_service
from api.domain.dtos.pricing_dto import CreatePricingDto, PricingListDto, UpdatePricingDto
from api.domain.enum.feature import Feature
from api.domain.enum.permission import Permission
from api.domain.security.feature_access_management import check_feature_access
from api.infrastructure.security.current_user import CurrentUser
from api.interfaces.middlewares.tenant_middleware import get_tenant_id
from api.interfaces.security.role_checker import check_permissions_for_current_role
from api.usecases.pricing_service import PricingService


def _assert_create_scope(current_user: CurrentUser, request_tenant_id) -> None:
    # Write-in-wrong-scope guard, mirroring the product guard
    # (iteration 886): price writes are Stripe-object writes, not DB
    # records, but their scope still comes from the current DB — the
    # tenant Stripe resolver reads the singleton settings record in
    # the current DB with no tenant filter. So a tenant caller
    # without a tenant DB selected (no X-Tenant-ID/subdomain, hitting
    # the host DB) would create or update prices in the HOST Stripe
    # account (scope "tenant" from the caller's tenant_id, keys from
    # the host singleton), polluting the host catalog and hiding the
    # objects from the caller's own tenant Stripe account.
    # Legitimate tenant price management happens with the middleware
    # scope equal to the caller's tenant id, and host callers
    # (tenant_id None) are unaffected. A mismatched scope fails closed
    # rather than writing into the wrong Stripe account.
    if current_user.tenant_id is not None and (
        request_tenant_id is None or str(request_tenant_id) != str(current_user.tenant_id)
    ):
        raise ForbiddenException("Prices cannot be managed outside your tenant's scope.")


def _assert_read_scope(current_user: CurrentUser, request_tenant_id) -> None:
    # Read-in-wrong-scope guard, mirroring the product guard
    # (iteration 892): the price list is a Stripe-object read, not a
    # DB record, but its scope still comes from the current DB — the
    # tenant Stripe resolver reads the singleton settings record in
    # the current DB with no tenant filter. So a tenant caller
    # without a tenant DB selected (no X-Tenant-ID / subdomain,
    # hitting the host DB) would list the HOST Stripe account's
    # prices (scope "tenant" from the caller's tenant_id, keys from
    # the host singleton) — a catalog leak to a tenant admin, not
    # just a wrong catalog. Legitimate tenant price browsing happens
    # with the middleware scope equal to the caller's tenant id, and
    # host callers (tenant_id None) are unaffected. A mismatched
    # scope fails closed rather than serving another account's
    # catalog.
    if current_user.tenant_id is not None and (
        request_tenant_id is None or str(request_tenant_id) != str(current_user.tenant_id)
    ):
        raise ForbiddenException("Prices cannot be listed outside your tenant's scope.")


router = APIRouter(
    prefix="/prices",
    dependencies=[
        Depends(check_feature_access(feature_name=Feature.STRIPE)),
        Depends(check_permissions_for_current_role(required_permissions=[Permission.MANAGE_PRODUCTS_AND_PRICING]))
    ]

)
router.tags = ["Stripe - Pricing"]

@router.get("/", response_model=PricingListDto)
async def get_pricing_list(
    response: Response,
    current_user: CurrentUser,
    pricing_service: PricingService = Depends(get_pricing_service),
    request_tenant_id = Depends(get_tenant_id)
):
    _assert_read_scope(current_user, request_tenant_id)
    # The list is scope-dependent (host vs tenant), so it must not
    # be served from a browser or proxy cache: a cached 200 could
    # show one scope's prices to another user after an account switch
    # on a shared machine, or hide freshly created prices — the same
    # no-store hardening as the billing plan list GET.
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    scope = "tenant" if current_user.tenant_id else "host"
    return await pricing_service.list_prices(scope=scope)


@router.post("/", status_code=status.HTTP_201_CREATED)
async def create_pricing(
    pricing: CreatePricingDto,
    current_user: CurrentUser,
    pricing_service: PricingService = Depends(get_pricing_service),
    request_tenant_id = Depends(get_tenant_id)
):
    _assert_create_scope(current_user, request_tenant_id)
    scope = "tenant" if current_user.tenant_id else "host"
    await pricing_service.create_price(scope=scope, price=pricing)
    return status.HTTP_201_CREATED


@router.patch("/{price_id:path}", status_code=status.HTTP_204_NO_CONTENT)
async def update_pricing(
    price_id: str,
    pricing: UpdatePricingDto,
    current_user: CurrentUser,
    pricing_service: PricingService = Depends(get_pricing_service),
    request_tenant_id = Depends(get_tenant_id)
):
    _assert_create_scope(current_user, request_tenant_id)
    scope = "tenant" if current_user.tenant_id else "host"
    await pricing_service.update_price(price_id=price_id, scope=scope, update=pricing)
    return status.HTTP_204_NO_CONTENT
