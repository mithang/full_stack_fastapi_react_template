from fastapi import APIRouter, Depends, Response, status
from fastapi.params import Query

from api.common.exceptions import ForbiddenException
from api.core.container import get_product_service
from api.domain.dtos.product_dto import CreateProductDto, ProductDto, ProductListDto
from api.domain.enum.feature import Feature
from api.domain.enum.permission import Permission
from api.domain.security.feature_access_management import check_feature_access
from api.infrastructure.security.current_user import CurrentUser
from api.interfaces.middlewares.tenant_middleware import get_tenant_id
from api.interfaces.security.role_checker import check_permissions_for_current_role
from api.usecases.product_service import ProductService


def _assert_create_scope(current_user: CurrentUser, request_tenant_id) -> None:
    # Write-in-wrong-scope guard, mirroring the Stripe settings
    # (iteration 884) and storage configure (iteration 885) guards:
    # product writes are Stripe-object writes, not DB records, but
    # their scope still comes from the current DB — the tenant Stripe
    # resolver reads the singleton settings record in the current DB
    # with no tenant filter. So a tenant caller without a tenant DB
    # selected (no X-Tenant-ID/subdomain, hitting the host DB) would
    # create, update or delete products in the HOST Stripe account
    # (scope "tenant" from the caller's tenant_id, keys from the host
    # singleton), polluting the host catalog and hiding the objects
    # from the caller's own tenant Stripe account. Legitimate tenant
    # product management happens with the middleware scope equal to
    # the caller's tenant id, and host callers (tenant_id None) are
    # unaffected. A mismatched scope fails closed rather than writing
    # into the wrong Stripe account.
    if current_user.tenant_id is not None and (
        request_tenant_id is None or str(request_tenant_id) != str(current_user.tenant_id)
    ):
        raise ForbiddenException("Products cannot be managed outside your tenant's scope.")


def _assert_read_scope(current_user: CurrentUser, request_tenant_id) -> None:
    # Read-in-wrong-scope guard, mirroring the invoice guard
    # (iteration 891): product listing/detail are Stripe-object
    # reads, not DB records, but their scope still comes from the
    # current DB — the tenant Stripe resolver reads the singleton
    # settings record in the current DB with no tenant filter. So a
    # tenant caller without a tenant DB selected (no X-Tenant-ID /
    # subdomain, hitting the host DB) would list the HOST Stripe
    # account's products (scope "tenant" from the caller's
    # tenant_id, keys from the host singleton) — a catalog leak to a
    # tenant admin, not just a wrong catalog. Legitimate tenant
    # product browsing happens with the middleware scope equal to
    # the caller's tenant id, and host callers (tenant_id None)
    # are unaffected. A mismatched scope fails closed rather than
    # serving another account's catalog.
    if current_user.tenant_id is not None and (
        request_tenant_id is None or str(request_tenant_id) != str(current_user.tenant_id)
    ):
        raise ForbiddenException("Products cannot be listed outside your tenant's scope.")


router = APIRouter(
    prefix="/products",
    dependencies=[
        Depends(check_feature_access(feature_name=Feature.STRIPE)),
        Depends(check_permissions_for_current_role(required_permissions=[Permission.MANAGE_PRODUCTS_AND_PRICING]))
    ]
)
router.tags = ["Stripe - Products"]

@router.get("/", summary="List Products", response_model=ProductListDto)
async def list_products(
    response: Response,
    current_user: CurrentUser,
    product_service: ProductService = Depends(get_product_service),
    active: bool = Query(default=True, description="Filter active products, defaults to True"),
    request_tenant_id = Depends(get_tenant_id)
):
    _assert_read_scope(current_user, request_tenant_id)
    # The list is scope-dependent (tenant vs host) and changes when
    # products are created/updated/deleted, so it must not be served
    # from a browser or proxy cache: a cached 200 could show one
    # tenant's products to another tenant after an account switch on a
    # shared machine, or hide a freshly created product — the same
    # no-store hardening as the GET /permissions/ list.
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    scope = "tenant" if current_user.tenant_id else "host"
    return await product_service.list_products(scope=scope, show_active=active)

@router.get("/{product_id:path}", summary="Get Product by ID", response_model=ProductDto)
async def get_product_by_id(
    response: Response,
    product_id: str,
    current_user: CurrentUser,
    product_service: ProductService = Depends(get_product_service),
    request_tenant_id = Depends(get_tenant_id)
):
    _assert_read_scope(current_user, request_tenant_id)
    # Same no-store hardening as the GET /products/ list: a single
    # product record is scope-dependent and changes on update/delete,
    # so a cached 200 could show one tenant's product to another tenant
    # after an account switch on a shared machine, or hide a fresh edit.
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    scope = "tenant" if current_user.tenant_id else "host"
    return await product_service.get_product_by_id(product_id=product_id, scope=scope)


@router.post("/", summary="Create a Product", status_code=status.HTTP_201_CREATED)
async def create_product(
    product_dto: CreateProductDto,
    current_user: CurrentUser,
    product_service: ProductService = Depends(get_product_service),
    request_tenant_id = Depends(get_tenant_id)
):
    _assert_create_scope(current_user, request_tenant_id)
    scope = "tenant" if current_user.tenant_id else "host"
    await product_service.create_product(product_dto=product_dto, scope=scope)
    return status.HTTP_201_CREATED
    


@router.patch("/{product_id:path}", summary="Update a Product", status_code=status.HTTP_204_NO_CONTENT)
async def update_product(
    product_id: str,
    product_dto: CreateProductDto,
    current_user: CurrentUser,
    product_service: ProductService = Depends(get_product_service),
    request_tenant_id = Depends(get_tenant_id)
):
    _assert_create_scope(current_user, request_tenant_id)
    scope = "tenant" if current_user.tenant_id else "host"
    await product_service.update_product(product_id=product_id, product_dto=product_dto, scope=scope)
    return status.HTTP_204_NO_CONTENT

@router.delete("/{product_id:path}", summary="Delete a Product", status_code=status.HTTP_202_ACCEPTED)
async def delete_product(
    product_id: str,
    current_user: CurrentUser,
    product_service: ProductService = Depends(get_product_service),
    request_tenant_id = Depends(get_tenant_id)
):
    _assert_create_scope(current_user, request_tenant_id)
    scope = "tenant" if current_user.tenant_id else "host"
    await product_service.delete_product(product_id=product_id, scope=scope)
    return status.HTTP_202_ACCEPTED
