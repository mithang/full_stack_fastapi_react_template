from fastapi import APIRouter, Depends, Query, status
from api.common.exceptions import InvalidOperationException
from api.core.container import get_billing_record_service, get_tenant_service
from api.domain.dtos.billing_dto import BillingRecordListDto
from api.domain.dtos.checkout_dto import CheckoutRequestDto, CheckoutResponseDto
from api.domain.enum.feature import Feature
from api.domain.enum.permission import Permission
from api.domain.security.feature_access_management import check_feature_access
from api.infrastructure.security.current_user import CurrentUser
from api.interfaces.security.role_checker import check_permissions_for_current_role
from api.usecases.billing_record_service import BillingRecordService
from api.usecases.tenant_service import TenantService

from api.common.utils import get_host_main_domain_name, get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/checkouts", dependencies=[
    Depends(check_feature_access(feature_name=Feature.STRIPE)),
])
router.tags = ["Stripe - Checkout"]

@router.post("/host/{tenant_id:path}/tenant", response_model=CheckoutResponseDto)
async def create_host_checkout_session(
    checkout_req: CheckoutRequestDto,
    current_user: CurrentUser,
    billing_service: BillingRecordService = Depends(get_billing_record_service)
):
    if current_user and current_user.tenant_id is not None:
        if checkout_req.tenant_id != current_user.tenant_id:
            logger.error(f"Tenant ID mismatch for the current user. And current user's tenant id is: {current_user.tenant_id} and requested tenant id is: {checkout_req.tenant_id}")
            raise InvalidOperationException(f"Tenant ID mismatch for the current user. {checkout_req.tenant_id}")

        # Mirror the tenant checkout session endpoint below: the Stripe
        # customer for this session is created with checkout_req.email,
        # so without this check a caller could create a host-scope
        # session (and its billing record) under someone else's email.
        # Legitimate callers pass their own email, as the tenant
        # endpoint already requires.
        if current_user.email != checkout_req.email:
            logger.error(f"Email mismatch for the current user. And current user's email is: {current_user.email} and requested email is: {checkout_req.email}")
            raise InvalidOperationException(f"Email mismatch for the current user. {checkout_req.email}")

        host_main_domain = f"https://{get_host_main_domain_name()}"
        url = await billing_service.create_host_check_out_session_for_tenant(frontend_url=host_main_domain, checkout_req=checkout_req)
        return CheckoutResponseDto(checkout_url=url)

    # A host checkout session is created for a tenant (see
    # create_host_check_out_session_for_tenant), so a caller without a
    # tenant — a host user, whose tenant_id is None — previously fell
    # through this function with no return, and FastAPI's
    # CheckoutResponseDto validation of None failed as a 500 instead
    # of a mapped API error. Fail fast with the same
    # InvalidOperationException the mismatch check above uses; tenant
    # callers return above and are unchanged.
    raise InvalidOperationException("A tenant is required to create a host checkout session.")


@router.post("/tenant/subscription", response_model=CheckoutResponseDto)
async def create_tenant_checkout_session(
    checkout_req: CheckoutRequestDto,
    current_user: CurrentUser,
    tenant_service: TenantService = Depends(get_tenant_service),
    billing_service: BillingRecordService = Depends(get_billing_record_service)
):
    if current_user and current_user.tenant_id is not None:
        if checkout_req.tenant_id != current_user.tenant_id:
            logger.error(f"Tenant ID mismatch for the current user. And current user's tenant id is: {current_user.tenant_id} and requested tenant id is: {checkout_req.tenant_id}")
            raise InvalidOperationException(f"Tenant ID mismatch for the current user. {checkout_req.tenant_id}")

    # A tenant checkout session is created for the caller's tenant, so a
    # caller without a tenant — a host user, whose tenant_id is None —
    # previously skipped the mismatch check above and fell through to
    # get_tenant_by_id(None), surfacing as a misleading "Tenant None
    # not found" 404 instead of a clear error. Fail fast with the same
    # InvalidOperationException the host checkout fix (previous
    # iteration) uses; tenant callers are unchanged, and no Stripe
    # call is made for the rejected caller.
    if current_user.tenant_id is None:
        raise InvalidOperationException("A tenant is required to create a tenant checkout session.")

    if current_user.email != checkout_req.email:
        logger.error(f"Email mismatch for the current user. And current user's email is: {current_user.email} and requested email is: {checkout_req.email}")
        raise InvalidOperationException(f"Email mismatch for the current user. {checkout_req.email}")

    tenant = await tenant_service.get_tenant_by_id(current_user.tenant_id)
    # A tenant may have neither a custom domain nor a subdomain (both
    # nullable on the entity), in which case the old code produced
    # frontend_url "https://None" as the Stripe checkout return URL —
    # the same neither-domain class fixed for magic-link/passkey/SSO
    # in earlier iterations. Fall back to the main domain; custom-domain
    # and subdomain tenants are unchanged.
    domain = tenant.custom_domain or tenant.subdomain or get_host_main_domain_name()
    frontend_url = f"https://{domain}"
    url = await billing_service.create_tenant_check_out_session_for_tenant_users(
        frontend_url=frontend_url,
        user_id=current_user.id,
        checkout_req=checkout_req
    )
    return CheckoutResponseDto(checkout_url=url)



@router.post("/host/payment/success", status_code=status.HTTP_202_ACCEPTED)
async def host_checkout_success(
    session_id: str,
    tenant_id: str,
    current_user: CurrentUser,
    billing_service: BillingRecordService = Depends(get_billing_record_service)
):
    # A host payment success finalises the caller's tenant-scope
    # record, so a caller without a tenant — a host user, whose
    # tenant_id is None — previously failed closed only incidentally
    # through the mismatch check below (None never equals the query
    # tenant_id), surfacing as a misleading "Tenant ID mismatch"
    # error. Fail fast with the explicit tenant-required error the
    # tenant success/cancel endpoints use; tenant callers still hit
    # the mismatch check below unchanged, and no Stripe call is made
    # for the rejected caller.
    if current_user.tenant_id is None:
        raise InvalidOperationException("A tenant is required to confirm a host checkout session.")
    if current_user.tenant_id != tenant_id:
        logger.error(f"Tenant ID mismatch for the current user. And current user's tenant id is: {current_user.tenant_id} and requested tenant id is: {tenant_id}")
        raise InvalidOperationException(f"Tenant ID mismatch for the current user. {tenant_id}")

    await billing_service.handle_host_checkout_success(session_id=session_id, tenant_id=current_user.tenant_id)
    return status.HTTP_202_ACCEPTED


@router.post("/host/payment/cancel", status_code=status.HTTP_202_ACCEPTED)
async def host_checkout_canceled(
    tenant_id: str,
    current_user: CurrentUser,
    billing_service: BillingRecordService = Depends(get_billing_record_service)
):
    # Same explicit tenant-required guard as the host success
    # endpoint above: a tenant-less caller previously failed closed
    # only incidentally through the mismatch check, with a
    # misleading "Tenant ID mismatch" error. Tenant callers still
    # hit the mismatch check below unchanged, and no service call
    # is made for the rejected caller.
    if current_user.tenant_id is None:
        raise InvalidOperationException("A tenant is required to cancel a host checkout session.")
    if current_user.tenant_id != tenant_id:
        logger.error(f"Tenant ID mismatch for the current user. And current user's tenant id is: {current_user.tenant_id} and requested tenant id is: {tenant_id}")
        raise InvalidOperationException(f"Tenant ID mismatch for the current user. {tenant_id}")

    await billing_service.handle_host_checkout_canceled(tenant_id=current_user.tenant_id)
    return status.HTTP_202_ACCEPTED


@router.post("/tenant/payment/success", status_code=status.HTTP_202_ACCEPTED)
async def tenant_checkout_success(
    session_id: str,
    current_user: CurrentUser,
    billing_service: BillingRecordService = Depends(get_billing_record_service)
):
    # A tenant payment success finalises the caller's tenant-scope
    # record, so a caller without a tenant — a host user, whose
    # tenant_id is None — previously proceeded to a Stripe retrieve
    # that could only end in a tenant-mismatch error, since the
    # service's tenant guard fails closed on None. Fail fast with the
    # same InvalidOperationException the checkout-session endpoints
    # use, mirroring the iteration-377/378 guards; tenant callers are
    # unchanged, and no Stripe call is made for the rejected caller.
    if current_user.tenant_id is None:
        raise InvalidOperationException("A tenant is required to confirm a tenant checkout session.")
    await billing_service.handle_tenant_checkout_success(session_id=session_id, user_id=current_user.id, tenant_id=current_user.tenant_id)
    return status.HTTP_202_ACCEPTED


@router.post("/tenant/payment/cancel", status_code=status.HTTP_202_ACCEPTED)
async def tenant_checkout_canceled(
    current_user: CurrentUser,
    billing_service: BillingRecordService = Depends(get_billing_record_service)
):
    # A tenant payment cancel marks the caller's tenant-scope records
    # canceled, so a caller without a tenant — a host user, whose
    # tenant_id is None — previously returned 202 having canceled
    # nothing, since the service's tenant guard fails closed on None:
    # a silent success, the same class as the iteration-364/365 fixes.
    # Fail fast with the same InvalidOperationException the tenant
    # success guard above uses; tenant callers are unchanged.
    if current_user.tenant_id is None:
        raise InvalidOperationException("A tenant is required to cancel a tenant checkout session.")
    await billing_service.handle_tenant_checkout_canceled(user_id=current_user.id, tenant_id=current_user.tenant_id)
    return status.HTTP_202_ACCEPTED


@router.get("/all", response_model=BillingRecordListDto, status_code=status.HTTP_200_OK)
async def list_checkout_records(
    # The frontend defaults to limit 10, but a direct API call passed
    # skip/limit straight into the DB query unbounded, so a single request
    # could dump the whole checkout-record table (limit=1000000) or pass
    # negative values; out-of-range values now fail fast with a 422.
    # Default limit 100 preserved (unlike the limit-10 list endpoints).
    skip: int = Query(0, ge=0, le=10000), limit: int = Query(100, ge=1, le=100),
    _bool: bool = Depends(check_permissions_for_current_role(required_permissions=[Permission.MANAGE_BILLING])),
    billing_service: BillingRecordService = Depends(get_billing_record_service)
):
    return await billing_service.list_checkout_records(skip=skip, limit=limit)

