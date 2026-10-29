from fastapi import APIRouter, Depends, Query, Response, status
from api.common.exceptions import ForbiddenException, InvalidOperationException
from api.core.container import get_billing_record_service, get_tenant_service
from api.domain.dtos.billing_dto import BillingRecordListDto
from api.domain.dtos.checkout_dto import CheckoutRequestDto, CheckoutResponseDto
from api.domain.enum.feature import Feature
from api.domain.enum.permission import Permission
from api.domain.security.feature_access_management import check_feature_access
from api.infrastructure.security.current_user import CurrentUser
from api.interfaces.middlewares.tenant_middleware import get_tenant_id
from api.interfaces.security.role_checker import check_permissions_for_current_role
from api.usecases.billing_record_service import BillingRecordService
from api.usecases.tenant_service import TenantService

from api.common.utils import get_host_main_domain_name, get_logger

logger = get_logger(__name__)


def _safe_log_value(value) -> str:
    # CheckoutRequestDto.tenant_id is a plain str (JSON body, so a
    # newline survives as \n in the string), and the success/cancel
    # tenant_id is a Query str that Starlette percent-decodes — so a
    # mismatched tenant_id could otherwise forge extra log lines
    # (same class as the account-endpoint fixes in iterations 955 and
    # 958). Only the logged/exception-message copy is flattened; the
    # mismatch checks still use the raw value, and the ApiBaseException
    # handler logs ex.message verbatim, so a raw id in the raise would
    # re-expose it even where the logger line is sanitized. The email
    # fields need no such treatment: they are EmailStr-validated.
    return str(value).replace("\r", " ").replace("\n", " ")


def _assert_create_scope(current_user: CurrentUser, request_tenant_id) -> None:
    # Write-in-wrong-scope guard, mirroring the product/price/plan
    # guards (iterations 886-888): a tenant checkout session is a
    # Stripe-object write (customer + session), not just a DB record,
    # but its scope still comes from the current DB — the tenant
    # Stripe resolver reads the singleton settings record in the
    # current DB with no tenant filter. So a tenant caller without a
    # tenant DB selected (no X-Tenant-ID/subdomain, hitting the host
    # DB) would create the customer and session in the WRONG Stripe
    # account and save the billing record in the host DB, hiding the
    # session from the caller's own tenant account. Legitimate tenant
    # checkout happens with the middleware scope equal to the caller's
    # tenant id, and host callers (tenant_id None) are unaffected —
    # they still hit the existing tenant-required error below. A
    # mismatched scope fails closed rather than writing into the
    # wrong Stripe account. The host checkout endpoint above is
    # deliberately not guarded: it is host-scope by design (host
    # Stripe keys, host record), regardless of which DB serves it.
    if current_user.tenant_id is not None and (
        request_tenant_id is None or str(request_tenant_id) != str(current_user.tenant_id)
    ):
        raise ForbiddenException(
            "Tenant checkout sessions cannot be created outside your tenant's scope."
        )


def _assert_list_scope(current_user: CurrentUser, request_tenant_id) -> None:
    # List-in-wrong-DB guard, mirroring the roles list guard
    # (iteration 927) and the Stripe settings read guard (iteration
    # 932): the service already scopes the list to the caller's
    # tenant stamp, but it does not check which database served the
    # request. So a tenant caller listing on the host DB (no
    # X-Tenant-ID/subdomain, request scope None) could still read
    # tenant-stamped checkout records sitting in the host DB (e.g.
    # planted before the create guard) — financial records, not just
    # names. Legitimate tenant record lists happen in the caller's
    # own tenant DB, where the middleware scope equals their tenant
    # id (the frontend ApiClient sends X-Tenant-ID), and host callers
    # (tenant_id None) are unaffected. A mismatched scope fails
    # closed before any read.
    if current_user.tenant_id is not None and (
        request_tenant_id is None or str(request_tenant_id) != str(current_user.tenant_id)
    ):
        raise ForbiddenException(
            "Checkout records cannot be listed outside your tenant's scope."
        )


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
            logger.error(f"Tenant ID mismatch for the current user. And current user's tenant id is: {current_user.tenant_id} and requested tenant id is: {_safe_log_value(checkout_req.tenant_id)}")
            raise InvalidOperationException(f"Tenant ID mismatch for the current user. {_safe_log_value(checkout_req.tenant_id)}")

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
    billing_service: BillingRecordService = Depends(get_billing_record_service),
    request_tenant_id = Depends(get_tenant_id)
):
    _assert_create_scope(current_user, request_tenant_id)
    if current_user and current_user.tenant_id is not None:
        if checkout_req.tenant_id != current_user.tenant_id:
            logger.error(f"Tenant ID mismatch for the current user. And current user's tenant id is: {current_user.tenant_id} and requested tenant id is: {_safe_log_value(checkout_req.tenant_id)}")
            raise InvalidOperationException(f"Tenant ID mismatch for the current user. {_safe_log_value(checkout_req.tenant_id)}")

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
        logger.error(f"Tenant ID mismatch for the current user. And current user's tenant id is: {current_user.tenant_id} and requested tenant id is: {_safe_log_value(tenant_id)}")
        raise InvalidOperationException(f"Tenant ID mismatch for the current user. {_safe_log_value(tenant_id)}")

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
        logger.error(f"Tenant ID mismatch for the current user. And current user's tenant id is: {current_user.tenant_id} and requested tenant id is: {_safe_log_value(tenant_id)}")
        raise InvalidOperationException(f"Tenant ID mismatch for the current user. {_safe_log_value(tenant_id)}")

    await billing_service.handle_host_checkout_canceled(tenant_id=current_user.tenant_id)
    return status.HTTP_202_ACCEPTED


@router.post("/tenant/payment/success", status_code=status.HTTP_202_ACCEPTED)
async def tenant_checkout_success(
    session_id: str,
    current_user: CurrentUser,
    billing_service: BillingRecordService = Depends(get_billing_record_service),
    request_tenant_id = Depends(get_tenant_id)
):
    # Same wrong-scope guard as session creation (iteration 889):
    # the success handler retrieves the session through the tenant
    # Stripe resolver, which reads the singleton settings record in
    # the current DB with no tenant filter, and finalises the record
    # in the current DB. A tenant caller without a tenant DB selected
    # (no X-Tenant-ID/subdomain, hitting the host DB) previously
    # reached that retrieve — failing only incidentally as a Stripe
    # 404, since the session lives in the tenant's Stripe account —
    # instead of failing fast with a clear scope error. The service's
    # record-level tenant/user checks already blocked cross-tenant
    # finalisation, so this guard changes the failure mode, not the
    # outcome, for mismatched callers; legitimate tenant finalisation
    # (middleware scope == caller tenant, as ApiClient sends) and host
    # callers (still hit the tenant-required error below) are unchanged.
    _assert_create_scope(current_user, request_tenant_id)
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
    billing_service: BillingRecordService = Depends(get_billing_record_service),
    request_tenant_id = Depends(get_tenant_id)
):
    # Same wrong-scope guard as the success endpoint above: cancel
    # marks records in the current DB, so a tenant caller without a
    # tenant DB selected previously reached the service and canceled
    # only records already (wrongly) planted in the host DB, while a
    # legitimate cancel in the tenant DB was never reached. Fail fast
    # here instead; legitimate tenant cancels (middleware scope ==
    # caller tenant) and host callers (still hit the tenant-required
    # error below) are unchanged.
    _assert_create_scope(current_user, request_tenant_id)
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
    response: Response,
    current_user: CurrentUser,
    # The frontend defaults to limit 10, but a direct API call passed
    # skip/limit straight into the DB query unbounded, so a single request
    # could dump the whole checkout-record table (limit=1000000) or pass
    # negative values; out-of-range values now fail fast with a 422.
    # Default limit 100 preserved (unlike the limit-10 list endpoints).
    skip: int = Query(0, ge=0, le=10000), limit: int = Query(100, ge=1, le=100),
    _bool: bool = Depends(check_permissions_for_current_role(required_permissions=[Permission.MANAGE_BILLING])),
    billing_service: BillingRecordService = Depends(get_billing_record_service),
    request_tenant_id = Depends(get_tenant_id)
):
    _assert_list_scope(current_user, request_tenant_id)
    # Financial records: a browser/proxy-cached 200 could serve one
    # tenant's billing records to another admin after an account
    # switch, or hide freshly written records — same class as the
    # /audit-logs fix in the previous iteration.
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    # Scope to the caller's tenant: tenant requests normally hit the
    # tenant database (TenantMiddleware), but a tenant user calling
    # without a tenant DB selected (no X-Tenant-ID/subdomain) would
    # otherwise read the host database's full checkout-record table.
    # Host callers (tenant_id None) keep the global view, the same
    # scope rule as the GET /users/ list.
    return await billing_service.list_checkout_records(skip=skip, limit=limit, tenant_id=current_user.tenant_id)

