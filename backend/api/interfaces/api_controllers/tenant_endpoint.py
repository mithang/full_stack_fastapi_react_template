from fastapi import APIRouter, Depends, Query, Response, status

from api.common.dtos.worker_dto import WorkerPayloadDto
from api.common.exceptions import ApiBaseException, ForbiddenException, InvalidOperationException
from api.common.utils import get_host_main_domain_name, get_logger, get_utc_now
from api.core.container import    get_billing_record_service, get_subscription_plan_service, get_tenant_service
from api.core.exceptions import InvalidSubdomainException, TenantNotFoundException
from api.domain.dtos.subcription_plan_dto import SubscriptionPlanDto
from api.domain.dtos.tenant_dto import CreateTenantResponseDto, FeatureDto, SubdomainAvailabilityDto, TenantDto, TenantListDto, CreateTenantDto, UpdateTenantDto, UpdateTenantResponseDto
from api.domain.dtos.user_dto import CreateUserDto
from api.domain.entities.tenant import Subdomain, Tenant
from api.domain.enum.feature import Feature
from api.domain.enum.permission import Permission
from api.domain.security.feature_access_management import check_feature_access
from api.infrastructure.security.current_user import CurrentUser
from api.interfaces.middlewares.tenant_middleware import get_tenant_id
from api.interfaces.security.role_checker import check_permissions_for_current_role
from api.usecases.billing_record_service import BillingRecordService
from api.usecases.subscription_plan_service import SubscriptionPlanService
from api.usecases.tenant_service import TenantService
from api.infrastructure.messaging.celery_worker import handle_post_tenant_creation, handle_post_tenant_deletion, handle_tenant_dns_update

logger = get_logger(__name__)

router = APIRouter(prefix="/tenants", tags=["Tenants"])


def _assert_update_scope(current_user: CurrentUser, request_tenant_id) -> None:
    # Update-in-wrong-DB guard, mirroring the user/role update guards
    # (iterations 905-907): update_dns already refuses a tenant_id
    # stamped for another tenant, but it does not check which database
    # served the request. So a tenant caller updating on the host DB
    # (no X-Tenant-ID/subdomain, request scope None) could still
    # overwrite the custom_domain / is_active of a tenant record
    # sitting in the host DB (e.g. planted before the create guard)
    # and enqueue its DNS-update job, while the real tenant DB record
    # is untouched. Legitimate tenant DNS updates happen in the
    # caller's own tenant DB, where the middleware scope equals their
    # tenant id (the frontend ApiClient sends X-Tenant-ID), and host
    # callers (tenant_id None) are unaffected. A mismatched scope fails
    # closed before any read, write, or job enqueue.
    if current_user.tenant_id is not None and (
        request_tenant_id is None or str(request_tenant_id) != str(current_user.tenant_id)
    ):
        raise ForbiddenException("Tenant DNS cannot be updated outside your tenant's scope.")

@router.get("/", response_model=TenantListDto, status_code=status.HTTP_200_OK)
async def list_tenants(
    response: Response,
    current_user: CurrentUser,
    skip: int = Query(0, ge=0, le=10000), limit: int = Query(10, ge=1, le=100),
    service: TenantService = Depends(get_tenant_service),
    _bool: bool = Depends(check_permissions_for_current_role(required_permissions=[Permission.HOST_MANAGE_TENANTS]))
):
    # The HOST_MANAGE_TENANTS gate also admits FULL_ACCESS holders (see
    # UserAccessManagement), and every tenant's seeded ADMIN role holds
    # FULL_ACCESS, so without this a tenant admin could enumerate every
    # tenant (names, subdomains, custom domains, subscription ids) via
    # this list. The frontend tenants page is host-only (App.tsx renders
    # it only when the user has no tenant_id), so scoping a tenant
    # caller to their own tenant loses no legitimate use; host callers
    # (tenant_id None) keep the full paginated list below.
    if current_user.tenant_id is not None:
        tenant = await service.get_tenant_by_id(tenant_id=current_user.tenant_id)
        return TenantListDto(
            tenants=[TenantDto(**tenant.model_dump())],
            skip=0, limit=1, total=1, has_previous=False, has_next=False,
        )
    # This GET returns the host-admin tenant list, so it must never be
    # served from a browser or proxy cache: a cached 200 could hide a
    # freshly created or deleted tenant, or serve one host admin's list
    # to another after an account switch on a shared machine — the same
    # no-store hardening as the /users/{user_id} and /configurations/stripe
    # GETs. Response is already imported in this module.
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return await service.list_tenants(skip=skip, limit=limit)

@router.post("/", response_model=CreateTenantResponseDto, status_code=status.HTTP_201_CREATED)
async def create_tenant(
    data: CreateTenantDto,
    current_user: CurrentUser,
    service: TenantService = Depends(get_tenant_service),
    _bool: bool = Depends(check_permissions_for_current_role(required_permissions=[Permission.HOST_MANAGE_TENANTS]))
):
    # Unlike the sibling single-record endpoints there is no tenant id
    # here to scope to, so a tenant caller cannot be narrowed to their
    # own tenant — creation itself is a host operation. The
    # HOST_MANAGE_TENANTS gate also admits FULL_ACCESS holders (see
    # UserAccessManagement), and every tenant's seeded ADMIN role holds
    # FULL_ACCESS, so without this a tenant admin could create arbitrary
    # new tenants with a caller-chosen admin account (email + password),
    # claiming subdomains and gaining admin of a fresh tenant. The
    # frontend tenants page and its create dialog are host-only (the
    # sidebar hides /tenants for tenant users), so rejecting tenant
    # callers loses no legitimate use; host callers (tenant_id None)
    # are unaffected. The check runs before any service call or worker
    # dispatch, so no tenant or admin account is created.
    if current_user.tenant_id is not None:
        raise ForbiddenException("Tenant creation is restricted to host administrators.")
    tenant_id = await service.create_tenant(data)
    
    response = CreateTenantResponseDto(id=str(tenant_id))
    
    admin_user = CreateUserDto(
        email=data.admin_email,
        password=data.admin_password,
        first_name=data.first_name,
        last_name=data.last_name,
        gender=data.gender,
        tenant_id=response.id,
        sub_domain=data.subdomain
    )
    payload=WorkerPayloadDto(
        label="post-tenant-creation",
        data=admin_user,
        tenant_id=response.id
    )
    handle_post_tenant_creation.delay(
        payload=payload.model_dump_json()
    )
    return response


@router.delete("/{id}", status_code=status.HTTP_202_ACCEPTED)
async def delete_tenant(
    id: str,
    current_user: CurrentUser,
    service: TenantService = Depends(get_tenant_service),
    _bool: bool = Depends(check_permissions_for_current_role(required_permissions=[Permission.HOST_MANAGE_TENANTS]))
):
    try:
        tenant: Tenant = await service.get_tenant_by_id(tenant_id=id)
        # The HOST_MANAGE_TENANTS gate also admits FULL_ACCESS holders (see
        # UserAccessManagement), and every tenant's seeded ADMIN role holds
        # FULL_ACCESS, so without this a tenant admin could pass any
        # tenant_id and delete another tenant outright — the most
        # destructive of the sibling host-gated endpoints. Host callers
        # (tenant_id None) keep the global view. Compared after fetch,
        # so id forms normalize, mirroring the PUT/check_dns/update_dns
        # scoping; the check runs before any deletion or worker dispatch.
        if current_user.tenant_id is not None and str(tenant.id) != current_user.tenant_id:
            raise TenantNotFoundException(id)
        tenant_doc = TenantDto(**tenant.model_dump())
        payload=WorkerPayloadDto(
            label="post-tenant-deletion",
            data=tenant_doc,
            tenant_id=id
        )
        await service.delete_tenant(tenant_id=id)
        handle_post_tenant_deletion.delay(payload=payload.model_dump_json())
        return status.HTTP_202_ACCEPTED
    except TenantNotFoundException as e:
        raise e
    except Exception as e:
        # Keep the internal detail server-side only: str(e) can carry
        # database/upstream internals, and the ApiBaseException handler
        # returns its message verbatim to the client (and logs it).
        # Every other controller that swallows an unexpected error
        # (storage configure, Stripe webhook) logs the detail and
        # returns a generic message instead; the frontend delete toast
        # is a fixed "Failed to delete tenant" string, so no client
        # copy depends on the detail.
        logger.error(f"Failed to delete tenant {id}: {e}")
        raise ApiBaseException("Failed to delete tenant.")


@router.get("/search_by_name/{name}", response_model=TenantDto, status_code=status.HTTP_200_OK)
async def search_by_name(
    name: str,
    response: Response,
    service: TenantService = Depends(get_tenant_service)
):
    # This GET returns a full tenant record, so it must never be served
    # from a browser or proxy cache: a cached 200 could serve one
    # tenant's record to another admin after an account switch on a
    # shared machine, or hide freshly updated tenant details — the
    # same no-store hardening as the tenant list GET above.
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    tenant = await service.find_by_name(name)
    return TenantDto(**tenant.model_dump())


@router.get("/search_by_subdomain/{subdomain}", response_model=TenantDto, status_code=status.HTTP_200_OK)
async def search_by_subdomain(
    subdomain: Subdomain,
    response: Response,
    service: TenantService = Depends(get_tenant_service)
):
    # This GET returns a full tenant record, so it must never be served
    # from a browser or proxy cache: a cached 200 could serve one
    # tenant's record to another admin after an account switch on a
    # shared machine, or hide freshly updated tenant details — the
    # same no-store hardening as the search_by_name GET above.
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    tenant = await service.find_by_subdomain(subdomain)
    return TenantDto(**tenant.model_dump())


@router.get("/check_subdomain/{subdomain}", response_model=SubdomainAvailabilityDto, status_code=status.HTTP_200_OK)
async def check_subdomain_availability(
    subdomain: Subdomain,
    response: Response,
    service: TenantService = Depends(get_tenant_service)
):
    # This GET reports whether a subdomain is taken, so it must never
    # be served from a browser or proxy cache: a cached 200 could
    # report a subdomain as available after it was just registered
    # (or as taken after it was freed) — the same no-store hardening
    # as the search_by_subdomain GET above.
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    try: 
        await service.find_by_subdomain(subdomain)
        is_available = False
    except TenantNotFoundException as e:
        is_available = True
    except InvalidSubdomainException as e:
        is_available = False

    return SubdomainAvailabilityDto(is_available=is_available)


@router.post("/{tenant_id}/update_dns", 
            response_model=UpdateTenantResponseDto,
            description=
            f"""
                When bringing your own domain you must map the DNS records for your custom domain to point to our main domain.
                You can do this by adding a CNAME record in your domain's DNS settings.
                Here is an example of how to set it up:
                Type: CNAME
                Name: app
                Value: {get_host_main_domain_name()}
            """,
            status_code=status.HTTP_202_ACCEPTED
        )
async def update_tenant_dns_record(
    tenant_id: str,
    data: UpdateTenantDto,
    current_user: CurrentUser,
    tenant_service: TenantService = Depends(get_tenant_service),
    _bool: bool = Depends(check_permissions_for_current_role(required_permissions=[Permission.HOST_MANAGE_TENANTS, Permission.MANAGE_TENANT_SETTINGS])),
    request_tenant_id = Depends(get_tenant_id)
):
    _assert_update_scope(current_user, request_tenant_id)
    tenant = await tenant_service.get_tenant_by_id(tenant_id)
    # Tenant callers may only update their own tenant's DNS: the
    # permission gate above also admits MANAGE_TENANT_SETTINGS, so without
    # this a tenant admin could pass any tenant_id and overwrite another
    # tenant's custom_domain / is_active and enqueue its DNS-update job.
    # Host callers (tenant_id None) keep the global view. A cross-tenant id
    # raises the same 404 as an unknown id, so a probe cannot distinguish
    # the two — mirroring the check_dns scoping from iteration 856, and
    # the check runs before any write or job enqueue.
    if current_user.tenant_id is not None and str(tenant.id) != current_user.tenant_id:
        raise TenantNotFoundException(tenant_id)
    if tenant.custom_domain_status == "activation-progress":
        return UpdateTenantResponseDto(
            message="Your previous custom domain update is still in progress. Please wait until it is processed."
        )
    
    if tenant.custom_domain_status == "active":
        return UpdateTenantResponseDto(
            message="Your custom domain is already active. If you want to change it, please contact support."
        )
    
    payload=WorkerPayloadDto[dict[str, str]](
        label="update-tenant-dns",
        data={
            "custom_domain": data.custom_domain,
            "user_id": str(current_user.id),
        },
        tenant_id=str(tenant.id)
    )
    tenant.custom_domain = data.custom_domain
    tenant.is_active = data.is_active if data.is_active is not None else tenant.is_active
    tenant.custom_domain_status = "activation-progress" if data.custom_domain else None
    # Direct .save() bypasses BaseRepository.update()'s central updated_at stamp (iteration 411).
    tenant.updated_at = get_utc_now()
    await tenant.save()
    handle_tenant_dns_update.delay(
        payload=payload.model_dump_json()
    )
    return UpdateTenantResponseDto(
        message="We have received your request. The changes will reflect in a few minutes. And email notification will be sent."
    )

@router.get("/{tenant_id}/check_dns", response_model=UpdateTenantResponseDto, status_code=status.HTTP_200_OK)
async def check_dns_status(
    tenant_id: str,
    response: Response,
    current_user: CurrentUser,
    tenant_service: TenantService = Depends(get_tenant_service),
    _bool: bool = Depends(check_permissions_for_current_role(required_permissions=[Permission.HOST_MANAGE_TENANTS, Permission.MANAGE_TENANT_SETTINGS])),
    request_tenant_id = Depends(get_tenant_id)
):
    # Same wrong-DB class as update_dns (iteration 921): the stamp
    # check below only compares against the record the request's
    # database returned, so a tenant caller on the host DB (no
    # X-Tenant-ID/subdomain, scope None) could read the DNS status
    # of, and enqueue DNS-update jobs for, a tenant-stamped record
    # sitting in the host DB (e.g. planted before the create guard).
    # This guard fails closed before any read or job enqueue; the
    # message's "updated" wording still fits because this endpoint
    # enqueues a DNS-update job. Legitimate tenant checks happen in
    # the caller's own tenant DB (the frontend ApiClient sends
    # X-Tenant-ID) and host callers (tenant_id None) are unaffected.
    _assert_update_scope(current_user, request_tenant_id)
    # This GET enqueues a Celery DNS-update job (for tenants in
    # activation-progress or failed status) and returns a status message
    # that changes as activation proceeds, so it must never be served
    # from a browser or proxy cache: a cached 200 would report a stale
    # status and skip the enqueue the admin just requested. Same
    # no-store hardening as the state-changing GETs in the account
    # controller (logout, magic-link validation, SSO callback).
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    tenant_doc = await tenant_service.get_tenant_by_id(tenant_id)
    # Tenant callers may only check their own tenant's DNS status: the
    # permission gate above also admits MANAGE_TENANT_SETTINGS, so without
    # this a tenant admin could pass any tenant_id, enqueue DNS-update jobs
    # for another tenant's custom domain and read its activation status.
    # Host callers (tenant_id None) keep the global view. A cross-tenant id
    # raises the same 404 as an unknown id, so a probe cannot distinguish
    # the two — mirroring the users/roles/SSO single-record scoping.
    if current_user.tenant_id is not None and str(tenant_doc.id) != current_user.tenant_id:
        raise TenantNotFoundException(tenant_id)
    payload=WorkerPayloadDto[dict[str, str]](
        label="update-tenant-dns",
            data={
                "custom_domain": tenant_doc.custom_domain,
                "user_id": str(current_user.id),
            },
            tenant_id=str(tenant_doc.id)
        )
    if not tenant_doc.custom_domain:
        raise InvalidOperationException("No custom domain is set for this tenant.")
    
    if tenant_doc.custom_domain_status == "activation-progress":
        handle_tenant_dns_update.delay(
            payload=payload.model_dump_json()
        )
        return UpdateTenantResponseDto(
            message="Your custom domain activation is still in progress. Please wait until it is processed."
        )
    
    if tenant_doc.custom_domain_status == "active":
        return UpdateTenantResponseDto(
            message="Your custom domain is already active. No further action is needed."
        )
    
    if tenant_doc.custom_domain_status == "failed":
        
        handle_tenant_dns_update.delay(
            payload=payload.model_dump_json()
        )
        return UpdateTenantResponseDto(
            message="Your custom domain activation previously failed. Please update your DNS settings and try again."
        )

    return UpdateTenantResponseDto(
        message="DNS status check completed successfully."
    )

@router.put("/{tenant_id}", response_model=None, status_code=status.HTTP_204_NO_CONTENT)
async def update_tenant(
    tenant_id: str,
    data: UpdateTenantDto,
    current_user: CurrentUser,
    tenant_service: TenantService = Depends(get_tenant_service),
    _bool: bool = Depends(check_permissions_for_current_role(required_permissions=[Permission.HOST_MANAGE_TENANTS]))
):
    # The HOST_MANAGE_TENANTS gate also admits FULL_ACCESS holders (see
    # UserAccessManagement), and every tenant's seeded ADMIN role holds
    # FULL_ACCESS, so without this a tenant admin could pass any
    # tenant_id and overwrite another tenant's is_active, custom_domain
    # or subscription_id. Host callers (tenant_id None) keep the global
    # view. Compared after fetch, so id forms normalize, mirroring the
    # check_dns/update_dns scoping; the check runs before any write.
    tenant = await tenant_service.get_tenant_by_id(tenant_id)
    if current_user.tenant_id is not None and str(tenant.id) != current_user.tenant_id:
        raise TenantNotFoundException(tenant_id)
    await tenant_service.update_tenant(tenant_id, data)
    return None

@router.get("/{tenant_id}/features", response_model=list[FeatureDto], status_code=status.HTTP_200_OK)
async def get_tenant_features(
    response: Response,
    tenant_id: str,
    current_user: CurrentUser,
    tenant_service: TenantService = Depends(get_tenant_service),
    _bool: bool = Depends(check_permissions_for_current_role(required_permissions=[Permission.HOST_MANAGE_TENANTS]))
):
    # The HOST_MANAGE_TENANTS gate also admits FULL_ACCESS holders (see
    # UserAccessManagement), and every tenant's seeded ADMIN role holds
    # FULL_ACCESS, so without this a tenant admin could pass any
    # tenant_id and read another tenant's feature enablement (e.g.
    # which paid features it has). Host callers (tenant_id None) keep
    # the global view. Compared after fetch, so id forms normalize,
    # mirroring the PUT/DELETE/update_feature scoping; the check runs
    # before any feature data is returned. Unknown ids behave as before
    # (get_tenant_by_id already raises TenantNotFoundException).
    tenant = await tenant_service.get_tenant_by_id(tenant_id)
    if current_user.tenant_id is not None and str(tenant.id) != current_user.tenant_id:
        raise TenantNotFoundException(tenant_id)
    # This GET returns one tenant's feature enablement, so it must never be
    # served from a browser or proxy cache: a cached 200 could hide a
    # freshly toggled feature, or serve one tenant's features to another
    # host admin after an account switch on a shared machine — the same
    # no-store hardening as the /tenants/ list GET above. Response is
    # already imported in this module.
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return await tenant_service.get_features_by_tenant_id(tenant_id)
    
@router.patch("/{tenant_id}/update_feature", response_model=UpdateTenantResponseDto, status_code=status.HTTP_200_OK)
async def update_tenant_feature(
    tenant_id: str,
    feature: FeatureDto,
    current_user: CurrentUser,
    tenant_service: TenantService = Depends(get_tenant_service),
    _bool: bool = Depends(check_permissions_for_current_role(required_permissions=[Permission.HOST_MANAGE_TENANTS]))
):
    # The HOST_MANAGE_TENANTS gate also admits FULL_ACCESS holders (see
    # UserAccessManagement), and every tenant's seeded ADMIN role holds
    # FULL_ACCESS, so without this a tenant admin could pass any
    # tenant_id and toggle another tenant's features (e.g. disable
    # STRIPE or enable a feature that tenant never bought). Host
    # callers (tenant_id None) keep the global view. Compared after
    # fetch, so id forms normalize, mirroring the PUT/DELETE scoping;
    # the check runs before any write.
    tenant = await tenant_service.get_tenant_by_id(tenant_id)
    if current_user.tenant_id is not None and str(tenant.id) != current_user.tenant_id:
        raise TenantNotFoundException(tenant_id)
    await tenant_service.update_feature(tenant_id, feature)
    return UpdateTenantResponseDto(
        message=f"Feature '{feature.name.value}' updated successfully for tenant."
    )


@router.patch("/{tenant_id}/activate_trial_plan", response_model=UpdateTenantResponseDto, status_code=status.HTTP_200_OK)
async def activate_trial_plan(
    tenant_id: str,
    current_user: CurrentUser,
    tenant_service: TenantService = Depends(get_tenant_service),
    subcription_plan_service: SubscriptionPlanService = Depends(get_subscription_plan_service),
    billing_record_service: BillingRecordService = Depends(get_billing_record_service),
    _feature_check: bool = Depends(check_feature_access(feature_name=Feature.STRIPE)),
    # Activating a trial creates a Stripe trial subscription and
    # overwrites the target tenant's subscription_id, so it is a
    # host-admin mutation like the sibling tenant endpoints above
    # (update, update_feature, delete) — not a tenant-user action.
    # The feature check alone only required the caller's own tenant
    # to have STRIPE enabled, so any authenticated tenant user could
    # activate a trial for any tenant_id in the path. The frontend
    # caller is the host-admin tenant-subscription dialog, so
    # legitimate callers already hold this permission.
    _bool: bool = Depends(check_permissions_for_current_role(required_permissions=[Permission.HOST_MANAGE_TENANTS])),
):
    # The HOST_MANAGE_TENANTS gate also admits FULL_ACCESS holders (see
    # UserAccessManagement), and every tenant's seeded ADMIN role holds
    # FULL_ACCESS, so without this a tenant admin could pass any
    # tenant_id and create a Stripe trial subscription for another
    # tenant, overwriting that tenant's subscription_id. Host callers
    # (tenant_id None) keep the global view. Compared after fetch, so
    # id forms normalize, mirroring the PUT/DELETE/update_feature/
    # features scoping; the check runs before any Stripe or billing
    # work. Unknown ids behave as before (get_tenant_by_id already
    # raises TenantNotFoundException).
    tenant = await tenant_service.get_tenant_by_id(tenant_id)
    if current_user.tenant_id is not None and str(tenant.id) != current_user.tenant_id:
        raise TenantNotFoundException(tenant_id)
    logger.debug(f"Activating trial plan for tenant ID: {tenant_id}")
    all_plans = await billing_record_service.list_plans('host')
    if len(all_plans.plans) == 0:
        logger.error("No plans are configured in Stripe. Please create a plan before activating a trial.")
        raise InvalidOperationException("No plans are configured. Please create a plan before activating a trial.")

    trial = list(filter(lambda p: p.trial_period_days is not None and p.trial_period_days > 0, all_plans.plans))
    
    if not trial:
        logger.error("No trial plan is configured. Please create a plan with a trial period before activating a trial or update an existing plan.")
        raise InvalidOperationException("No trial plan is configured. Please create a plan with a trial period before activating a trial or update an existing plan.")
    
    id = trial[0].id
    logger.debug(f"Trial plan found: {id}, activating for tenant ID: {tenant_id}")
    subscription_id = await subcription_plan_service.create_trial_plan_for_tenant(tenant_id, id)
    await tenant_service.update_tenant(tenant_id=tenant_id, data=UpdateTenantDto(subscription_id=subscription_id))
    logger.debug(f"Trial plan activated successfully for tenant ID: {tenant_id}")
    return UpdateTenantResponseDto(
        message="Trial plan activated successfully for tenant."
    )

