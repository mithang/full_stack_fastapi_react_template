from typing import Any

import stripe
from beanie import PydanticObjectId
from api.common.exceptions import InvalidOperationException
from api.common.utils import get_logger
from api.core.container import get_billing_record_service, get_stripe_setting_service
from api.domain.dtos.stripe_setting_dto import CreateStripeSettingDto, StripeSettingDto
from api.domain.enum.feature import Feature as FeatureEnum
from api.domain.enum.permission import Permission
from api.domain.security.feature_access_management import check_feature_access
from api.infrastructure.security.current_user import CurrentUser
from api.interfaces.security.role_checker import check_permissions_for_current_role
from api.usecases.billing_record_service import BillingRecordService
from api.usecases.stripe_setting_service import StripeSettingService
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse
from api.core.config import settings
from api.core.exceptions import StripeSettingsNotFoundException


logger = get_logger(__name__)


router = APIRouter(
    prefix="/configurations",
    dependencies=[
        Depends(
            check_permissions_for_current_role(
                required_permissions=[Permission.MANAGE_PAYMENTS_SETTINGS]
            )
        ),
        Depends(check_feature_access(FeatureEnum.STRIPE)),
    ],
)
router.tags = ["Stripe"]


# The Stripe webhook cannot live on the router above: its dependencies
# require a logged-in user with MANAGE_PAYMENTS_SETTINGS (CurrentUser
# needs a Bearer access token), which Stripe's server-to-server POSTs
# never carry — so every webhook was rejected before signature
# verification ran and invoice.paid events were never processed. This
# router carries no auth dependencies; Stripe signature verification
# inside the handler is the webhook's authentication, as is standard.
webhook_router = APIRouter(prefix="/configurations", tags=["Stripe"])


@router.post("/stripe", status_code=status.HTTP_201_CREATED)
async def configure_stripe_setting(
    configuration: CreateStripeSettingDto,
    current_user: CurrentUser,
    stripe_setting_service: StripeSettingService = Depends(get_stripe_setting_service),
):
    if not current_user.tenant_id:
        raise InvalidOperationException(
            "Tenant context is required to configure Stripe settings."
        )

    await stripe_setting_service.configure_stripe_settings(
        settings=configuration, tenant_id=str(current_user.tenant_id)
    )
    return status.HTTP_201_CREATED


@router.get("/stripe", response_model=StripeSettingDto, status_code=status.HTTP_200_OK)
async def get_stripe_settings(
    current_user: CurrentUser,
    stripe_setting_service: StripeSettingService = Depends(get_stripe_setting_service),
):
    if not current_user.tenant_id:
        raise InvalidOperationException(
            "Tenant context is required to get Stripe settings."
        )
    return await stripe_setting_service.get_stripe_settings()


SUPPORTED_EVENTS = {
    "invoice.paid": lambda obj, svc, tenant_id=None: handle_invoice_paid(
        obj, svc, tenant_id
    ),
}


@webhook_router.post("/stripe/webhooks", status_code=status.HTTP_200_OK)
async def stripe_webhook(
    request: Request,
    stripe_setting_service: StripeSettingService = Depends(get_stripe_setting_service),
    billing_record_service: BillingRecordService = Depends(get_billing_record_service),
):
    event = None
    stripe_webhook_secret = None
    payload = await request.body()

    # Check the request context for tenant or host. If tenant then get tenant webhook secret otherwise use host from env.
    # The stored secret must only be fetched in the tenant branch: host
    # Stripe settings live in env, not the database, so fetching here for
    # a host webhook raised StripeSettingsNotFoundException (mapped to
    # 404 by the API exception handler) before signature verification
    # ever ran — and Stripe retries every non-2xx delivery, so host
    # invoice.paid events were never processed.
    if request.state.tenant_id:
        # Tenant-scoped webhook
        try:
            stripe_settings = await stripe_setting_service.get_stripe_secret()
        except StripeSettingsNotFoundException:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Tenant webhook secret not configured",
            )
        if not stripe_settings or not stripe_settings.stripe_webhook_secret:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Tenant webhook secret not configured",
            )
        stripe_webhook_secret = stripe_settings.stripe_webhook_secret
    else:
        # Host-scoped webhook
        stripe_webhook_secret = settings.stripe_webhook_secret
        if not stripe_webhook_secret:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Host webhook secret not configured",
            )

    try:
        sig_header = request.headers.get("stripe-signature")

        event = stripe.Webhook.construct_event(
            payload=payload,
            sig_header=sig_header,
            secret=stripe_webhook_secret,
        )
    except ValueError:
        # Invalid payload
        logger.error("Invalid payload")
        raise HTTPException(status_code=400, detail="Invalid payload")
    except stripe.error.SignatureVerificationError as e:
        logger.error(f"Webhook signature verification failed: {e}")
        raise HTTPException(status_code=400, detail="Invalid signature")
    except Exception as e:
        logger.error(f"Unexpected error constructing event: {e}")
        raise HTTPException(status_code=400, detail="Webhook error")

    # Extract the event type and object. Guard the envelope the same
    # way the invoice conversion guards malformed invoice fields: a
    # signature-verified event with a missing type/data/object would
    # otherwise raise KeyError/TypeError here, outside any try/catch,
    # surfacing as a 500 that Stripe retries forever — and a retry
    # redelivers the identical payload, so it can never succeed. Such
    # an event is acknowledged with 200 (as unhandled types are below)
    # and logged, instead of looping forever.
    try:
        event_type = event["type"]
        data_object = event["data"]["object"]
        if data_object is None:
            # A null object is malformed the same way a missing one
            # is: dispatching it would crash handle_invoice_paid on
            # .get, again as a retried 500. (No isinstance check here:
            # a Stripe event object need not be a plain dict.)
            raise TypeError("event data object is None")
    except (KeyError, TypeError, AttributeError):
        logger.warning("Ignoring malformed webhook event envelope")
        return JSONResponse(
            status_code=200, content={"message": "Malformed event envelope"}
        )

    # ------------------------------------------------------------------
    # Handle relevant Stripe events
    # ------------------------------------------------------------------

    if event_type not in SUPPORTED_EVENTS:
        # Acknowledge with 2xx, not 404: Stripe treats any non-2xx as a
        # failed delivery and retries it, so an event type this app
        # deliberately ignores would be redelivered repeatedly. The
        # signature has already been verified above, so ignoring it
        # here is safe.
        logger.info(f"Ignoring unhandled event type: {event_type}")
        return JSONResponse(
            status_code=200, content={"message": "Unhandled event type"}
        )

    # Thread the webhook's own tenant context through: the secret above
    # was already selected from this tenant's stored settings, so a
    # tenant-scoped delivery belongs to that tenant even when the invoice
    # carries no tenant_id in its metadata.
    request_tenant_id = getattr(request.state, "tenant_id", None)
    await SUPPORTED_EVENTS.get(event_type, None)(
        data_object,
        billing_record_service,
        str(request_tenant_id) if request_tenant_id else None,
    )

    return JSONResponse(status_code=200, content={"status": "success"})


async def handle_invoice_paid(
    invoice: dict[str, Any],
    billing_record_service: BillingRecordService,
    tenant_id: str | None = None,
) -> None:
    # Invoice metadata wins when present; otherwise fall back to the
    # tenant context the webhook itself arrived under (a tenant delivery
    # was verified against that tenant's stored secret, so attributing
    # it to the host scope merely because the invoice metadata lacks
    # tenant_id would misattribute the record). A null metadata value
    # falls back the same way instead of raising AttributeError, as
    # does a truthy non-dict value (e.g. a string), which the old
    # `or {}` guard did not cover: `.get` on it raised AttributeError
    # outside the save try/catch below, turning a valid delivery into
    # a 500 that Stripe retries forever — the same class fixed for line
    # metadata in the billing service.
    invoice_metadata = invoice.get("metadata")
    # Guard the scalar tenant_id the same way _extract_tenant_id guards
    # its line-metadata values: the dict check above only guards the
    # container, so a truthy non-string tenant_id (e.g. an int) would
    # otherwise pass through here and bypass the service guard entirely
    # — from_stripe_invoice_paid short-circuits on a truthy tenant_id
    # and never calls _extract_tenant_id — then raise inside
    # PydanticObjectId() in the record build, outside the save
    # try/catch, turning a valid delivery into a 500 that Stripe
    # retries forever. A malformed value falls back to the webhook
    # tenant context, as an empty value already did.
    metadata_tenant_id = (
        invoice_metadata.get("tenant_id")
        if isinstance(invoice_metadata, dict)
        else None
    )
    if not isinstance(metadata_tenant_id, str) or not metadata_tenant_id:
        metadata_tenant_id = None
    # Guard ObjectId validity the same way the service guards its
    # resolved tenant_id (iteration 280): a non-empty string that is
    # not a valid ObjectId (e.g. a slug from another system in invoice
    # metadata) would otherwise win over the webhook tenant context
    # above, then be dropped to None by the service guard — losing a
    # valid webhook attribution and leaving a tenant-scope record with
    # no tenant. Validated here, it falls back to the webhook tenant
    # context instead, as an empty value already did; valid ObjectId
    # strings behave as before. The service guard stays as the
    # backstop for other callers.
    if metadata_tenant_id is not None:
        try:
            PydanticObjectId(metadata_tenant_id)
        except Exception:
            metadata_tenant_id = None
    tenant_id = metadata_tenant_id or tenant_id

    billing_record = await billing_record_service.from_stripe_invoice_paid(
        invoice=invoice, scope="tenant" if tenant_id else "host", tenant_id=tenant_id
    )

    if not billing_record:
        # .get, not ["id"]: the conversion above now tolerates a
        # missing/malformed invoice id, so logging it directly would
        # reintroduce the KeyError here — after a successful save in
        # the success branch, that 500 would make Stripe retry the
        # delivery and create a duplicate record.
        logger.warning(
            f"Could not convert invoice to BillingRecordDto: {invoice.get('id')}"
        )
        return

    # Deduplicate retried deliveries before the insert: Stripe
    # redelivers an invoice.paid event when its first delivery did not
    # return 2xx — including when the save itself succeeded but the
    # response was lost — and without this check the retry inserts a
    # second record for the same invoice. The check runs before the
    # save try/catch so a lookup failure still surfaces as a non-2xx
    # (and a safe retry) instead of a blind insert; a duplicate is
    # acknowledged with the normal 200 below, so Stripe stops retrying
    # it. An empty invoice id (the malformed-invoice fallback) skips
    # the check via billing_record_exists_for_invoice itself.
    if await billing_record_service.billing_record_exists_for_invoice(
        billing_record.metadata.get("invoice_id", "")
    ):
        logger.info(
            f"BillingRecord already exists for invoice {invoice.get('id')} – skipping duplicate"
        )
        return

    try:
        await billing_record_service.create_billing_record(billing_record)
        logger.info(
            f"BillingRecord created for tenant {tenant_id} – invoice {invoice.get('id')}"
        )
    except Exception as e:
        # Re-raise after logging: unlike an unhandled event type (which
        # is deliberately acknowledged with 200), a failed save of a
        # handled invoice.paid event must surface as a non-2xx response
        # so Stripe retries the delivery; swallowing it here returned
        # 200 "success" while the billing record was never persisted.
        logger.exception(
            f"Failed to save BillingRecord for invoice {invoice.get('id')}: {e}"
        )
        raise
